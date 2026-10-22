import UIKit
import WebKit
import UserNotifications
import LinkPresentation
import SafariServices

let LIVE_URL = URL(string: "https://web.lockin-app.online")!

// MARK: - Share sheet item (AirDrop gets the bare link; chat apps get the message + link)
final class ShareItem: NSObject, UIActivityItemSource {
    let url: URL
    let text: String?
    init(url: URL, text: String?) { self.url = url; self.text = text }
    func activityViewControllerPlaceholderItem(_ activityViewController: UIActivityViewController) -> Any { url }
    func activityViewController(_ activityViewController: UIActivityViewController, itemForActivityType activityType: UIActivity.ActivityType?) -> Any? {
        guard let type = activityType, let text = text, type != .airDrop, type != .copyToPasteboard else { return url }
        return text + "\n" + url.absoluteString
    }
    func activityViewController(_ activityViewController: UIActivityViewController, subjectForActivityType activityType: UIActivity.ActivityType?) -> String { "Lock In" }
    func activityViewControllerLinkMetadata(_ activityViewController: UIActivityViewController) -> LPLinkMetadata? {
        let md = LPLinkMetadata()
        md.originalURL = url
        md.url = url
        md.title = text ?? "Lock In"
        return md
    }
}

// MARK: - Main view controller (thin shell around the live site)
/// Bridge for the page: window.webkit.messageHandlers.lockin.postMessage({action:'notify'|'cancel'|'auth'|'haptic'|'share'|'browser'|'icon'|'pro', ...})
final class NotifyBridge: NSObject, WKScriptMessageHandler {
    weak var presenter: UIViewController?
    func userContentController(_ ucc: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any], let action = body["action"] as? String else { return }
        let center = UNUserNotificationCenter.current()
        switch action {
        case "auth":
            center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
        case "haptic":
            let style = (body["style"] as? String) ?? "light"
            DispatchQueue.main.async {
                switch style {
                case "success": UINotificationFeedbackGenerator().notificationOccurred(.success)
                case "selection": UISelectionFeedbackGenerator().selectionChanged()
                case "medium": UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                case "heavy": UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
                default: UIImpactFeedbackGenerator(style: .light).impactOccurred()
                }
            }
        case "share":
            guard let s = body["url"] as? String, let url = URL(string: s) else { return }
            let text = body["text"] as? String
            DispatchQueue.main.async { [weak self] in
                guard let base = self?.presenter else { return }
                var top: UIViewController = base
                while let p = top.presentedViewController { top = p }
                let ac = UIActivityViewController(activityItems: [ShareItem(url: url, text: text)], applicationActivities: nil)
                if let pop = ac.popoverPresentationController {
                    pop.sourceView = top.view
                    pop.sourceRect = CGRect(x: top.view.bounds.midX, y: top.view.bounds.maxY - 90, width: 1, height: 1)
                }
                top.present(ac, animated: true)
            }
        case "browser":
            // a Stripe page (checkout link, manage subscription): in an in-app browser sheet, not Safari
            guard let s = body["url"] as? String, let url = URL(string: s), let sc = url.scheme?.lowercased(), sc == "https" || sc == "http" else { return }
            DispatchQueue.main.async { [weak self] in (self?.presenter as? ViewController)?.openInApp(url) }
        case "icon":
            // Lock In Pro: the gold app icon (iOS shows a short notice when it changes)
            let name: String? = (body["name"] as? String) == "pro" ? "ProIcon" : nil
            DispatchQueue.main.async {
                let app = UIApplication.shared
                guard app.supportsAlternateIcons, app.alternateIconName != name else { return }
                app.setAlternateIconName(name) { _ in }
            }
        case "pro":
            // remembered for the launch screen: gold for Pro
            UserDefaults.standard.set((body["on"] as? Bool) ?? false, forKey: "lockinPro")
        case "cancel":
            center.removePendingNotificationRequests(withIdentifiers: ["rest"])
        case "notify":
            let secs = max(1.0, (body["secs"] as? Double) ?? Double((body["secs"] as? Int) ?? 0))
            let content = UNMutableNotificationContent()
            content.title = (body["title"] as? String) ?? "Rest is over"
            content.body = (body["body"] as? String) ?? "Time for your next set"
            content.sound = .default
            if #available(iOS 15.0, *) { content.interruptionLevel = .timeSensitive }
            let req = UNNotificationRequest(identifier: "rest", content: content,
                                            trigger: UNTimeIntervalNotificationTrigger(timeInterval: secs, repeats: false))
            center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                guard granted else { return }
                center.removePendingNotificationRequests(withIdentifiers: ["rest"])
                center.add(req)
            }
        default: break
        }
    }
}

final class ViewController: UIViewController, WKNavigationDelegate, WKUIDelegate, UNUserNotificationCenterDelegate, SFSafariViewControllerDelegate {
    private let bridge = NotifyBridge()
    private var webView: WKWebView!
    private var retryView: UIView?
    private var popupNav: UINavigationController?
    private let bg = UIColor(red: 0x0e/255.0, green: 0x10/255.0, blue: 0x13/255.0, alpha: 1)

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = bg

        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.websiteDataStore = .default()
        // No app-bound domains: they blocked the offline copy (and service workers never ran in sideloaded builds).

        config.userContentController.add(bridge, name: "lockin")
        bridge.presenter = self
        let app = UIApplication.shared
        let icons = app.supportsAlternateIcons ? "true" : "false"
        let icon = app.alternateIconName == "ProIcon" ? "pro" : "default"
        let native = "window.__lockinNative={share:true,links:true,browser:true,pro:true,icons:" + icons + ",icon:'" + icon + "',version:'" + (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") + "'};"
        config.userContentController.addUserScript(WKUserScript(source: native, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        // Sign-in popups on puter.com get a dark theme so they match the app (Google/Apple pages follow dark mode themselves).
        let darkAuth = """
        (function(){ if (location.hostname !== 'puter.com') return;
          if (!window.opener && !/sign-in|auth|login|signup/.test(location.pathname + location.search)) return;
          var s = document.createElement('style');
          s.textContent = 'html{background:#0e1013!important}body{filter:invert(.92) hue-rotate(180deg)!important;background:#fff!important;min-height:100vh}img,svg,video,canvas,picture,iframe{filter:invert(1) hue-rotate(180deg)!important}';
          document.documentElement.appendChild(s); })();
        """
        config.userContentController.addUserScript(WKUserScript(source: darkAuth, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        UNUserNotificationCenter.current().delegate = self
        webView = makeWebView(config)
        webView.scrollView.bounces = false
        view.addSubview(webView)
        showSplash()
        load()
    }

    // MARK: Launch splash — same mark as the web splash, so the hand-off is seamless
    private var splash: UIView?
    private func showSplash() {
        let v = UIView(frame: view.bounds); v.backgroundColor = bg; v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        let tile = UIView(frame: CGRect(x: 0, y: 0, width: 84, height: 84))
        let g = CAGradientLayer(); g.frame = tile.bounds; g.cornerRadius = 26
        let pro = UserDefaults.standard.bool(forKey: "lockinPro"), gold = UIColor(red: 0.94, green: 0.75, blue: 0.30, alpha: 1)
        if pro {
            // Lock In Pro: black tile, gold barbell
            g.colors = [UIColor(red: 0.125, green: 0.125, blue: 0.14, alpha: 1).cgColor, UIColor(red: 0.047, green: 0.047, blue: 0.055, alpha: 1).cgColor]
            g.startPoint = CGPoint(x: 0.5, y: 0); g.endPoint = CGPoint(x: 0.5, y: 1)
            g.borderColor = gold.withAlphaComponent(0.5).cgColor; g.borderWidth = 1
        } else {
            g.colors = [UIColor(red: 0.43, green: 0.65, blue: 1, alpha: 1).cgColor, UIColor(red: 0.31, green: 0.49, blue: 0.97, alpha: 1).cgColor, UIColor(red: 0.48, green: 0.42, blue: 1, alpha: 1).cgColor]
            g.startPoint = CGPoint(x: 0, y: 0); g.endPoint = CGPoint(x: 1, y: 1)
        }
        tile.layer.addSublayer(g)
        tile.layer.shadowColor = (pro ? gold : UIColor(red: 0.31, green: 0.49, blue: 0.97, alpha: 1)).cgColor
        tile.layer.shadowOpacity = pro ? 0.32 : 0.45; tile.layer.shadowRadius = 25; tile.layer.shadowOffset = CGSize(width: 0, height: 18)
        let icon = UIImageView(image: UIImage(systemName: "dumbbell.fill", withConfiguration: UIImage.SymbolConfiguration(pointSize: 34, weight: .semibold)))
        icon.tintColor = pro ? gold : .white; icon.contentMode = .center; icon.frame = tile.bounds
        tile.addSubview(icon)
        tile.center = CGPoint(x: v.bounds.midX, y: v.bounds.midY)
        tile.autoresizingMask = [.flexibleLeftMargin, .flexibleRightMargin, .flexibleTopMargin, .flexibleBottomMargin]
        v.addSubview(tile)
        UIView.animate(withDuration: 1.2, delay: 0, options: [.autoreverse, .repeat, .allowUserInteraction, .curveEaseInOut]) { tile.transform = CGAffineTransform(translationX: 0, y: -6) }
        view.addSubview(v); splash = v
    }
    private func hideSplash() {
        guard let v = splash else { return }; splash = nil
        UIView.animate(withDuration: 0.35, delay: 0.15, options: [.curveEaseOut]) { v.alpha = 0 } completion: { _ in v.removeFromSuperview() }
    }

    // MARK: Deep links — lockin://add/<code> (friend invite) and lockin://split/<code> (shared split)
    var pendingLink: URL?
    private static func fragment(for url: URL) -> String? {
        guard url.scheme?.lowercased() == "lockin", let kind = url.host?.lowercased(), kind == "add" || kind == "split" else { return nil }
        let code = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard (4...20).contains(code.count), code.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }), code.allSatisfy({ $0.isASCII }) else { return nil }
        return "#" + kind + "=" + code
    }
    func openDeepLink(_ url: URL) {
        guard let frag = Self.fragment(for: url) else { return }
        if loaded { webView.evaluateJavaScript("location.hash='" + frag + "'", completionHandler: nil) }
        else { pendingLink = url }
    }
    private func applyPendingLink() {
        guard let u = pendingLink, let frag = Self.fragment(for: u) else { return }
        pendingLink = nil
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            self?.webView.evaluateJavaScript("location.hash='" + frag + "'", completionHandler: nil)
        }
    }

    private var watchdog: Timer?
    private var loaded = false
    private var offlineCopyShown = false

    // MARK: Offline copy — saved after every successful online load, opened when there is no connection.
    private var cacheFile: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("lockin-offline.html")
    }
    private func saveOfflineCopy() {
        var req = URLRequest(url: LIVE_URL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        req.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, _ in
            guard let self = self, let data = data, (resp as? HTTPURLResponse)?.statusCode == 200,
                  let html = String(data: data, encoding: .utf8), html.contains("<html") else { return }
            try? html.write(to: self.cacheFile, atomically: true, encoding: .utf8)
        }.resume()
    }
    /// Returns true when an offline copy was available and is now showing.
    @discardableResult private func showOfflineCopy() -> Bool {
        guard var html = try? String(contentsOf: cacheFile, encoding: .utf8), html.count > 1000 else { return false }
        watchdog?.invalidate()
        offlineCopyShown = true
        loaded = true
        retryView?.removeFromSuperview(); retryView = nil
        // Offline: drop the network-only script (it would block rendering while it times out);
        // the page already runs from on-device data when the Puter SDK is missing.
        html = html.replacingOccurrences(of: "<script src=\"https://js.puter.com/v2/\"></script>", with: "<script>window.__offlineCopy=1</script>")
        let bytes = html.utf8.count
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.webView.stopLoading()
            self.webView.loadHTMLString(html, baseURL: LIVE_URL)
            // Diagnostics: if the page didn't render, say exactly what happened instead of a blank screen.
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
                self?.webView.evaluateJavaScript("[document.readyState, !!document.querySelector('.hero'), (document.querySelector('.view.active')||{}).id||'none', location.href, window.__lastErr||''].join(' | ')") { res, err in
                    let info = (res as? String) ?? ("eval error: " + (err?.localizedDescription ?? "?"))
                    if !info.contains("| true |") || info.contains("| none |") {
                        self?.showRetry("Offline copy (\(bytes) bytes) didn’t start: " + info)
                    }
                }
            }
        }
        return true
    }
    private func load() {
        loaded = false
        offlineCopyShown = false
        webView.load(URLRequest(url: LIVE_URL, cachePolicy: .reloadRevalidatingCacheData, timeoutInterval: 20))
        watchdog?.invalidate()
        watchdog = Timer.scheduledTimer(withTimeInterval: 25, repeats: false) { [weak self] _ in
            guard let self = self, !self.loaded else { return }
            if !self.showOfflineCopy() { self.showRetry("The page took too long to load.") }
        }
    }

    private func makeWebView(_ config: WKWebViewConfiguration) -> WKWebView {
        let wv = WKWebView(frame: view.bounds, configuration: config)
        wv.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        wv.navigationDelegate = self
        wv.uiDelegate = self
        wv.isOpaque = false
        wv.backgroundColor = bg
        wv.scrollView.backgroundColor = bg
        return wv
    }

    // App open: the page already beeps and shows the timer, so don't double up with a banner.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([])
    }

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }

    private var topVC: UIViewController { presentedViewController ?? self }

    // MARK: Navigation — keep app domains inside, open the rest in an in-app browser sheet
    private func isAllowed(_ host: String) -> Bool {
        let allowed = ["lockin-app.online", "puter.com", "cloudflare.com"]
        return allowed.contains { host == $0 || host.hasSuffix("." + $0) }
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // Sign-in popups (Google / Apple / Microsoft via Puter) must finish inside the popup, so never bounce them to Safari.
        if webView != self.webView { decisionHandler(.allow); return }
        // Other apps' links (sidestore://, mailto:, tel: …) open in that app instead of failing inside the web view.
        if let url = navigationAction.request.url, let scheme = url.scheme?.lowercased(),
           !["http", "https", "about", "blob", "data", "file", "lockin"].contains(scheme) {
            UIApplication.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        if navigationAction.targetFrame?.isMainFrame ?? true,
           let url = navigationAction.request.url,
           let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
           let host = url.host, !isAllowed(host) {
            openInApp(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    // MARK: In-app browser (Stripe pages, other websites) — the page hears when it closes
    func openInApp(_ url: URL) {
        let sf = SFSafariViewController(url: url)
        sf.delegate = self
        sf.dismissButtonStyle = .close
        sf.preferredControlTintColor = UIColor(red: 0.94, green: 0.75, blue: 0.30, alpha: 1)
        sf.preferredBarTintColor = UIColor(red: 0x17/255.0, green: 0x1a/255.0, blue: 0x20/255.0, alpha: 1)
        var top: UIViewController = self
        while let p = top.presentedViewController { top = p }
        top.present(sf, animated: true)
    }
    func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        webView.evaluateJavaScript("window.dispatchEvent(new Event('lockin:browserclosed'))", completionHandler: nil)
    }

    // MARK: Popups (sign-in) presented inside the app
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        let popup = WKWebView(frame: .zero, configuration: configuration)
        popup.navigationDelegate = self
        popup.uiDelegate = self
        // Google refuses OAuth in embedded web views by user agent; present as mobile Safari.
        let osv = UIDevice.current.systemVersion.replacingOccurrences(of: ".", with: "_")
        let major = UIDevice.current.systemVersion.split(separator: ".").first.map(String.init) ?? "18"
        popup.customUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS \(osv) like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(major).0 Mobile/15E148 Safari/604.1"
        popup.isOpaque = false
        popup.backgroundColor = bg
        popup.scrollView.backgroundColor = bg
        let vc = UIViewController()
        vc.view.backgroundColor = bg
        vc.title = "Sign in to Lock In"
        popup.frame = vc.view.bounds
        popup.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        vc.view.addSubview(popup)
        // loading state while Puter's secure sign-in page opens
        let spin = UIView(frame: vc.view.bounds); spin.backgroundColor = bg; spin.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        let ai = UIActivityIndicatorView(style: .large); ai.color = UIColor(red: 0.56, green: 0.72, blue: 1, alpha: 1); ai.startAnimating()
        let lbl = UILabel(); lbl.text = "Opening secure sign-in…"; lbl.textColor = UIColor(white: 0.65, alpha: 1); lbl.font = .systemFont(ofSize: 14, weight: .medium)
        let st = UIStackView(arrangedSubviews: [ai, lbl]); st.axis = .vertical; st.spacing = 14; st.alignment = .center
        st.translatesAutoresizingMaskIntoConstraints = false; spin.addSubview(st)
        NSLayoutConstraint.activate([st.centerXAnchor.constraint(equalTo: spin.centerXAnchor), st.centerYAnchor.constraint(equalTo: spin.centerYAnchor, constant: -40)])
        vc.view.addSubview(spin); popupSpinners.append(spin)
        vc.navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .close, target: self, action: #selector(closePopup))
        let nav = UINavigationController(rootViewController: vc)
        nav.modalPresentationStyle = .pageSheet
        nav.overrideUserInterfaceStyle = .dark
        let ap = UINavigationBarAppearance(); ap.configureWithOpaqueBackground(); ap.backgroundColor = UIColor(red: 0x17/255.0, green: 0x1a/255.0, blue: 0x20/255.0, alpha: 1)
        ap.titleTextAttributes = [.foregroundColor: UIColor.white, .font: UIFont.systemFont(ofSize: 16, weight: .bold)]
        nav.navigationBar.standardAppearance = ap; nav.navigationBar.scrollEdgeAppearance = ap; nav.navigationBar.tintColor = UIColor(red: 0.56, green: 0.72, blue: 1, alpha: 1)
        var top: UIViewController = self
        while let p = top.presentedViewController { top = p }
        top.present(nav, animated: true)
        if popupNav == nil { popupNav = nav }
        return popup
    }

    private var popupSpinners: [UIView] = []
    private func hidePopupSpinner() {
        let list = popupSpinners; popupSpinners = []
        for v in list { UIView.animate(withDuration: 0.25) { v.alpha = 0 } completion: { _ in v.removeFromSuperview() } }
    }

    @objc private func closePopup() { popupNav?.dismiss(animated: true); popupNav = nil }
    func webViewDidClose(_ webView: WKWebView) { if webView != self.webView { closePopup() } }

    // MARK: Offline retry screen
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if webView == self.webView && !loaded && !showOfflineCopy() { showRetry(error.localizedDescription) }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        if webView == self.webView && !loaded && !showOfflineCopy() { showRetry(error.localizedDescription) }
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        if webView == self.webView { load() }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if webView != self.webView { hidePopupSpinner() }
        if webView == self.webView {
            hideSplash()
            loaded = true
            watchdog?.invalidate()
            if !offlineCopyShown { saveOfflineCopy() }
            retryView?.removeFromSuperview(); retryView = nil
            applyPendingLink()
        }
    }

    private func showRetry(_ detail: String = "") {
        hideSplash()
        guard retryView == nil else { return }
        let v = UIView(frame: view.bounds)
        v.backgroundColor = bg
        v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        let label = UILabel()
        label.text = "Couldn’t load Lock In"
        label.textColor = .white
        label.font = .systemFont(ofSize: 20, weight: .bold)
        let sub = UILabel()
        sub.text = "Check your connection and try again." + (detail.isEmpty ? "" : "\n\n" + detail)
        sub.textColor = UIColor(white: 0.7, alpha: 1)
        sub.font = .systemFont(ofSize: 14)
        sub.numberOfLines = 0
        sub.textAlignment = .center
        let btn = UIButton(type: .system)
        btn.setTitle("Retry", for: .normal)
        btn.titleLabel?.font = .systemFont(ofSize: 17, weight: .semibold)
        btn.addTarget(self, action: #selector(retryLoad), for: .touchUpInside)
        let stack = UIStackView(arrangedSubviews: [label, sub, btn])
        stack.axis = .vertical
        stack.spacing = 12
        stack.alignment = .center
        stack.translatesAutoresizingMaskIntoConstraints = false
        v.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: v.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: v.centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: v.leadingAnchor, constant: 32),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: v.trailingAnchor, constant: -32)
        ])
        view.addSubview(v)
        retryView = v
    }

    @objc private func retryLoad() {
        retryView?.removeFromSuperview(); retryView = nil
        load()
    }

    // MARK: Camera (scan a friend's QR code) — granted for Lock In's own pages; iOS still asks once for the app
    @available(iOS 15.0, *)
    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo,
                 type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        let h = origin.host.lowercased()
        decisionHandler(h == "lockin-app.online" || h.hasSuffix(".lockin-app.online") ? .grant : .prompt)
    }

    // MARK: alert / confirm / prompt
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let ac = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        ac.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler() })
        topVC.present(ac, animated: true)
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let ac = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        ac.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(false) })
        ac.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler(true) })
        topVC.present(ac, animated: true)
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?, initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (String?) -> Void) {
        let ac = UIAlertController(title: nil, message: prompt, preferredStyle: .alert)
        ac.addTextField { $0.text = defaultText }
        ac.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(nil) })
        ac.addAction(UIAlertAction(title: "OK", style: .default) { [weak ac] _ in
            completionHandler(ac?.textFields?.first?.text ?? "")
        })
        topVC.present(ac, animated: true)
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        let vc = ViewController()
        vc.pendingLink = connectionOptions.urlContexts.first?.url
        window.rootViewController = vc
        window.makeKeyAndVisible()
        self.window = window
    }
    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        guard let url = URLContexts.first?.url, let vc = window?.rootViewController as? ViewController else { return }
        vc.openDeepLink(url)
    }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        true
    }
    func application(_ application: UIApplication,
                     configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        UISceneConfiguration(name: "Default", sessionRole: connectingSceneSession.role)
    }
}
