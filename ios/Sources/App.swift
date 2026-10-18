import UIKit
import WebKit
import UserNotifications

let LIVE_URL = URL(string: "https://summer-lock-in.puter.site")!

// MARK: - Main view controller (thin shell around the live site)
/// Bridge for the page: window.webkit.messageHandlers.lockin.postMessage({action:'notify'|'cancel'|'auth', ...})
final class NotifyBridge: NSObject, WKScriptMessageHandler {
    func userContentController(_ ucc: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any], let action = body["action"] as? String else { return }
        let center = UNUserNotificationCenter.current()
        switch action {
        case "auth":
            center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
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

final class ViewController: UIViewController, WKNavigationDelegate, WKUIDelegate, UNUserNotificationCenterDelegate {
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
        UNUserNotificationCenter.current().delegate = self
        webView = makeWebView(config)
        view.addSubview(webView)
        load()
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

    // MARK: Navigation — keep app domains inside, open the rest in Safari
    private func isAllowed(_ host: String) -> Bool {
        let allowed = ["puter.site", "puter.com", "cloudflare.com"]
        return allowed.contains { host == $0 || host.hasSuffix("." + $0) }
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // Sign-in popups (Google / Apple / Microsoft via Puter) must finish inside the popup, so never bounce them to Safari.
        if webView != self.webView { decisionHandler(.allow); return }
        if navigationAction.targetFrame?.isMainFrame ?? true,
           let url = navigationAction.request.url,
           let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
           let host = url.host, !isAllowed(host) {
            UIApplication.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
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
        let vc = UIViewController()
        vc.view.backgroundColor = bg
        popup.frame = vc.view.bounds
        popup.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        vc.view.addSubview(popup)
        vc.navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(closePopup))
        let nav = UINavigationController(rootViewController: vc)
        nav.modalPresentationStyle = .formSheet
        var top: UIViewController = self
        while let p = top.presentedViewController { top = p }
        top.present(nav, animated: true)
        if popupNav == nil { popupNav = nav }
        return popup
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
        if webView == self.webView {
            loaded = true
            watchdog?.invalidate()
            if !offlineCopyShown { saveOfflineCopy() }
            retryView?.removeFromSuperview(); retryView = nil
        }
    }

    private func showRetry(_ detail: String = "") {
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
        window.rootViewController = ViewController()
        window.makeKeyAndVisible()
        self.window = window
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
