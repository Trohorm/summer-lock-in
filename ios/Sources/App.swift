import UIKit
import WebKit
import HealthKit

let LIVE_URL = URL(string: "https://summer-lock-in.puter.site")!

// MARK: - HealthKit (steps today + last night's sleep, read-only)
enum Health {
    static let store = HKHealthStore()

    static func request(_ done: @escaping () -> Void) {
        guard HKHealthStore.isHealthDataAvailable(),
              let steps = HKObjectType.quantityType(forIdentifier: .stepCount),
              let sleep = HKObjectType.categoryType(forIdentifier: .sleepAnalysis) else { done(); return }
        store.requestAuthorization(toShare: nil, read: [steps, sleep]) { _, _ in
            DispatchQueue.main.async { done() }
        }
    }

    static func fetch(_ done: @escaping (Int?, Double?) -> Void) {
        guard HKHealthStore.isHealthDataAvailable() else { done(nil, nil); return }
        let group = DispatchGroup()
        var steps: Int?
        var sleepHours: Double?

        if let type = HKObjectType.quantityType(forIdentifier: .stepCount) {
            group.enter()
            let start = Calendar.current.startOfDay(for: Date())
            let pred = HKQuery.predicateForSamples(withStart: start, end: Date(), options: .strictStartDate)
            let q = HKStatisticsQuery(quantityType: type, quantitySamplePredicate: pred, options: .cumulativeSum) { _, result, _ in
                if let sum = result?.sumQuantity() {
                    let v = Int(sum.doubleValue(for: .count()))
                    if v > 0 { steps = v }
                }
                group.leave()
            }
            store.execute(q)
        }

        if let type = HKObjectType.categoryType(forIdentifier: .sleepAnalysis) {
            group.enter()
            let start = Date().addingTimeInterval(-20 * 3600)
            let pred = HKQuery.predicateForSamples(withStart: start, end: Date(), options: [])
            let q = HKSampleQuery(sampleType: type, predicate: pred, limit: HKObjectQueryNoLimit, sortDescriptors: nil) { _, samples, _ in
                var seconds: Double = 0
                (samples as? [HKCategorySample])?.forEach { s in
                    if s.value != HKCategoryValueSleepAnalysis.inBed.rawValue &&
                       s.value != HKCategoryValueSleepAnalysis.awake.rawValue {
                        seconds += s.endDate.timeIntervalSince(s.startDate)
                    }
                }
                if seconds > 15 * 60 { sleepHours = (seconds / 360).rounded() / 10 }
                group.leave()
            }
            store.execute(q)
        }

        group.notify(queue: .main) { done(steps, sleepHours) }
    }
}

// MARK: - Main view controller (thin shell around the live site)
final class ViewController: UIViewController, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
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
        if #available(iOS 14.0, *) { config.limitsNavigationsToAppBoundDomains = true }
        config.userContentController.add(self, name: "health")

        webView = makeWebView(config)
        view.addSubview(webView)
        webView.load(URLRequest(url: LIVE_URL))

        NotificationCenter.default.addObserver(self, selector: #selector(appActive),
                                               name: UIApplication.didBecomeActiveNotification, object: nil)
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

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }

    @objc private func appActive() { pushHealth() }

    private var topVC: UIViewController { presentedViewController ?? self }

    // MARK: Health bridge (web -> native via webkit.messageHandlers.health)
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "health" else { return }
        Health.request { [weak self] in self?.pushHealth() }
    }

    private func pushHealth() {
        Health.fetch { [weak self] steps, sleep in
            guard let self = self, steps != nil || sleep != nil else { return }
            var parts: [String] = []
            if let s = steps { parts.append("steps:\(s)") }
            if let sl = sleep { parts.append("sleep:\(sl)") }
            let js = "window.healthImport && window.healthImport({\(parts.joined(separator: ","))})"
            self.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    // MARK: Navigation — keep app domains inside, open the rest in Safari
    private func isAllowed(_ host: String) -> Bool {
        let allowed = ["puter.site", "puter.com", "cloudflare.com"]
        return allowed.contains { host == $0 || host.hasSuffix("." + $0) }
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
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
        let vc = UIViewController()
        vc.view.backgroundColor = bg
        popup.frame = vc.view.bounds
        popup.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        vc.view.addSubview(popup)
        vc.navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(closePopup))
        let nav = UINavigationController(rootViewController: vc)
        nav.modalPresentationStyle = .formSheet
        present(nav, animated: true)
        popupNav = nav
        return popup
    }

    @objc private func closePopup() { popupNav?.dismiss(animated: true); popupNav = nil }
    func webViewDidClose(_ webView: WKWebView) { if webView != self.webView { closePopup() } }

    // MARK: Offline retry screen
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if webView == self.webView && self.webView.url == nil { showRetry() }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if webView == self.webView {
            retryView?.removeFromSuperview(); retryView = nil
            pushHealth()
        }
    }

    private func showRetry() {
        guard retryView == nil else { return }
        let v = UIView(frame: view.bounds)
        v.backgroundColor = bg
        v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        let label = UILabel()
        label.text = "No connection"
        label.textColor = .white
        label.font = .systemFont(ofSize: 20, weight: .bold)
        let sub = UILabel()
        sub.text = "Summer Lock In needs internet for the first load."
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
        webView.load(URLRequest(url: LIVE_URL))
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
