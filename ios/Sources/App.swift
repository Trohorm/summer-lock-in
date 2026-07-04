import UIKit
import WebKit

// Summer Lock In — native shell around the live Puter app.
// Loads https://summer-lock-in.puter.site so the sideloaded app IS the same Puter
// app as the website (shared account, logs, photos, AI coach). A service worker on
// the site caches the shell so it opens and works offline after the first online
// sign-in. Service workers in WKWebView require App-Bound Domains, so the webview
// runs with limitsNavigationsToAppBoundDomains and the puter domains are listed in
// Info.plist under WKAppBoundDomains.
final class ViewController: UIViewController, WKNavigationDelegate, WKUIDelegate {
    private let appURL = URL(string: "https://summer-lock-in.puter.site/")!
    private let bg = UIColor(red: 0x0e/255.0, green: 0x10/255.0, blue: 0x13/255.0, alpha: 1)
    private var webView: WKWebView!
    private var popupVC: UIViewController?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = bg

        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.websiteDataStore = .default()                 // persistent: cookies, localStorage, service worker
        config.limitsNavigationsToAppBoundDomains = true     // required for service workers in WKWebView
        config.preferences.javaScriptCanOpenWindowsAutomatically = true

        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.isOpaque = false
        webView.backgroundColor = bg
        webView.scrollView.backgroundColor = bg
        webView.scrollView.contentInsetAdjustmentBehavior = .never
        webView.allowsBackForwardNavigationGestures = false
        view.addSubview(webView)

        webView.load(URLRequest(url: appURL))
    }

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }

    private func isInApp(_ url: URL?) -> Bool {
        guard let host = url?.host?.lowercased() else { return false }
        return host == "puter.com"  || host.hasSuffix(".puter.com")
            || host == "puter.site" || host.hasSuffix(".puter.site")
            || host == "puter.localhost"
    }

    // Keep Puter navigation (app, auth, API) inside the app; send other links to Safari.
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if navigationAction.targetFrame == nil { decisionHandler(.allow); return }   // popup → createWebViewWith
        if let url = navigationAction.request.url,
           let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" {
            if isInApp(url) { decisionHandler(.allow) }
            else { UIApplication.shared.open(url); decisionHandler(.cancel) }
            return
        }
        decisionHandler(.allow)
    }

    // Puter sign-in opens a popup (window.open). Present it in-app reusing the SAME
    // configuration so window.opener + postMessage keep working and auth can finish.
    // Non-Puter popups (e.g. the "Powered by Puter" link) go to Safari.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = navigationAction.request.url, !isInApp(url) {
            UIApplication.shared.open(url)
            return nil
        }
        let popup = WKWebView(frame: view.bounds, configuration: configuration)
        popup.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        popup.navigationDelegate = self
        popup.uiDelegate = self
        popup.isOpaque = false
        popup.backgroundColor = bg
        popup.scrollView.backgroundColor = bg

        let sheet = UIViewController()
        sheet.view.backgroundColor = bg
        popup.frame = sheet.view.bounds
        sheet.view.addSubview(popup)
        popupVC = sheet
        present(sheet, animated: true)
        return popup
    }

    // Popup called window.close() (auth finished or cancelled) → dismiss it.
    func webViewDidClose(_ webView: WKWebView) {
        popupVC?.dismiss(animated: true)
        popupVC = nil
    }

    // First-launch-offline (or site unreachable): friendly retry screen on the main webview only.
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        guard webView === self.webView else { return }
        let code = (error as NSError).code
        if code == NSURLErrorCancelled || code == 102 { return }   // policy-cancelled navigation, not a real failure
        showOffline()
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        guard webView === self.webView else { return }
        let code = (error as NSError).code
        if code == NSURLErrorCancelled || code == 102 { return }
        showOffline()
    }
    private func showOffline() {
        let html = """
        <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
        <style>html,body{height:100%;margin:0;background:#0e1013;color:#e9ecf1;
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
        .w{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:24px}
        h1{font-size:20px;letter-spacing:.12em;text-transform:uppercase;font-weight:800;margin:0 0 8px}
        h1 span{color:#5b93ff}p{color:#a6aeba;font-size:15px;line-height:1.5;max-width:300px}
        a{margin-top:18px;display:inline-block;background:#5b93ff;color:#fff;text-decoration:none;
        font-weight:700;padding:12px 22px;border-radius:10px}</style></head>
        <body><div class="w"><h1>Summer <span>Lock In</span></h1>
        <p>Connect to the internet for the first launch. Once you've opened it online and signed in, it works offline.</p>
        <a href="https://summer-lock-in.puter.site/">Retry</a></div></body></html>
        """
        webView.loadHTMLString(html, baseURL: appURL)
    }

    // alert() / confirm() / prompt() support — the app uses all three.
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let ac = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        ac.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler() })
        (presentedViewController ?? self).present(ac, animated: true)
    }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let ac = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        ac.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(false) })
        ac.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler(true) })
        (presentedViewController ?? self).present(ac, animated: true)
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
        (presentedViewController ?? self).present(ac, animated: true)
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
