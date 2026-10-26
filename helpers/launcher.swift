// Hashling.app's executable. It starts the Hashling daemon (Node) as a child so that
// macOS attributes privacy permissions (Full Disk Access, Bluetooth) to
// "Hashling" rather than to Node itself. launchd keeps it running.
//
// It also owns Hashling's menu bar shield and native notifications. Both only
// read from the daemon; anything that changes the Mac still goes through the
// dashboard's Touch ID approval.
//
//   Hashling                 run the daemon + menu bar (used by the LaunchAgent)
//   Hashling --open [view]   open the dashboard in the browser (view: findings, approvals, ...)
import AppKit
import Foundation
import UserNotifications

setvbuf(stdout, nil, _IOLBF, 0)
let bundle = Bundle.main
let home = FileManager.default.homeDirectoryForCurrentUser.path
/// Info.plist value, or nil when it is empty (the notarized release build leaves both empty,
/// because one signed app has to work on every Mac).
func plistPath(_ key: String) -> String? {
    guard let v = bundle.object(forInfoDictionaryKey: key) as? String, !v.isEmpty else { return nil }
    return v
}
/// Built on this Mac: the paths the installer wrote. Release build: where the installer puts Hashling.
let root = plistPath("HashlingRoot") ?? "\(home)/.hashling/app"
let node = plistPath("HashlingNode")
    ?? ["\(home)/.hashling/runtime/node", "/opt/homebrew/opt/node@24/bin/node", "/usr/local/opt/node@24/bin/node", "/opt/homebrew/bin/node"]
        .first { FileManager.default.isExecutableFile(atPath: $0) } ?? "/opt/homebrew/bin/node"
let base = "http://127.0.0.1:5750"
/// Where the dashboard opens in the browser: the friendly name, which always means this Mac.
let dashboardBase = "http://hashling.localhost:5750"
let stateFile = "\(home)/.hashling/notified.json"
let agentLabel = "dev.hashling.agent"

func readToken() -> String {
    (try? String(contentsOfFile: "\(home)/.hashling/token", encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
}

/// Asks Hashling for a one-time sign-in code (valid 60 s, single use) so the real key never lands in a URL.
func signInCode() -> String? {
    var r = URLRequest(url: URL(string: "\(base)/api/session-code")!, timeoutInterval: 5)
    r.httpMethod = "POST"
    r.httpShouldHandleCookies = false
    r.setValue("Bearer \(readToken())", forHTTPHeaderField: "Authorization")
    let done = DispatchSemaphore(value: 0)
    var code: String?
    URLSession.shared.dataTask(with: r) { data, res, _ in
        if (res as? HTTPURLResponse)?.statusCode == 200, let data,
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            code = json["code"] as? String
        }
        done.signal()
    }.resume()
    _ = done.wait(timeout: .now() + 6)
    return code
}

/// "#/findings" style fragment -> dashboard URL that signs the browser in first.
/// Without a code (Hashling not answering) it opens the unlock screen instead.
func dashboardURL(_ fragment: String = "") -> URL {
    guard let code = signInCode() else { return URL(string: "\(dashboardBase)/\(fragment)")! }
    return URL(string: "\(dashboardBase)/?c=\(code)\(fragment)")!
}

if let i = CommandLine.arguments.firstIndex(of: "--open") {
    let view = CommandLine.arguments.count > i + 1 ? "#/\(CommandLine.arguments[i + 1])" : ""
    NSWorkspace.shared.open(dashboardURL(view))
    exit(0)
}

// MARK: - Daemon

let child = Process()
child.executableURL = URL(fileURLWithPath: node)
child.arguments = ["--no-warnings", "\(root)/src/daemon.ts"]
var env = ProcessInfo.processInfo.environment
env["HASHLING_APP"] = bundle.bundlePath
child.environment = env
child.currentDirectoryURL = URL(fileURLWithPath: root)

for sig in [SIGTERM, SIGINT, SIGHUP] {
    signal(sig, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    src.setEventHandler { child.terminate() }
    src.resume()
    _ = Unmanaged.passRetained(src)
}

child.terminationHandler = { p in exit(p.terminationStatus) }
do {
    try child.run()
} catch {
    FileHandle.standardError.write("Hashling: could not start \(node): \(error)\n".data(using: .utf8)!)
    exit(1)
}

// MARK: - API

struct Overview: Decodable {
    let score: Int
    let verdict: String
    let pendingActions: Int
    let openFindings: [String: Int]
}

struct Finding: Decodable {
    let id: String
    let category: String
    let severity: String
    let title: String
    let summary: String
}

struct Action: Decodable {
    let id: String
    let summary: String
    let reason: String
    let requested_by: String
}

enum API {
    static func request(_ path: String, method: String = "GET", asDashboard: Bool = false) -> URLRequest {
        var r = URLRequest(url: URL(string: base + path)!, timeoutInterval: 10)
        r.httpMethod = method
        r.httpShouldHandleCookies = false
        let token = readToken()
        // Run-now is a dashboard-only route; the menu bar is part of the user's own UI, so it signs in like the dashboard does.
        if asDashboard { r.setValue("hashling_session=\(token)", forHTTPHeaderField: "Cookie") }
        else { r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        r.setValue("Hashling menu bar", forHTTPHeaderField: "x-hashling-client")
        return r
    }

    static func get<T: Decodable>(_ path: String, _ type: T.Type) async -> T? {
        guard let (data, res) = try? await URLSession.shared.data(for: request(path)),
              (res as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    static func post(_ path: String) async -> Bool {
        guard let (_, res) = try? await URLSession.shared.data(for: request(path, method: "POST", asDashboard: true)) else { return false }
        return ((res as? HTTPURLResponse)?.statusCode ?? 500) < 300
    }
}

// MARK: - Paste guard

/// "Paste this into Terminal" scams (fake captchas, fake Mac fix-it pages, Atomic Stealer): a web page
/// copies a command for you and tells you to paste it. Hashling looks at the clipboard only when it changes,
/// only on this Mac, and only for this shape of command. The text is never saved or sent anywhere.
final class PasteGuard {
    private var last = NSPasteboard.general.changeCount
    private let danger = try! NSRegularExpression(pattern: #"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?((ba|z)?sh|python3?)\b|\$\(\s*(curl|wget)\b|base64\s+(-d|-D|--decode)[^\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|\bosascript\s+-e\b|xattr\s+-[a-z]*[cd][a-z]*\b.*quarantine|chmod\s+\+x\s+/(tmp|private/tmp)/"#, options: [.caseInsensitive])
    private let trusted = try! NSRegularExpression(pattern: #"raw\.githubusercontent\.com/Homebrew|brew\.sh|sh\.rustup\.rs|get\.pnpm\.io|bun\.sh|deno\.land|astral\.sh|nvm-sh|claude\.ai/install|install\.python-poetry|get\.docker\.com|ollama\.com/install"#, options: [.caseInsensitive])
    /// Copies made inside your own terminal or code editor are your own work.
    private let ownTools: Set<String> = ["com.apple.Terminal", "com.googlecode.iterm2", "dev.warp.Warp-Stable", "com.mitchellh.ghostty", "com.microsoft.VSCode", "com.todesktop.230313mzl4w4u92", "com.apple.dt.Xcode", "dev.zed.Zed", "com.anthropic.claudefordesktop"]
    var enabled: Bool {
        get { UserDefaults.standard.object(forKey: "pasteGuard") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "pasteGuard") }
    }
    var onDanger: ((_ source: String, _ text: String) -> Void)?
    /// Clipper malware swaps a copied wallet address for the attacker's within moments.
    var onSwap: ((_ original: String, _ replacement: String) -> Void)?
    private var lastAddress: (text: String, kind: String, at: Date)?
    private let addressKinds: [(String, NSRegularExpression)] = [
        ("Bitcoin", try! NSRegularExpression(pattern: #"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"#)),
        ("Ethereum", try! NSRegularExpression(pattern: #"^0x[a-fA-F0-9]{40}$"#)),
        ("Tron", try! NSRegularExpression(pattern: #"^T[1-9A-HJ-NP-Za-km-z]{33}$"#)),
        ("Solana", try! NSRegularExpression(pattern: #"^[1-9A-HJ-NP-Za-km-z]{32,44}$"#)),
    ]
    private func addressKind(_ s: String) -> String? {
        let r = NSRange(s.startIndex..., in: s)
        return addressKinds.first { $0.1.firstMatch(in: s, range: r) != nil }?.0
    }

    func start() { Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in self?.check() } }

    private func check() {
        let pb = NSPasteboard.general
        guard pb.changeCount != last else { return }
        last = pb.changeCount
        guard enabled, let s = pb.string(forType: .string), s.count < 20_000 else { return }
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if let kind = addressKind(trimmed) {
            if let prev = lastAddress, prev.kind == kind, prev.text != trimmed, Date().timeIntervalSince(prev.at) < 2 {
                lastAddress = nil
                onSwap?(prev.text, trimmed)
                return
            }
            lastAddress = (trimmed, kind, Date())
            return
        }
        let front = NSWorkspace.shared.frontmostApplication
        if let id = front?.bundleIdentifier, ownTools.contains(id) { return }
        let r = NSRange(s.startIndex..., in: s)
        guard danger.firstMatch(in: s, range: r) != nil, trusted.firstMatch(in: s, range: r) == nil else { return }
        onDanger?(front?.localizedName ?? "An app", s)
    }

    /// After clearing, the next change is ours, not a new copy.
    func clear() { NSPasteboard.general.clearContents(); last = NSPasteboard.general.changeCount }
    func restore(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        last = NSPasteboard.general.changeCount
        // If the malware swaps it again, that is caught too.
        if let kind = addressKind(text) { lastAddress = (text, kind, Date()) }
    }
}

// MARK: - Camera and microphone watch

/// Follows the same log macOS uses for the orange and green dots, live, and speaks up the first time
/// an app uses the camera or microphone. Apps you have seen before stay quiet.
final class SensorWatch {
    private var proc: Process?
    private var buffer = Data()
    private var active = Set<String>()
    private let attribution = try! NSRegularExpression(pattern: #""(cam|mic|scr):([^"]+)""#)
    var onFirstUse: ((_ kind: String, _ bundleID: String) -> Void)?
    private var seen: Set<String> {
        get { Set(UserDefaults.standard.stringArray(forKey: "sensorSeen") ?? []) }
        set { UserDefaults.standard.set(Array(newValue), forKey: "sensorSeen") }
    }

    struct History: Decodable { struct S: Decodable { let kind: String; let app: String }; let sessions: [S]? }

    /// Apps already seen using the camera or mic (from Hashling's 7-day history) are not "first time".
    func seedFromHistory() async {
        // Seeded once per version of what is watched (v2 added screen recording).
        if UserDefaults.standard.bool(forKey: "sensorSeededV2") { return }
        // Right after a restart the history may not be collected yet; wait for it rather than saving an empty list.
        for _ in 0..<20 {
            if let h = await API.get("/api/sensors", History.self), let sessions = h.sessions {
                seen = seen.union(sessions.filter { ["cam", "mic", "scr"].contains($0.kind) }.map { "\($0.kind):\($0.app)" })
                UserDefaults.standard.set(true, forKey: "sensorSeededV2")
                return
            }
            try? await Task.sleep(nanoseconds: 30_000_000_000)
        }
    }

    func start() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        p.arguments = ["stream", "--style", "compact", "--predicate", #"subsystem == "com.apple.controlcenter" AND category == "sensor-indicators" AND eventMessage BEGINSWITH "Active activity attributions changed""#]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            DispatchQueue.main.async { self?.consume(d) }
        }
        // If log stream ever exits, start it again a little later.
        p.terminationHandler = { [weak self] _ in DispatchQueue.main.asyncAfter(deadline: .now() + 30) { self?.start() } }
        try? p.run()
        proc = p
    }

    private func consume(_ d: Data) {
        buffer.append(d)
        while let nl = buffer.firstIndex(of: 10) {
            let line = String(decoding: buffer[..<nl], as: UTF8.self)
            buffer.removeSubrange(...nl)
            guard line.contains("Active activity attributions changed") else { continue }
            let ns = line as NSString
            let now = Set(attribution.matches(in: line, range: NSRange(location: 0, length: ns.length)).map { "\(ns.substring(with: $0.range(at: 1))):\(ns.substring(with: $0.range(at: 2)))" })
            // macOS's own parts (the screenshot tool, FaceTime, Siri) are not news.
            for key in now.subtracting(active) where !seen.contains(key) && !key.contains(":com.apple.") {
                seen.insert(key)
                let parts = key.split(separator: ":", maxSplits: 1).map(String.init)
                onFirstUse?(parts[0], parts[1])
            }
            active = now
        }
    }
}

// MARK: - Notification de-dupe

/// IDs already alerted on, kept on disk so a finding or proposal never alerts twice, even across restarts.
struct Notified: Codable {
    var findings: [String] = []
    var actions: [String] = []

    static func load() -> Notified? {
        guard let d = FileManager.default.contents(atPath: stateFile) else { return nil }
        return try? JSONDecoder().decode(Notified.self, from: d)
    }

    func save() {
        let trimmed = Notified(findings: Array(findings.suffix(3000)), actions: Array(actions.suffix(3000)))
        guard let d = try? JSONEncoder().encode(trimmed) else { return }
        FileManager.default.createFile(atPath: stateFile, contents: d, attributes: [.posixPermissions: 0o600])
    }
}

/// What deserves an interruption: anything high or critical, any malware hit, any tracker following you.
func alertWorthy(_ f: Finding) -> Bool {
    f.severity == "high" || f.severity == "critical" || f.category == "malware" || f.category == "malware-artifacts" || f.category == "trackers"
}

// MARK: - Event stream (real time)

/// Listens to /api/stream and calls onChange (debounced) whenever the daemon reports new data.
final class Stream: NSObject, URLSessionDataDelegate {
    private var session: URLSession!
    private var task: URLSessionDataTask?
    private var buffer = ""
    private let onChange: () -> Void

    init(onChange: @escaping () -> Void) {
        self.onChange = onChange
        super.init()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 90 // the daemon pings every 20 s
        cfg.timeoutIntervalForResource = .infinity
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: .main)
    }

    func connect() {
        var r = API.request("/api/stream")
        r.timeoutInterval = 90
        task = session.dataTask(with: r)
        task?.resume()
    }

    func urlSession(_ s: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        buffer += String(decoding: data, as: UTF8.self)
        while let r = buffer.range(of: "\n\n") {
            let block = buffer[..<r.lowerBound]
            buffer.removeSubrange(..<r.upperBound)
            if block.contains("event: change") { onChange() }
        }
    }

    func urlSession(_ s: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        buffer = ""
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in self?.connect() }
    }
}

// MARK: - Menu bar + notifications

final class App: NSObject, NSApplicationDelegate, NSMenuDelegate, UNUserNotificationCenterDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let menu = NSMenu()
    var stream: Stream?
    var overview: Overview?
    var notified = Notified.load()
    var refreshing = false
    var again = false
    var debounce: DispatchWorkItem?
    let pasteGuard = PasteGuard()
    let sensors = SensorWatch()
    var pausedUntil: Date? {
        get { (UserDefaults.standard.object(forKey: "pausedUntil") as? Date).flatMap { $0 > Date() ? $0 : nil } }
        set { UserDefaults.standard.set(newValue, forKey: "pausedUntil") }
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        item.button?.toolTip = "Hashling"
        paint()
        build()

        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { ok, err in
            if !ok { print("Hashling notifications: not allowed\(err.map { " (\($0.localizedDescription))" } ?? "")") }
        }

        stream = Stream { [weak self] in self?.scheduleRefresh() }
        // Give the daemon a moment to bind its port before the first call.
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            self?.stream?.connect()
            self?.refresh()
        }
        Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in self?.refresh() }
        // Tell the dashboard whether Hashling may show notifications (most warnings arrive that way), once it is up and then now and again.
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in self?.reportNotificationState() }
        Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { [weak self] _ in self?.reportNotificationState() }
        pasteGuard.onDanger = { [weak self] source, text in self?.warnPaste(source: source, text: text) }
        pasteGuard.onSwap = { [weak self] original, replacement in self?.warnSwap(original: original, replacement: replacement) }
        pasteGuard.start()
        sensors.onFirstUse = { [weak self] kind, id in self?.warnSensor(kind: kind, bundleID: id) }
        sensors.start()
        // Apps already in Hashling's camera/mic history are not "first time"; the daemon needs a moment to start.
        Task { try? await Task.sleep(nanoseconds: 6_000_000_000); await sensors.seedFromHistory() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            let w = self?.item.button?.window
            print("Hashling menu bar: shield \(w?.isVisible == true ? "shown" : "hidden") at \(w.map { NSStringFromRect($0.frame) } ?? "nowhere")")
            UNUserNotificationCenter.current().getNotificationSettings { s in
                let state = s.authorizationStatus == .authorized || s.authorizationStatus == .provisional ? "on" : s.authorizationStatus == .denied ? "off" : "undecided"
                print("Hashling notifications: \(state == "on" ? "allowed" : state == "off" ? "turned off in System Settings" : "not decided yet")")
            }
        }
    }

    // MARK: Data

    func scheduleRefresh() {
        debounce?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.refresh() }
        debounce = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: w)
    }

    func refresh() {
        if refreshing { again = true; return }
        refreshing = true
        Task { @MainActor in
            defer {
                refreshing = false
                if again { again = false; refresh() }
            }
            overview = await API.get("/api/overview", Overview.self)
            paint()
            build()
            guard overview != nil,
                  let findings = await API.get("/api/findings?status=active&limit=500", [Finding].self),
                  let actions = await API.get("/api/actions?status=pending", [Action].self) else { return }
            alert(findings: findings.filter(alertWorthy), actions: actions)
        }
    }

    // MARK: Notifications

    func alert(findings: [Finding], actions: [Action]) {
        // First run: remember what is already there instead of flooding the user with old news.
        guard var seen = notified else {
            notified = Notified(findings: findings.map(\.id), actions: actions.map(\.id))
            notified?.save()
            return
        }
        let newFindings = findings.filter { !seen.findings.contains($0.id) }
        let newActions = actions.filter { !seen.actions.contains($0.id) }
        if newFindings.isEmpty && newActions.isEmpty { return }
        seen.findings += newFindings.map(\.id)
        seen.actions += newActions.map(\.id)
        notified = seen
        seen.save()
        // Critical (ransomware, a stranger taking control) breaks through paused alerts and turned-off notifications.
        for f in newFindings where f.severity == "critical" || f.title.hasPrefix("A just-installed app can now control") { urgent(f) }
        if pausedUntil != nil { return }

        if newFindings.count > 3 {
            post(id: "findings-\(Date().timeIntervalSince1970)", title: "I found \(newFindings.count) new things that need a look",
                 body: newFindings.prefix(3).map(\.title).joined(separator: "\n"), view: "#/findings")
        } else {
            for f in newFindings { notify(f) }
        }
        if newActions.count > 2 {
            post(id: "actions-\(Date().timeIntervalSince1970)", title: "\(newActions.count) agent requests are waiting",
                 body: "Review and approve them with Touch ID.", view: "#/approvals")
        } else {
            for a in newActions {
                post(id: "action-\(a.id)", title: "Approval needed",
                     body: "\(a.requested_by) wants to: \(a.summary)" + (a.reason.isEmpty ? "" : "\n\(a.reason)"), view: "#/approvals")
            }
        }
    }

    func notify(_ f: Finding) {
        let title: String
        var view = "#/findings?id=\(f.id)"
        switch f.category {
        case "malware", "malware-artifacts": title = "Malware found"
        case "trackers": title = "A tracker may be following you"; view = "#/tracking"
        default: title = f.severity == "critical" ? "Critical: \(f.title)" : "Needs attention: \(f.title)"
        }
        let body = f.category == "malware" || f.category == "trackers" || f.category == "malware-artifacts" ? "\(f.title)\n\(f.summary)" : f.summary
        post(id: "finding-\(f.id)", title: title, body: body, view: view)
    }

    func post(id: String, title: String, body: String, view: String) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        c.sound = .default
        c.userInfo = ["view": view]
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: c, trigger: nil)) { err in
            print("Hashling alert: \(title)\(err.map { " (not shown: \($0.localizedDescription))" } ?? "")")
        }
    }

    func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse, withCompletionHandler done: @escaping () -> Void) {
        let view = r.notification.request.content.userInfo["view"] as? String ?? ""
        NSWorkspace.shared.open(dashboardURL(view))
        done()
    }

    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification, withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .list, .sound])
    }

    // MARK: Menu

    func paint() {
        guard let button = item.button else { return }
        guard let o = overview else {
            let img = NSImage(systemSymbolName: "number", accessibilityDescription: "Hashling is starting up")
            img?.isTemplate = true
            button.image = img
            return
        }
        // Hashling is a #: the menu bar shows it in green, orange or red for how the Mac is doing.
        let (symbol, color): (String, NSColor) = o.score >= 80 ? ("number", .systemGreen)
            : o.score >= 50 ? ("number", .systemOrange)
            : ("number", .systemRed)
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .bold).applying(.init(paletteColors: [color]))
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "Hashling score \(o.score)")?.withSymbolConfiguration(cfg)
        img?.isTemplate = false
        button.image = img
        button.toolTip = "Hashling: \(o.score)/100, \(o.verdict)"
    }

    func menuWillOpen(_ m: NSMenu) { refresh() }

    func build() {
        menu.removeAllItems()
        if let o = overview {
            menu.addItem(info("Security score \(o.score) of 100", bold: true))
            menu.addItem(info(o.verdict))
            menu.addItem(.separator())
            if o.pendingActions > 0 {
                menu.addItem(action(o.pendingActions == 1 ? "1 approval waiting" : "\(o.pendingActions) approvals waiting", #selector(openApprovals)))
            } else {
                menu.addItem(info("No approvals waiting"))
            }
        } else {
            menu.addItem(info("Starting up, one moment..."))
        }
        menu.addItem(.separator())
        menu.addItem(action("Open dashboard", #selector(openDashboard), key: "d"))
        menu.addItem(action("Check a message for scams…", #selector(openScamCheck)))
        menu.addItem(action("I think I’ve been hacked…", #selector(openHacked)))
        menu.addItem(action("Run check-up now", #selector(runCheckup), key: "r", enabled: overview != nil))
        if let until = pausedUntil {
            let t = DateFormatter.localizedString(from: until, dateStyle: .none, timeStyle: .short)
            menu.addItem(action("Resume alerts (paused until \(t))", #selector(resumeAlerts)))
        } else {
            menu.addItem(action("Pause alerts for 1 hour", #selector(pauseAlerts)))
        }
        let guardItem = action("Warn before risky Terminal pastes", #selector(togglePasteGuard))
        guardItem.state = pasteGuard.enabled ? .on : .off
        menu.addItem(guardItem)
        menu.addItem(.separator())
        menu.addItem(action("Quit Hashling", #selector(quit), key: "q"))
    }

    func info(_ title: String, bold: Bool = false) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        i.isEnabled = false
        if bold { i.attributedTitle = NSAttributedString(string: title, attributes: [.font: NSFont.menuFont(ofSize: 0).withWeight(.semibold)]) }
        return i
    }

    func action(_ title: String, _ sel: Selector, key: String = "", enabled: Bool = true) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        i.target = self
        i.isEnabled = enabled
        return i
    }

    @objc func openDashboard() { NSWorkspace.shared.open(dashboardURL()) }
    func reportNotificationState() {
        UNUserNotificationCenter.current().getNotificationSettings { s in
            let state = s.authorizationStatus == .authorized || s.authorizationStatus == .provisional ? "on" : s.authorizationStatus == .denied ? "off" : "undecided"
            var r = API.request("/api/client-status", method: "POST", asDashboard: true)
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
            r.httpBody = try? JSONSerialization.data(withJSONObject: ["notifications": state])
            URLSession.shared.dataTask(with: r).resume()
        }
    }

    @objc func openScamCheck() { NSWorkspace.shared.open(dashboardURL("#/scamcheck")) }
    @objc func openHacked() { NSWorkspace.shared.open(dashboardURL("#/hacked")) }
    @objc func openApprovals() { NSWorkspace.shared.open(dashboardURL("#/approvals")) }

    @objc func runCheckup() {
        Task {
            var ok = true
            for name in ["posture", "network", "persistence", "permissions", "location", "trackers", "agents", "attackPacks"] {
                ok = await API.post("/api/run/\(name)") && ok
            }
            post(id: "checkup-\(Date().timeIntervalSince1970)", title: ok ? "Check-up started" : "Check-up could not start",
                 body: ok ? "I’m re-checking this Mac now. I’ll alert you if I find anything serious." : "I didn’t answer in time. Try again in a moment.",
                 view: "")
        }
    }

    /// Shown even while alerts are paused: this one is about to happen, not a report of something past.
    func warnPaste(source: String, text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .critical
        a.messageText = "Don’t paste this into Terminal"
        a.informativeText = "\(source) just copied a command that downloads and runs a program on your Mac.\n\nFake “verify you are human” pages and fake Mac fix-it guides use this exact trick to install programs that steal passwords, bank logins and crypto. Real websites, Apple and your bank never ask you to paste commands into Terminal."
        a.addButton(withTitle: "Clear it, keep me safe")
        a.addButton(withTitle: "I trust it")
        let cleared = a.runModal() == .alertFirstButtonReturn
        if cleared { pasteGuard.clear() }
        var r = API.request("/api/paste-guard", method: "POST", asDashboard: true)
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try? JSONSerialization.data(withJSONObject: ["source": source, "cleared": cleared, "command": String(text.prefix(400))])
        URLSession.shared.dataTask(with: r).resume()
    }

    func warnSensor(kind: String, bundleID: String) {
        let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
        let name = url.map { $0.deletingPathExtension().lastPathComponent } ?? bundleID
        let what = kind == "cam" ? "camera" : kind == "scr" ? "screen" : "microphone"
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = kind == "scr" ? "\(name) is recording your screen for the first time" : "\(name) is using your \(what) for the first time"
        a.informativeText = "If you just started a call or recording in \(name), this is expected and I won’t ask again. If you did not, open Hashling and I’ll show you what it is and how to take the permission away."
        a.addButton(withTitle: "That was me")
        a.addButton(withTitle: "Open Hashling")
        if a.runModal() == .alertSecondButtonReturn { NSWorkspace.shared.open(dashboardURL("#/permissions")) }
        var r = API.request("/api/sensor-alert", method: "POST", asDashboard: true)
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try? JSONSerialization.data(withJSONObject: ["app": name, "kind": what])
        URLSession.shared.dataTask(with: r).resume()
    }

    func warnSwap(original: String, replacement: String) {
        NSApp.activate(ignoringOtherApps: true)
        let short = { (s: String) in s.count > 16 ? "\(s.prefix(8))…\(s.suffix(6))" : s }
        let a = NSAlert()
        a.alertStyle = .critical
        a.messageText = "The wallet address you copied was swapped"
        a.informativeText = "You copied \(short(original)), but a moment later something on this Mac replaced it with \(short(replacement)).\n\nThis is how crypto-stealing malware redirects payments to the thief. Do not send anything to the new address. Open Hashling and let me run a malware scan."
        a.addButton(withTitle: "Put back the address I copied")
        a.addButton(withTitle: "Leave it")
        let restored = a.runModal() == .alertFirstButtonReturn
        if restored { pasteGuard.restore(original) }
        var r = API.request("/api/paste-guard", method: "POST", asDashboard: true)
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try? JSONSerialization.data(withJSONObject: ["kind": "address-swap", "source": NSWorkspace.shared.frontmostApplication?.localizedName ?? "An app", "cleared": restored, "command": "\(short(original)) → \(short(replacement))"])
        URLSession.shared.dataTask(with: r).resume()
    }

    func urgent(_ f: Finding) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .critical
        a.messageText = f.title
        a.informativeText = "\(f.summary)\n\nOpen Hashling now and I’ll show you exactly what to do."
        a.addButton(withTitle: "Open Hashling")
        a.addButton(withTitle: "Later")
        if a.runModal() == .alertFirstButtonReturn { NSWorkspace.shared.open(dashboardURL("#/findings?id=\(f.id)")) }
    }

    @objc func togglePasteGuard() { pasteGuard.enabled.toggle(); build() }

    @objc func pauseAlerts() { pausedUntil = Date().addingTimeInterval(3600); build() }
    @objc func resumeAlerts() { pausedUntil = nil; build() }

    @objc func quit() {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Quit Hashling?"
        a.informativeText = "I’ll stop watching this Mac until you log in again. To bring me back sooner, open Hashling from the Applications folder in your home folder."
        a.addButton(withTitle: "Quit")
        a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        // launchd keeps Hashling alive, so take it out of launchd instead of just exiting.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["bootout", "gui/\(getuid())/\(agentLabel)"]
        if (try? p.run()) == nil { child.terminate() }
    }
}

extension NSFont {
    func withWeight(_ w: NSFont.Weight) -> NSFont {
        NSFont.systemFont(ofSize: pointSize, weight: w)
    }
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
