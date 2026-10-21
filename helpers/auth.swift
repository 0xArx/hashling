// hashling-auth "<what is being approved>": asks the person at the keyboard to
// confirm with Touch ID (or their login password). Exit 0 only on success.
// Every Hashling action goes through this, so an AI agent cannot approve its own
// proposals even if it can reach the local API.
import Foundation
import LocalAuthentication

let reason = CommandLine.arguments.dropFirst().joined(separator: " ")
guard !reason.isEmpty else {
    FileHandle.standardError.write("usage: hashling-auth <reason>\n".data(using: .utf8)!)
    exit(2)
}

let ctx = LAContext()
ctx.localizedCancelTitle = "Don't allow"
var error: NSError?
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
    print("No Touch ID or password available: \(error?.localizedDescription ?? "unknown")")
    exit(3)
}

let sem = DispatchSemaphore(value: 0)
var ok = false
var message = ""
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: String(reason.prefix(150))) { success, err in
    ok = success
    message = success ? "Confirmed" : (err?.localizedDescription ?? "Not confirmed")
    sem.signal()
}
_ = sem.wait(timeout: .now() + 110)
print(message)
exit(ok ? 0 : 1)
