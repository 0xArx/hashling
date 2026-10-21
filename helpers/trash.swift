// hashling-trash <path>...: moves each item to the user's Trash with Finder's own
// mechanism (so "Put Back" works). Prints one JSON line per item. Never deletes.
import Foundation

struct Result: Encodable { let path: String; let ok: Bool; let trashedAs: String?; let error: String? }

let enc = JSONEncoder()
var failures = 0
for path in CommandLine.arguments.dropFirst() {
    var out: NSURL?
    do {
        try FileManager.default.trashItem(at: URL(fileURLWithPath: path), resultingItemURL: &out)
        if let d = try? enc.encode(Result(path: path, ok: true, trashedAs: (out as URL?)?.path, error: nil)) { print(String(decoding: d, as: UTF8.self)) }
    } catch {
        failures += 1
        if let d = try? enc.encode(Result(path: path, ok: false, trashedAs: nil, error: error.localizedDescription)) { print(String(decoding: d, as: UTF8.self)) }
    }
}
exit(failures == 0 ? 0 : 1)
