// hashling-ocr <image>: reads the text and any QR codes in a screenshot or photo, on this Mac,
// with Apple's built-in Vision framework. Prints {"text": "...", "codes": ["..."]} as JSON.
import Foundation
import Vision
import AppKit

struct Out: Encodable { let text: String; let codes: [String]; let error: String? }

func emit(_ o: Out) {
    if let d = try? JSONEncoder().encode(o) { print(String(decoding: d, as: UTF8.self)) }
}

guard CommandLine.arguments.count > 1,
      let image = NSImage(contentsOfFile: CommandLine.arguments[1]),
      let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    emit(Out(text: "", codes: [], error: "Could not open the image."))
    exit(1)
}

let text = VNRecognizeTextRequest()
text.recognitionLevel = .accurate
text.usesLanguageCorrection = true
text.automaticallyDetectsLanguage = true
let codes = VNDetectBarcodesRequest()
codes.symbologies = [.qr, .aztec, .dataMatrix, .pdf417]

do {
    try VNImageRequestHandler(cgImage: cg, options: [:]).perform([text, codes])
    let lines = (text.results ?? []).compactMap { $0.topCandidates(1).first?.string }
    let found = (codes.results ?? []).compactMap { $0.payloadStringValue }
    emit(Out(text: lines.joined(separator: "\n"), codes: found, error: nil))
} catch {
    emit(Out(text: "", codes: [], error: error.localizedDescription))
    exit(1)
}
