// hashling-ble: listens for Bluetooth LE advertisements for N seconds and prints
// every advertiser as JSON. Used to spot Find My (AirTag-style), Tile,
// SmartTag and Chipolo trackers near this Mac. It never connects to anything.
import CoreBluetooth
import Foundation

struct Device: Encodable {
    var id: String
    var name: String?
    var rssi: Int
    var mfg: String?
    var services: [String]
    var count: Int
}

struct Output: Encodable {
    var state: String
    var devices: [Device]
    var error: String?
}

final class Scanner: NSObject, CBCentralManagerDelegate {
    private var central: CBCentralManager!
    private var seen: [UUID: Device] = [:]
    private let seconds: Double
    private var state = "unknown"

    init(seconds: Double) {
        self.seconds = seconds
        super.init()
        central = CBCentralManager(delegate: self, queue: nil, options: [CBCentralManagerOptionShowPowerAlertKey: false])
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds + 3) { self.finish() }
    }

    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn:
            state = "poweredOn"
            c.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
            DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { self.finish() }
        case .unauthorized: state = "unauthorized"; finish()
        case .poweredOff: state = "poweredOff"; finish()
        case .unsupported: state = "unsupported"; finish()
        default: state = "unknown"
        }
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData ad: [String: Any], rssi: NSNumber) {
        let mfg = (ad[CBAdvertisementDataManufacturerDataKey] as? Data).map { $0.map { String(format: "%02x", $0) }.joined() }
        let svc = ((ad[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []).map { $0.uuidString }
            + ((ad[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data])?.keys.map { $0.uuidString } ?? [])
        let r = rssi.intValue == 127 ? -100 : rssi.intValue
        if var d = seen[p.identifier] {
            d.count += 1
            d.rssi = max(d.rssi, r)
            if d.mfg == nil { d.mfg = mfg }
            d.services = Array(Set(d.services + svc))
            seen[p.identifier] = d
        } else {
            seen[p.identifier] = Device(id: p.identifier.uuidString, name: p.name ?? (ad[CBAdvertisementDataLocalNameKey] as? String), rssi: r, mfg: mfg, services: svc, count: 1)
        }
    }

    private var done = false
    func finish() {
        if done { return }
        done = true
        central.stopScan()
        let out = Output(state: state, devices: Array(seen.values))
        let enc = JSONEncoder()
        if let data = try? enc.encode(out) { FileHandle.standardOutput.write(data) }
        exit(0)
    }
}

var seconds = 12.0
let args = CommandLine.arguments
if let i = args.firstIndex(of: "--seconds"), i + 1 < args.count, let s = Double(args[i + 1]) { seconds = min(max(s, 2), 60) }
let scanner = Scanner(seconds: seconds)
RunLoop.main.run()
