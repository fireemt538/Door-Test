import SwiftUI
import CommonCrypto

// MARK: - Model

struct Door: Identifiable, Codable, Equatable {
    var id = UUID()
    var name: String = ""
    var statusPin: String = ""   // "A3" or "3"
    var relayPin: String = ""    // "6" or "D6" or "A1"

    /// ID the Arduino uses in its XML <status statusPin="..">. A0..A5 -> 0..5, Dn -> n
    var statusId: Int? { Door.parse(statusPin, analogAsIndex: true) }
    /// Actual digital pin number to pass as relayPin=. A0..A5 -> 14..19
    var relayNumber: Int? { Door.parse(relayPin, analogAsIndex: false) }

    static func parse(_ s: String, analogAsIndex: Bool) -> Int? {
        let t = s.trimmingCharacters(in: .whitespaces).uppercased()
        if t.hasPrefix("A"), let n = Int(t.dropFirst()), (0...7).contains(n) { return analogAsIndex ? n : 14 + n }
        if t.hasPrefix("D"), let n = Int(t.dropFirst()) { return n }
        return Int(t)
    }
    var isValid: Bool { !name.isEmpty && statusId != nil && relayNumber != nil }
}

// MARK: - XML parsing

final class ReplyParser: NSObject, XMLParserDelegate {
    var statuses: [Int: Bool] = [:]
    var token = ""
    private var currentPin: Int?
    private var text = ""

    func parser(_ p: XMLParser, didStartElement name: String, namespaceURI: String?,
                qualifiedName: String?, attributes: [String: String] = [:]) {
        text = ""
        if name == "status" { currentPin = Int(attributes["statusPin"] ?? "") }
    }
    func parser(_ p: XMLParser, foundCharacters s: String) { text += s }
    func parser(_ p: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if name == "status", let pin = currentPin { statuses[pin] = (t == "Opened") }
        if name == "challengeToken" { token = t }
    }
}

// MARK: - Crypto (AES-256 ECB, key = token zero-padded to 32 bytes)

func encryptPassword(_ password: String, token: String) -> String {
    var key = [UInt8](repeating: 0, count: 32)
    for (i, b) in token.utf8.prefix(32).enumerated() { key[i] = b }
    var block = [UInt8](repeating: 0, count: 16)
    for (i, b) in password.utf8.prefix(16).enumerated() { block[i] = b }
    var out = [UInt8](repeating: 0, count: 32)
    var n = 0
    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
            key, 32, nil, block, 16, &out, 32, &n)
    return out.prefix(16).map { String(format: "%02x", $0) }.joined()
}

// MARK: - Store

@MainActor
final class DoorStore: ObservableObject {
    @Published var host: String     { didSet { UserDefaults.standard.set(host, forKey: "host") } }
    @Published var port: String     { didSet { UserDefaults.standard.set(port, forKey: "port") } }
    @Published var password: String { didSet { UserDefaults.standard.set(password, forKey: "pw") } }
    @Published var doors: [Door]    { didSet { save() } }
    @Published var open: [Int: Bool] = [:]
    @Published var online = false
    @Published var busy: Set<UUID> = []
    @Published var message: String?

    init() {
        let d = UserDefaults.standard
        host = d.string(forKey: "host") ?? ""
        port = d.string(forKey: "port") ?? "8080"
        password = d.string(forKey: "pw") ?? ""
        if let data = d.data(forKey: "doors"), let arr = try? JSONDecoder().decode([Door].self, from: data) {
            doors = arr
        } else { doors = [] }
    }

    private func save() {
        if let data = try? JSONEncoder().encode(doors) { UserDefaults.standard.set(data, forKey: "doors") }
    }

    var configured: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    var baseURL: String { "http://\(host.trimmingCharacters(in: .whitespaces)):\(port.trimmingCharacters(in: .whitespaces))" }

    private func request(_ query: String = "") async -> (statuses: [Int: Bool], token: String)? {
        guard configured, let url = URL(string: baseURL + "/" + (query.isEmpty ? "" : "?" + query)) else { return nil }
        var req = URLRequest(url: url)
        req.timeoutInterval = 4
        req.cachePolicy = .reloadIgnoringLocalCacheData
        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let parser = ReplyParser()
            let xml = XMLParser(data: data)
            xml.delegate = parser
            guard xml.parse() else { return nil }
            return (parser.statuses, parser.token)
        } catch { return nil }
    }

    func refresh() async {
        if let r = await request() { open = r.statuses; online = true } else { online = false }
    }

    func isOpen(_ d: Door) -> Bool? {
        guard online, let id = d.statusId else { return nil }
        return open[id]
    }

    func toggle(_ door: Door) async {
        guard let relay = door.relayNumber else { message = "Invalid relay pin."; return }
        busy.insert(door.id)
        defer { busy.remove(door.id) }
        guard let fresh = await request(), !fresh.token.isEmpty else {
            message = "Can't reach the controller."
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            return
        }
        let hex = encryptPassword(password, token: fresh.token)
        if let r = await request("relayPin=\(relay)&password=\(hex)") {
            open = r.statuses; online = true
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } else {
            message = "Command failed."
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
        try? await Task.sleep(nanoseconds: 1_500_000_000)
        await refresh()
    }
}

// MARK: - App

@main
struct MillerDoorApp: App {
    var body: some Scene {
        WindowGroup { ContentView().preferredColorScheme(.dark) }
    }
}

struct ContentView: View {
    @StateObject private var store = DoorStore()
    @State private var pending: Door?
    @State private var showSettings = false

    private var anyOpen: Bool { store.doors.contains { store.isOpen($0) == true } }
    private var openCount: Int { store.doors.filter { store.isOpen($0) == true }.count }

    var body: some View {
        NavigationStack {
            ZStack {
                LinearGradient(colors: [Color(red: 0.05, green: 0.07, blue: 0.14),
                                        anyOpen ? Color(red: 0.25, green: 0.08, blue: 0.08)
                                                : Color(red: 0.05, green: 0.2, blue: 0.2)],
                               startPoint: .top, endPoint: .bottom)
                    .ignoresSafeArea()
                    .animation(.easeInOut(duration: 0.8), value: anyOpen)

                ScrollView {
                    VStack(spacing: 18) {
                        if store.doors.isEmpty || !store.configured {
                            emptyState
                        } else {
                            header
                            LazyVGrid(columns: [GridItem(.flexible(), spacing: 14), GridItem(.flexible())], spacing: 14) {
                                ForEach(store.doors.filter { $0.isValid }) { door in
                                    DoorCard(door: door, isOpen: store.isOpen(door),
                                             busy: store.busy.contains(door.id)) { pending = door }
                                }
                            }
                            if let url = URL(string: store.baseURL + "/config") {
                                Link(destination: url) {
                                    Label("Controller web settings", systemImage: "safari")
                                        .font(.footnote).foregroundStyle(.secondary)
                                }.padding(.top, 8)
                            }
                        }
                    }
                    .padding()
                }
                .refreshable { await store.refresh() }
            }
            .navigationTitle("MillerDoor")
            .toolbar { Button { showSettings = true } label: { Image(systemName: "gearshape.fill") } }
            .sheet(isPresented: $showSettings) { SettingsView(store: store) }
            .confirmationDialog(pending.map { "\(store.isOpen($0) == true ? "Close" : "Open") \($0.name)?" } ?? "",
                                isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } }),
                                titleVisibility: .visible) {
                if let d = pending {
                    Button(store.isOpen(d) == true ? "Close" : "Open") {
                        UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
                        Task { await store.toggle(d) }
                    }
                }
                Button("Cancel", role: .cancel) {}
            }
            .alert("Oops", isPresented: Binding(get: { store.message != nil }, set: { if !$0 { store.message = nil } })) {
                Button("OK") {}
            } message: { Text(store.message ?? "") }
        }
        .task {
            if !store.configured || store.doors.isEmpty { showSettings = true }
            while !Task.isCancelled {
                await store.refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "door.left.hand.closed").font(.system(size: 54)).foregroundStyle(.teal)
            Text("Set up MillerDoor").font(.title2.bold())
            Text("Enter your controller address, password and doors.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button("Open Settings") { showSettings = true }.buttonStyle(.borderedProminent).tint(.teal)
        }.padding(.top, 80)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Circle().fill(!store.online ? .gray : (anyOpen ? .red : .green)).frame(width: 12, height: 12)
                .shadow(color: !store.online ? .clear : (anyOpen ? .red : .green), radius: 6)
            Text(!store.online ? "Offline" : (anyOpen ? "\(openCount) open" : "All secure"))
                .font(.title3.weight(.semibold))
            Spacer()
        }.padding(.horizontal, 4)
    }
}

struct DoorCard: View {
    let door: Door
    let isOpen: Bool?
    let busy: Bool
    let action: () -> Void
    private var color: Color { isOpen == nil ? .gray : (isOpen! ? .red : .green) }

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: isOpen == true ? "door.left.hand.open" : "door.left.hand.closed")
                        .font(.title).foregroundStyle(color)
                    Spacer()
                    if busy { ProgressView() }
                }
                Spacer(minLength: 20)
                Text(door.name).font(.headline).foregroundStyle(.primary)
                Text(isOpen == nil ? "Unknown" : (isOpen! ? "OPEN" : "Closed"))
                    .font(.subheadline.weight(.bold)).foregroundStyle(color)
                Text(isOpen == true ? "Tap to close" : "Tap to open")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 150, alignment: .leading)
            .padding(16)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(color.opacity(0.6), lineWidth: 1.5))
            .shadow(color: color.opacity(0.35), radius: 12, y: 4)
        }
        .buttonStyle(.plain)
        .disabled(busy)
        .animation(.easeInOut, value: isOpen)
    }
}

// MARK: - Settings

struct SettingsView: View {
    @ObservedObject var store: DoorStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section("Controller") {
                    TextField("IP address or hostname", text: $store.host)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("Port", text: $store.port).keyboardType(.numberPad)
                    SecureField("Password", text: $store.password)
                    HStack {
                        Text("Status"); Spacer()
                        Text(store.online ? "Connected" : "Unreachable")
                            .foregroundStyle(store.online ? .green : .red)
                    }
                }

                Section(header: Text("Doors"),
                        footer: Text("Status pin = the Arduino input wired to the door sensor (e.g. A3). Relay pin = the output that triggers the opener (e.g. 6).")) {
                    ForEach($store.doors) { $door in
                        VStack(alignment: .leading, spacing: 8) {
                            TextField("Door name", text: $door.name).font(.headline)
                            HStack {
                                VStack(alignment: .leading) {
                                    Text("Status pin").font(.caption).foregroundStyle(.secondary)
                                    TextField("A3", text: $door.statusPin)
                                        .textInputAutocapitalization(.characters).autocorrectionDisabled()
                                        .textFieldStyle(.roundedBorder)
                                }
                                VStack(alignment: .leading) {
                                    Text("Relay pin").font(.caption).foregroundStyle(.secondary)
                                    TextField("6", text: $door.relayPin)
                                        .textInputAutocapitalization(.characters).autocorrectionDisabled()
                                        .textFieldStyle(.roundedBorder)
                                }
                            }
                            if !door.isValid {
                                Text("Needs a name and valid pins").font(.caption).foregroundStyle(.orange)
                            }
                        }.padding(.vertical, 4)
                    }
                    .onDelete { store.doors.remove(atOffsets: $0) }
                    .onMove { store.doors.move(fromOffsets: $0, toOffset: $1) }

                    Button { store.doors.append(Door()) } label: { Label("Add door", systemImage: "plus.circle.fill") }
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { EditButton() }
                ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } }
            }
            .task { await store.refresh() }
        }
    }
}
