import SwiftUI
import CommonCrypto
import AppIntents

// MARK: - Models

struct Door: Identifiable, Codable, Equatable {
    var id = UUID()
    var name = ""
    var statusPin = ""   // "A3" or "3"
    var relayPin = ""    // "6", "D6" or "A1"

    var statusId: Int? { Door.parse(statusPin, analogAsIndex: true) }
    var relayNumber: Int? { Door.parse(relayPin, analogAsIndex: false) }

    static func parse(_ s: String, analogAsIndex: Bool) -> Int? {
        let t = s.trimmingCharacters(in: .whitespaces).uppercased()
        if t.hasPrefix("A"), let n = Int(t.dropFirst()), (0...7).contains(n) { return analogAsIndex ? n : 14 + n }
        if t.hasPrefix("D"), let n = Int(t.dropFirst()) { return n }
        return Int(t)
    }
    var isValid: Bool { !name.isEmpty && statusId != nil && relayNumber != nil }
}

struct Controller: Identifiable, Codable, Equatable {
    var id = UUID()
    var name = "Controller"
    var host = ""
    var port = "8080"
    var password = ""
    var doors: [Door] = []

    var configured: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    var baseURL: String { "http://\(host.trimmingCharacters(in: .whitespaces)):\(port.trimmingCharacters(in: .whitespaces))" }
    var validDoors: [Door] { doors.filter { $0.isValid } }
}

// MARK: - Persistence (shared with Siri intents)

enum ConfigStore {
    static let key = "controllers_v2"

    static func load() -> [Controller] {
        let d = UserDefaults.standard
        if let data = d.data(forKey: key), let arr = try? JSONDecoder().decode([Controller].self, from: data) { return arr }
        // migrate from v1 (single controller) if present
        if let host = d.string(forKey: "host"), !host.isEmpty {
            var c = Controller(name: "Controller 1")
            c.host = host
            c.port = d.string(forKey: "port") ?? "8080"
            c.password = d.string(forKey: "pw") ?? ""
            if let data = d.data(forKey: "doors"), let doors = try? JSONDecoder().decode([Door].self, from: data) { c.doors = doors }
            return [c]
        }
        return []
    }

    static func save(_ controllers: [Controller]) {
        if let data = try? JSONEncoder().encode(controllers) { UserDefaults.standard.set(data, forKey: key) }
    }

    static func find(doorID: String) -> (Controller, Door)? {
        for c in load() {
            if let d = c.doors.first(where: { $0.id.uuidString == doorID }) { return (c, d) }
        }
        return nil
    }
}

// MARK: - Networking

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

// AES-256 ECB, key = token zero-padded to 32 bytes
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

enum DoorAPI {
    struct Reply { let statuses: [Int: Bool]; let token: String }

    static func request(_ c: Controller, query: String = "") async -> Reply? {
        guard c.configured,
              let url = URL(string: c.baseURL + "/" + (query.isEmpty ? "" : "?" + query)) else { return nil }
        var req = URLRequest(url: url)
        req.timeoutInterval = 4
        req.cachePolicy = .reloadIgnoringLocalCacheData
        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let parser = ReplyParser()
            let xml = XMLParser(data: data)
            xml.delegate = parser
            guard xml.parse() else { return nil }
            return Reply(statuses: parser.statuses, token: parser.token)
        } catch { return nil }
    }

    /// Fires the door's relay (fetches a fresh challenge token first).
    static func trigger(_ c: Controller, _ door: Door) async -> Bool {
        guard let relay = door.relayNumber,
              let fresh = await request(c), !fresh.token.isEmpty else { return false }
        let hex = encryptPassword(c.password, token: fresh.token)
        return await request(c, query: "relayPin=\(relay)&password=\(hex)") != nil
    }
}

// MARK: - Store

@MainActor
final class DoorStore: ObservableObject {
    @Published var controllers: [Controller] { didSet { ConfigStore.save(controllers) } }
    @Published var refreshSecs: Int { didSet { UserDefaults.standard.set(refreshSecs, forKey: "refreshSecs") } }
    @Published var confirmActions: Bool { didSet { UserDefaults.standard.set(confirmActions, forKey: "confirm") } }

    @Published var open: [UUID: [Int: Bool]] = [:]
    @Published var online: [UUID: Bool] = [:]
    @Published var busy: Set<UUID> = []
    @Published var refreshing = false
    @Published var lastUpdate: Date?
    @Published var message: String?

    init() {
        let d = UserDefaults.standard
        controllers = ConfigStore.load()
        refreshSecs = d.object(forKey: "refreshSecs") as? Int ?? 2
        confirmActions = d.object(forKey: "confirm") as? Bool ?? true
    }

    func isOpen(_ c: Controller, _ d: Door) -> Bool? {
        guard online[c.id] == true, let sid = d.statusId else { return nil }
        return open[c.id]?[sid]
    }

    func refresh() async {
        refreshing = true
        let list = controllers.filter { $0.configured }
        await withTaskGroup(of: (UUID, DoorAPI.Reply?).self) { group in
            for c in list { group.addTask { (c.id, await DoorAPI.request(c)) } }
            for await (id, reply) in group {
                if let reply { open[id] = reply.statuses; online[id] = true } else { online[id] = false }
            }
        }
        lastUpdate = Date()
        refreshing = false
    }

    func toggle(_ c: Controller, _ d: Door) async {
        busy.insert(d.id)
        defer { busy.remove(d.id) }
        if await DoorAPI.trigger(c, d) {
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } else {
            message = "Couldn't reach \(c.name)."
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
        try? await Task.sleep(nanoseconds: 1_500_000_000)
        await refresh()
    }

    func settingsClosed() {
        MillerDoorShortcuts.updateAppShortcutParameters()
        Task { await refresh() }
    }
}

// MARK: - Siri / Shortcuts (App Intents)

struct DoorEntity: AppEntity {
    static var typeDisplayRepresentation: TypeDisplayRepresentation = "Door"
    static var defaultQuery = DoorQuery()

    var id: String
    var name: String
    var displayRepresentation: DisplayRepresentation { DisplayRepresentation(title: "\(name)") }
}

struct DoorQuery: EntityQuery {
    func entities(for identifiers: [String]) async throws -> [DoorEntity] {
        all().filter { identifiers.contains($0.id) }
    }
    func suggestedEntities() async throws -> [DoorEntity] { all() }

    private func all() -> [DoorEntity] {
        ConfigStore.load().flatMap { c in
            c.validDoors.map { DoorEntity(id: $0.id.uuidString, name: $0.name) }
        }
    }
}

enum SiriActions {
    static func set(_ e: DoorEntity, open want: Bool) async -> String {
        guard let (c, d) = ConfigStore.find(doorID: e.id) else { return "I couldn't find that door." }
        guard let sid = d.statusId,
              let reply = await DoorAPI.request(c),
              let isOpen = reply.statuses[sid] else { return "I can't reach \(c.name)." }
        if isOpen == want { return "\(d.name) is already \(want ? "open" : "closed")." }
        let ok = await DoorAPI.trigger(c, d)
        return ok ? "\(want ? "Opening" : "Closing") \(d.name)." : "That didn't work."
    }

    static func summary() async -> String {
        var openNames: [String] = []
        var unreachable: [String] = []
        for c in ConfigStore.load() where c.configured {
            guard let reply = await DoorAPI.request(c) else { unreachable.append(c.name); continue }
            for d in c.validDoors {
                if let sid = d.statusId, reply.statuses[sid] == true { openNames.append(d.name) }
            }
        }
        var parts: [String] = []
        parts.append(openNames.isEmpty ? "All doors are closed." : "Open: \(openNames.joined(separator: ", ")).")
        if !unreachable.isEmpty { parts.append("Can't reach \(unreachable.joined(separator: ", ")).") }
        return parts.joined(separator: " ")
    }
}

struct OpenDoorIntent: AppIntent {
    static var title: LocalizedStringResource = "Open Door"
    static var description = IntentDescription("Opens a door if it is currently closed.")
    @Parameter(title: "Door") var door: DoorEntity
    static var parameterSummary: some ParameterSummary { Summary("Open \(\.$door)") }

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let msg = await SiriActions.set(door, open: true)
        return .result(dialog: "\(msg)")
    }
}

struct CloseDoorIntent: AppIntent {
    static var title: LocalizedStringResource = "Close Door"
    static var description = IntentDescription("Closes a door if it is currently open.")
    @Parameter(title: "Door") var door: DoorEntity
    static var parameterSummary: some ParameterSummary { Summary("Close \(\.$door)") }

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let msg = await SiriActions.set(door, open: false)
        return .result(dialog: "\(msg)")
    }
}

struct RefreshStatusIntent: AppIntent {
    static var title: LocalizedStringResource = "Refresh Door Status"
    static var description = IntentDescription("Checks every door on every controller.")

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let msg = await SiriActions.summary()
        return .result(dialog: "\(msg)")
    }
}

struct MillerDoorShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: OpenDoorIntent(),
                    phrases: ["Open \(\.$door) with \(.applicationName)",
                              "Open a door with \(.applicationName)"],
                    shortTitle: "Open Door", systemImageName: "door.left.hand.open")
        AppShortcut(intent: CloseDoorIntent(),
                    phrases: ["Close \(\.$door) with \(.applicationName)",
                              "Close a door with \(.applicationName)"],
                    shortTitle: "Close Door", systemImageName: "door.left.hand.closed")
        AppShortcut(intent: RefreshStatusIntent(),
                    phrases: ["Refresh door status in \(.applicationName)",
                              "Check my doors with \(.applicationName)"],
                    shortTitle: "Refresh Status", systemImageName: "arrow.clockwise")
    }
}

// MARK: - App

let gold = Color(red: 0.83, green: 0.69, blue: 0.35)

@main
struct MillerDoorApp: App {
    var body: some Scene {
        WindowGroup { ContentView().preferredColorScheme(.dark).tint(gold) }
    }
}

struct Pending: Identifiable {
    let controller: Controller
    let door: Door
    var id: UUID { door.id }
}

struct ContentView: View {
    @StateObject private var store = DoorStore()
    @State private var pending: Pending?
    @State private var showSettings = false
    @State private var availH: CGFloat = 600

    private var shown: [Controller] { store.controllers.filter { $0.configured && !$0.validDoors.isEmpty } }
    private var allDoors: [(Controller, Door)] { shown.flatMap { c in c.validDoors.map { (c, $0) } } }
    private var openCount: Int { allDoors.filter { store.isOpen($0.0, $0.1) == true }.count }
    private var anyOnline: Bool { shown.contains { store.online[$0.id] == true } }

    var body: some View {
        NavigationStack {
            ZStack {
                LinearGradient(colors: [Color(red: 0.04, green: 0.08, blue: 0.18),
                                        openCount > 0 ? Color(red: 0.28, green: 0.08, blue: 0.10)
                                                      : Color(red: 0.07, green: 0.15, blue: 0.32)],
                               startPoint: .top, endPoint: .bottom)
                    .ignoresSafeArea()
                    .animation(.easeInOut(duration: 0.8), value: openCount)

                ScrollView {
                    VStack(spacing: 16) {
                        if shown.isEmpty { emptyState } else {
                            header
                            ForEach(shown) { c in group(c) }
                            refreshButton
                        }
                    }
                    .padding()
                }
                .refreshable { await store.refresh() }
                .background(GeometryReader { g in
                    Color.clear
                        .onAppear { availH = g.size.height }
                        .onChange(of: g.size.height) { availH = $0 }
                })
                .alert(pending.map { "\(store.isOpen($0.controller, $0.door) == true ? "Close" : "Open") \($0.door.name)?" } ?? "",
                       isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } }),
                       presenting: pending) { p in
                    Button(store.isOpen(p.controller, p.door) == true ? "Close" : "Open") {
                        UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
                        Task { await store.toggle(p.controller, p.door) }
                    }
                    Button("Cancel", role: .cancel) {}
                } message: { p in
                    Text(p.controller.name)
                }
            }
            .navigationTitle("MillerDoor")
            .toolbar { Button { showSettings = true } label: { Image(systemName: "gearshape.fill") } }
            .sheet(isPresented: $showSettings, onDismiss: { store.settingsClosed() }) { SettingsView(store: store) }
            .alert("Oops", isPresented: Binding(get: { store.message != nil }, set: { if !$0 { store.message = nil } })) {
                Button("OK") {}
            } message: { Text(store.message ?? "") }
        }
        .task {
            if store.controllers.isEmpty { showSettings = true }
            await store.refresh()
            while !Task.isCancelled {
                let secs = store.refreshSecs
                try? await Task.sleep(nanoseconds: UInt64(max(secs, 1)) * 1_000_000_000)
                if secs > 0 && !showSettings { await store.refresh() }
            }
        }
    }

    /// Sizes the door boxes so every door fits on screen at once.
    private var cardHeight: CGFloat {
        let g = CGFloat(shown.count)
        let rows = CGFloat(shown.reduce(0) { $0 + ($1.validDoors.count + 1) / 2 })
        let overhead: CGFloat = 32 + 30 + 56 + (g + 1) * 16 + g * 28 + max(rows - g, 0) * 12 + 12
        return min(150, max(64, (availH - overhead) / max(rows, 1)))
    }

    private func tap(_ c: Controller, _ d: Door) {
        if store.confirmActions { pending = Pending(controller: c, door: d) }
        else {
            UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
            Task { await store.toggle(c, d) }
        }
    }

    private func group(_ c: Controller) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Circle().fill(store.online[c.id] == true ? .green : .gray).frame(width: 7, height: 7)
                Text(c.name.uppercased())
                    .font(.caption.weight(.semibold)).tracking(1.4).foregroundStyle(.secondary)
                Spacer()
                if let url = URL(string: c.baseURL + "/config") {
                    Link(destination: url) { Image(systemName: "safari").font(.caption).foregroundStyle(.secondary) }
                }
            }
            .padding(.horizontal, 4)
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible())], spacing: 12) {
                ForEach(c.validDoors) { d in
                    DoorCard(door: d, isOpen: store.isOpen(c, d), busy: store.busy.contains(d.id), height: cardHeight) { tap(c, d) }
                }
            }
        }
    }

    private var refreshButton: some View {
        VStack(spacing: 6) {
            Button { Task { await store.refresh() } } label: {
                HStack(spacing: 6) {
                    ZStack {
                        Image(systemName: "arrow.clockwise").opacity(store.refreshing ? 0 : 1)
                        ProgressView().controlSize(.small).opacity(store.refreshing ? 1 : 0)
                    }
                    .frame(width: 16, height: 16)
                    Text("Refresh").font(.subheadline.weight(.semibold))
                }
                .frame(width: 120, height: 34)
            }
            .buttonStyle(.borderedProminent).foregroundStyle(.black)
            Text(store.lastUpdate.map { "Updated \($0.formatted(date: .omitted, time: .standard))" } ?? " ")
                .font(.caption).monospacedDigit().foregroundStyle(.secondary)
                .frame(height: 14)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "door.left.hand.closed").font(.system(size: 54)).foregroundStyle(gold)
            Text("Set up MillerDoor").font(.title2.bold())
            Text("Add a controller (IP, port, password) and its doors.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button("Open Settings") { showSettings = true }.buttonStyle(.borderedProminent).foregroundStyle(.black)
        }.padding(.top, 80)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Circle().fill(!anyOnline ? .gray : (openCount > 0 ? .red : .green)).frame(width: 12, height: 12)
                .shadow(color: !anyOnline ? .clear : (openCount > 0 ? .red : .green), radius: 6)
            Text(!anyOnline ? "Offline" : (openCount > 0 ? "\(openCount) open" : "All secure"))
                .font(.title3.weight(.semibold))
            Spacer()
        }.padding(.horizontal, 4)
    }
}

struct StatusLabel: View {
    let isOpen: Bool?
    @State private var dim = false

    private var color: Color { isOpen == nil ? .gray : (isOpen! ? .red : .green) }

    var body: some View {
        Text(isOpen == nil ? "Unknown" : (isOpen! ? "OPEN" : "Closed"))
            .font(isOpen == true ? .title3.weight(.heavy) : .subheadline.weight(.bold))
            .foregroundStyle(color)
            .opacity(isOpen == true && dim ? 0.15 : 1)
            .onAppear { update() }
            .onChange(of: isOpen) { _ in update() }
    }

    private func update() {
        if isOpen == true {
            withAnimation(.easeInOut(duration: 0.6).repeatForever(autoreverses: true)) { dim = true }
        } else {
            withAnimation(.linear(duration: 0.01)) { dim = false }
        }
    }
}

struct DoorCard: View {
    let door: Door
    let isOpen: Bool?
    let busy: Bool
    let height: CGFloat
    let action: () -> Void
    private var color: Color { isOpen == nil ? .gray : (isOpen! ? .red : .green) }
    private var icon: String { isOpen == true ? "door.left.hand.open" : "door.left.hand.closed" }

    var body: some View {
        Button(action: action) {
            Group {
                if height < 100 {
                    HStack(spacing: 10) {
                        Image(systemName: icon).font(.title3).foregroundStyle(color)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(door.name).font(.subheadline.weight(.semibold)).foregroundStyle(.primary).lineLimit(1)
                            StatusLabel(isOpen: isOpen)
                        }
                        Spacer(minLength: 0)
                        if busy { ProgressView() }
                    }
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: icon).font(.title2).foregroundStyle(color)
                            Spacer()
                            if busy { ProgressView() }
                        }
                        Spacer(minLength: 0)
                        Text(door.name).font(.headline).foregroundStyle(.primary).lineLimit(1)
                        StatusLabel(isOpen: isOpen)
                        if height >= 130 {
                            Text(isOpen == true ? "Tap to close" : "Tap to open")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
            .padding(height < 100 ? 12 : 14)
            .frame(height: height)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).stroke(color.opacity(0.6), lineWidth: 1.5))
            .shadow(color: color.opacity(0.3), radius: 10, y: 3)
        }
        .buttonStyle(.plain)
        .disabled(busy)
    }
}

// MARK: - Settings

struct SettingsView: View {
    @ObservedObject var store: DoorStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section(header: Text("General"),
                        footer: Text("Set refresh to 0 to update only when you tap Refresh.")) {
                    Stepper(value: $store.refreshSecs, in: 0...300) {
                        HStack {
                            Text("Refresh every"); Spacer()
                            Text(store.refreshSecs == 0 ? "Manual only" : "\(store.refreshSecs) sec")
                                .foregroundStyle(.secondary)
                        }
                    }
                    Toggle("Confirm before open/close", isOn: $store.confirmActions)
                }

                Section(header: Text("Controllers"),
                        footer: Text("Add one controller per Arduino. Doors from all of them show on the main screen, grouped by controller name.")) {
                    ForEach($store.controllers) { $c in
                        NavigationLink {
                            ControllerEditor(controller: $c, store: store)
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.name).font(.headline)
                                Text(c.host.isEmpty ? "Not set up" : "\(c.host):\(c.port) · \(c.doors.count) door(s)")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .onDelete { store.controllers.remove(atOffsets: $0) }
                    .onMove { store.controllers.move(fromOffsets: $0, toOffset: $1) }

                    Button {
                        store.controllers.append(Controller(name: "Controller \(store.controllers.count + 1)"))
                    } label: { Label("Add controller", systemImage: "plus.circle.fill") }
                }

                Section("Siri") {
                    Text("Say things like “Open the south door with MillerDoor”, “Close the back door with MillerDoor”, or “Refresh door status in MillerDoor”. They also appear in the Shortcuts app.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { EditButton() }
                ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } }
            }
        }
    }
}

struct ControllerEditor: View {
    @Binding var controller: Controller
    @ObservedObject var store: DoorStore
    private let maxDoors = 7
    private var totalDoors: Int { store.controllers.reduce(0) { $0 + $1.doors.count } }

    var body: some View {
        Form {
            Section("Controller") {
                TextField("Name (e.g. Miller Barn)", text: $controller.name)
                TextField("IP address or hostname", text: $controller.host)
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                TextField("Port", text: $controller.port).keyboardType(.numberPad)
                SecureField("Password", text: $controller.password)
                HStack {
                    Text("Status"); Spacer()
                    switch store.online[controller.id] {
                    case .some(true):  Text("Connected").foregroundStyle(.green)
                    case .some(false): Text("Unreachable").foregroundStyle(.red)
                    case .none:        Text("Not checked").foregroundStyle(.secondary)
                    }
                }
                Button("Test connection") { Task { await store.refresh() } }
            }

            Section(header: Text("Doors"),
                    footer: Text("Status pin = Arduino input wired to the door sensor (e.g. 3 or A3). Relay pin = output that triggers the opener (e.g. 6).")) {
                ForEach($controller.doors) { $door in
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("Door name", text: $door.name).font(.headline)
                        HStack {
                            VStack(alignment: .leading) {
                                Text("Status pin").font(.caption).foregroundStyle(.secondary)
                                TextField("3", text: $door.statusPin)
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
                .onDelete { controller.doors.remove(atOffsets: $0) }
                .onMove { controller.doors.move(fromOffsets: $0, toOffset: $1) }

                if totalDoors >= maxDoors {
                    Text("Maximum of \(maxDoors) doors reached.").font(.footnote).foregroundStyle(.secondary)
                } else {
                    Button { controller.doors.append(Door()) } label: { Label("Add door", systemImage: "plus.circle.fill") }
                }
            }
        }
        .navigationTitle(controller.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { EditButton() }
    }
}
