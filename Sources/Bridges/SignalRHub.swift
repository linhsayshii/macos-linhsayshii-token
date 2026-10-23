import Foundation
import Security

/// Transport-independent state of a classic ASP.NET SignalR 1.x/2.x hub endpoint: connection tokens, server→client
/// push buffering for long polling, and hub method dispatch. Transports (WebSocket, long poll) live in SignalRServer.
public struct SignalRCall: Sendable {
    public let origin: String
    let hub: SignalRHub
    let token: String
    /// Server→client callback (`Clients.Caller.<method>(args)`), delivered on whatever transport the connection uses.
    public func push(_ method: String, _ args: [String]) async {
        await hub.push(token: token, hub: "HandlerHub", method: method, args: args)
    }
    public func start(_ operation: @escaping @Sendable () async -> Void) async {
        await hub.start(token: token, operation: operation)
    }
}

public enum SignalRInvokeError: Error { case message(String) }

public actor SignalRHub {
    public typealias Handler = @Sendable (_ method: String, _ args: [String], _ call: SignalRCall) async throws -> String?

    struct Connection {
        var id: String
        var origin: String
        var counter = 0
        var buffer: [String] = []
        var sink: (@Sendable (String) -> Void)?
        var operations: [UUID: Task<Void, Never>] = [:]
    }

    public static let protocolVersion = "1.5"
    private var connections: [String: Connection] = [:]
    private let handler: Handler
    private let hubName: String

    public init(hubName: String = "handlerHub", handler: @escaping Handler) {
        self.hubName = hubName.lowercased(); self.handler = handler
    }

    // MARK: negotiate / lifecycle

    /// The jQuery client rejects the connection unless ProtocolVersion equals the clientProtocol it sent (the vendor page sends 2.1).
    public func negotiate(origin: String, clientProtocol: String? = nil) -> String {
        let token = Self.random(32), id = Self.random(16)
        connections[token] = Connection(id: id, origin: origin)
        return Self.json(["Url": "/signalr", "ConnectionToken": token, "ConnectionId": id,
                "KeepAliveTimeout": 20.0, "DisconnectTimeout": 30.0, "ConnectionTimeout": 110.0,
                "TryWebSockets": true, "ProtocolVersion": clientProtocol ?? Self.protocolVersion,
                "TransportConnectTimeout": 5.0, "LongPollDelay": 0.0] as [String: Any])
    }

    public func isKnown(_ token: String, origin: String? = nil) -> Bool {
        guard let connection = connections[token] else { return false }
        return origin == nil || origin == connection.origin
    }
    public func abort(_ token: String) {
        for task in connections[token]?.operations.values ?? [:].values { task.cancel() }
        connections[token] = nil
    }
    func abortAll() {
        for token in Array(connections.keys) { abort(token) }
    }
    func start(token: String, operation: @escaping @Sendable () async -> Void) {
        guard connections[token] != nil else { return }
        let id = UUID()
        connections[token]?.operations[id] = Task {
            await operation()
            self.finished(token: token, id: id)
        }
    }
    private func finished(token: String, id: UUID) { connections[token]?.operations[id] = nil }

    /// Initial frame of every transport: `S:1` tells the client the connection is initialized.
    public func initFrame(_ token: String) -> String? {
        guard var c = connections[token] else { return nil }
        let f = frame(&c, messages: [], initialized: true)
        connections[token] = c
        return f
    }

    /// WebSocket: route pushes straight to the socket. Buffered messages are flushed first.
    public func attach(token: String, sink: @escaping @Sendable (String) -> Void) {
        guard var c = connections[token] else { return }
        for m in c.buffer { sink(m) }
        c.buffer.removeAll(); c.sink = sink
        connections[token] = c
    }

    public func detach(token: String) { connections[token]?.sink = nil }

    // MARK: server -> client

    func push(token: String, hub: String, method: String, args: [String]) {
        guard var c = connections[token] else { return }
        let msg: [String: Any] = ["H": hub, "M": method, "A": args]
        let f = frame(&c, messages: [msg], initialized: false)
        if let sink = c.sink { sink(f) } else { c.buffer.append(f) }
        connections[token] = c
    }

    /// Long poll: waits up to `seconds` for buffered messages; an empty frame doubles as keep-alive.
    public func poll(token: String, seconds: Double = 20) async -> String? {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            guard var c = connections[token] else { return nil }
            if !c.buffer.isEmpty {
                let msgs = c.buffer.flatMap { Self.messages(in: $0) }
                c.buffer.removeAll()
                let f = frame(&c, messages: msgs, initialized: false)
                connections[token] = c
                return f
            }
            try? await Task.sleep(nanoseconds: 50_000_000)   // shortcut: sleep-poll instead of continuations; loopback traffic is tiny
        }
        guard var c = connections[token] else { return nil }
        let f = frame(&c, messages: [], initialized: false)
        connections[token] = c
        return f
    }

    // MARK: client -> server

    /// `data` is the transport payload `{"H":hub,"M":method,"A":[args],"I":invocationId}`.
    /// Returns the `{"I":…,"R":…}` / `{"I":…,"E":…}` reply, or nil if the payload is not a hub invocation.
    public func receive(token: String, data: String) async -> String? {
        guard let c = connections[token],
              let obj = (try? JSONSerialization.jsonObject(with: Data(data.utf8))) as? [String: Any],
              let method = obj["M"] as? String else { return nil }
        let id = (obj["I"].map { "\($0)" }) ?? ""
        guard (obj["H"] as? String)?.lowercased() == hubName else {
            return Self.json(["I": id, "E": "Hub not found"])
        }
        let call = SignalRCall(origin: c.origin, hub: self, token: token)
        do {
            let args = ((obj["A"] as? [Any]) ?? []).map { ($0 as? String) ?? Self.json($0) }
            let r = try await handler(method, args, call)
            var reply: [String: Any] = ["I": id]
            if let r { reply["R"] = r }
            return Self.json(reply)
        } catch SignalRInvokeError.message(let m) {
            return Self.json(["I": id, "E": m])
        } catch {
            return Self.json(["I": id, "E": "\(error)"])
        }
    }

    // MARK: helpers

    private func frame(_ c: inout Connection, messages: [[String: Any]], initialized: Bool) -> String {
        c.counter += 1
        var o: [String: Any] = ["C": "d-\(c.id.prefix(8).uppercased()),\(String(c.counter, radix: 16, uppercase: true))", "M": messages]
        if initialized { o["S"] = 1 }
        return Self.json(o)
    }

    private static func messages(in frame: String) -> [[String: Any]] {
        ((try? JSONSerialization.jsonObject(with: Data(frame.utf8))) as? [String: Any])?["M"] as? [[String: Any]] ?? []
    }

    static func random(_ n: Int) -> String {
        var b = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return b.map { String(format: "%02x", $0) }.joined()
    }

    static func json(_ o: Any) -> String {
        String(decoding: (try? JSONSerialization.data(withJSONObject: o, options: [.withoutEscapingSlashes])) ?? Data("{}".utf8), as: UTF8.self)
    }
}
