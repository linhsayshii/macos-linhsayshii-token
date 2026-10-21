import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
import NIOWebSocket

/// Classic ASP.NET SignalR server on 127.0.0.1 (jQuery client protocol 1.5): `/signalr/negotiate|connect|start|send|poll|
/// reconnect|ping|abort`, WebSocket and long-polling transports. Host/Origin are checked by WebGuard like every bridge
/// (the vendor's CorsOptions.AllowAll is deliberately narrowed to the origin allowlist).
/// shortcut: serverSentEvents / foreverFrame are not served; the client falls back to long polling after its
/// TransportConnectTimeout if WebSocket fails. Verified only against the vendor page's bundled client code, not a live plugin.
public final class SignalRServer: @unchecked Sendable {
    public enum StartError: Error { case portInUse, failed(String) }

    private let port: Int
    private let store: OriginStore
    private let hub: SignalRHub
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?

    public init(port: Int = 16080, store: OriginStore, hub: SignalRHub) {
        self.port = port; self.store = store; self.hub = hub
    }

    public func start() async throws -> Int {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        let (store, hub) = (self.store, self.hub)
        let bound = PortBox(port)
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 64)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { ch in
                let upgrader = NIOWebSocketServerUpgrader(
                    maxFrameSize: 1 << 24,
                    shouldUpgrade: { channel, head in
                        let p = channel.eventLoop.makePromise(of: HTTPHeaders?.self)
                        let (host, origin) = (head.headers.first(name: "Host"), head.headers.first(name: "Origin"))
                        let q = Self.query(head.uri)
                        let path = Self.path(head.uri)
                        Task {
                            let allow = await store.allowlist()
                            switch WebGuard(port: bound.value).check(host: host, origin: origin, allowlist: allow) {
                            case .ok:
                                let known = await hub.isKnown(q["connectionToken"] ?? "")
                                p.succeed(path == "/signalr/connect" && q["transport"] == "webSockets" && known ? HTTPHeaders() : nil)
                            case .unknownOrigin(let o): await store.notePending(o); p.succeed(nil)
                            case .badHost: p.succeed(nil)
                            }
                        }
                        return p.futureResult
                    },
                    upgradePipelineHandler: { channel, head in
                        let token = Self.query(head.uri)["connectionToken"] ?? ""
                        return channel.pipeline.removeHandler(name: "http").flatMap {
                            channel.pipeline.addHandler(SocketHandler(token: token, hub: hub))
                        }
                    })
                let config: NIOHTTPServerUpgradeConfiguration = (upgraders: [upgrader], completionHandler: { _ in })
                return ch.pipeline.configureHTTPServerPipeline(withServerUpgrade: config)
                    .flatMap { ch.pipeline.addHandler(RequestHandler(port: bound, store: store, hub: hub), name: "http") }
            }
        do {
            let ch = try await bootstrap.bind(host: "127.0.0.1", port: port).get()
            self.channel = ch
            bound.value = ch.localAddress?.port ?? port
            return bound.value
        } catch let e as IOError where e.errnoCode == EADDRINUSE {
            throw StartError.portInUse
        } catch {
            throw StartError.failed("\(error)")
        }
    }

    public func stop() async {
        try? await channel?.close().get()
        try? await group?.shutdownGracefully()
    }

    static func path(_ uri: String) -> String {
        String(uri.split(separator: "?", omittingEmptySubsequences: false).first ?? "").lowercased()
    }

    static func query(_ uri: String) -> [String: String] {
        guard let r = uri.firstIndex(of: "?") else { return [:] }
        return formDecode(String(uri[uri.index(after: r)...]))
    }

    static func formDecode(_ s: String) -> [String: String] {
        var out: [String: String] = [:]
        for pair in s.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let dec = { (x: Substring) in String(x).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(x) }
            out[dec(kv[0])] = kv.count > 1 ? dec(kv[1]) : ""
        }
        return out
    }
}

private final class PortBox: @unchecked Sendable {
    private let lock = NSLock(); private var v: Int
    init(_ v: Int) { self.v = v }
    var value: Int { get { lock.lock(); defer { lock.unlock() }; return v } set { lock.lock(); v = newValue; lock.unlock() } }
}

private final class RequestHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let port: PortBox
    let store: OriginStore
    let hub: SignalRHub
    private var head: HTTPRequestHead?
    private var body = ByteBuffer()

    init(port: PortBox, store: OriginStore, hub: SignalRHub) { self.port = port; self.store = store; self.hub = hub }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h): head = h; body.clear()
        case .body(var b): body.writeBuffer(&b)
        case .end:
            guard let h = head else { return }
            let bodyText = String(decoding: body.readableBytesView, as: UTF8.self)
            let (channel, loop, store, hub, port) = (context.channel, context.eventLoop, self.store, self.hub, self.port.value)
            Task {
                let origin = h.headers.first(name: "Origin")
                let allow = await store.allowlist()
                let guardian = WebGuard(port: port)
                switch guardian.check(host: h.headers.first(name: "Host"), origin: origin, allowlist: allow) {
                case .badHost:
                    Self.write(channel, loop, .forbidden, [:], "{}")
                case .unknownOrigin(let o):
                    await store.notePending(o)
                    Self.write(channel, loop, h.method == .OPTIONS ? .ok : .forbidden, [:], h.method == .OPTIONS ? "" : "{}")
                case .ok:
                    var headers = guardian.corsHeaders(origin: origin, allowlist: allow)
                    if !headers.isEmpty { headers["Access-Control-Allow-Credentials"] = "true" }   // jQuery SignalR sends withCredentials
                    if h.method == .OPTIONS {
                        var p = guardian.preflightHeaders(origin: origin, allowlist: allow,
                                                          requestedHeaders: h.headers.first(name: "Access-Control-Request-Headers"))
                        if !p.isEmpty { p["Access-Control-Allow-Credentials"] = "true" }
                        Self.write(channel, loop, .ok, p, "")
                        return
                    }
                    let (status, text) = await Self.route(h, body: bodyText, origin: origin ?? "local", hub: hub)
                    headers["Content-Type"] = "application/json; charset=UTF-8"
                    headers["Cache-Control"] = "no-cache"
                    Self.write(channel, loop, status, headers, text)
                }
            }
        }
    }

    static func route(_ h: HTTPRequestHead, body: String, origin: String, hub: SignalRHub) async -> (HTTPResponseStatus, String) {
        let path = SignalRServer.path(h.uri), q = SignalRServer.query(h.uri)
        let token = q["connectionToken"] ?? ""
        func json(_ o: Any) -> String { SignalRHub.json(o) }
        switch path {
        case "/signalr/negotiate":
            return (.ok, await hub.negotiate(origin: origin, clientProtocol: q["clientProtocol"]))
        case "/signalr/connect" where q["transport"] == "longPolling":
            guard let f = await hub.initFrame(token) else { return (.badRequest, "{}") }
            return (.ok, f)
        case "/signalr/poll", "/signalr/reconnect":
            guard let f = await hub.poll(token: token) else { return (.badRequest, "{}") }
            return (.ok, f)
        case "/signalr/start":
            return await hub.isKnown(token) ? (.ok, json(["Response": "started"])) : (.badRequest, "{}")
        case "/signalr/ping":
            return (.ok, json(["Response": "pong"]))
        case "/signalr/abort":
            await hub.abort(token); return (.ok, "{}")
        case "/signalr/send":
            let data = h.method == .POST ? SignalRServer.formDecode(body)["data"] : q["data"]
            guard await hub.isKnown(token), let data, let r = await hub.receive(token: token, data: data) else { return (.badRequest, "{}") }
            return (.ok, r)
        default:
            return (.notFound, "{}")
        }
    }

    static func write(_ channel: Channel, _ loop: EventLoop, _ status: HTTPResponseStatus, _ headers: [String: String], _ text: String) {
        loop.execute {
            var h = HTTPHeaders()
            for (k, v) in headers { h.add(name: k, value: v) }
            h.add(name: "Content-Length", value: "\(text.utf8.count)")
            channel.write(NIOAny(HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1, status: status, headers: h))), promise: nil)
            var buf = channel.allocator.buffer(capacity: text.utf8.count)
            buf.writeString(text)
            channel.write(NIOAny(HTTPServerResponsePart.body(.byteBuffer(buf))), promise: nil)
            channel.writeAndFlush(NIOAny(HTTPServerResponsePart.end(nil)), promise: nil)
        }
    }
}

/// One WebSocket connection: sends the init frame and keep-alives, forwards hub pushes, answers hub invocations.
private final class SocketHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame

    let token: String
    let hub: SignalRHub
    private var partial = ByteBuffer()
    private var keepAlive: RepeatedTask?

    init(token: String, hub: SignalRHub) { self.token = token; self.hub = hub }

    private static func send(_ channel: Channel, _ text: String) {
        channel.eventLoop.execute {
            var buf = channel.allocator.buffer(capacity: text.utf8.count)
            buf.writeString(text)
            channel.writeAndFlush(WebSocketFrame(fin: true, opcode: .text, data: buf), promise: nil)
        }
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let (channel, token, hub) = (context.channel, self.token, self.hub)
        Task {
            if let f = await hub.initFrame(token) { Self.send(channel, f) }
            await hub.attach(token: token) { Self.send(channel, $0) }
        }
        // SignalR KeepAlive = DisconnectTimeout / 3; the client reconnects if two go missing.
        keepAlive = context.eventLoop.scheduleRepeatedTask(initialDelay: .seconds(10), delay: .seconds(10)) { _ in
            Self.send(channel, "{}")
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        keepAlive?.cancel()
        let (token, hub) = (self.token, self.hub)
        Task { await hub.detach(token: token) }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var frame = unwrapInboundIn(data)
        switch frame.opcode {
        case .text, .continuation:
            var chunk = frame.unmaskedData; partial.writeBuffer(&chunk)
            guard frame.fin else { return }
            let text = partial.readString(length: partial.readableBytes) ?? ""
            partial.clear()
            let (channel, token, hub) = (context.channel, self.token, self.hub)
            Task {
                if let reply = await hub.receive(token: token, data: text) { Self.send(channel, reply) }
            }
        case .ping:
            context.writeAndFlush(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)), promise: nil)
        case .connectionClose:
            context.close(promise: nil)
        default: break
        }
    }
}
