import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1

/// Binds a CTSignBridge on 127.0.0.1:<port>. Guards the Host header against DNS
/// rebinding and answers CORS preflight for allowlisted origins only.
public final class HTTPServer: @unchecked Sendable {
    public enum StartError: Error { case portInUse, failed(String) }

    private let bridge: CTSignBridge
    private let port: Int
    private let allowlist: OriginAllowlist
    private let store: OriginStore?
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?
    private var connections = ListenerConnections()

    public init(bridge: CTSignBridge, port: Int = 32001, allowlist: OriginAllowlist) {
        self.bridge = bridge
        self.port = port
        self.allowlist = allowlist
        self.store = nil
    }

    public init(bridge: CTSignBridge, port: Int = 32001, store: OriginStore) {
        self.bridge = bridge; self.port = port; self.store = store; self.allowlist = .defaults
    }

    public func start() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        let connections = ListenerConnections()
        self.connections = connections
        let bridge = self.bridge
        let port = self.port
        let allowlist = self.allowlist
        let store = self.store
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 64)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { ch in
                connections.add(ch)
                return ch.pipeline.configureHTTPServerPipeline().flatMap {
                    ch.pipeline.addHandler(RequestHandler(bridge: bridge, port: port, allowlist: allowlist, store: store))
                }
            }
        do {
            self.channel = try await bootstrap.bind(host: "127.0.0.1", port: port).get()
        } catch let e as IOError where e.errnoCode == EADDRINUSE {
            await stop()
            throw StartError.portInUse
        } catch {
            await stop()
            throw StartError.failed("\(error)")
        }
    }

    public func stop() async {
        let channel = self.channel, group = self.group
        self.channel = nil; self.group = nil
        try? await channel?.close().get()
        await connections.closeAll()
        try? await group?.shutdownGracefully()
    }
}

private final class RequestHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let bridge: CTSignBridge
    let port: Int
    let allowlist: OriginAllowlist
    let store: OriginStore?

    private var head: HTTPRequestHead?
    private var body = ByteBuffer()
    private var requests: [UUID: Task<Void, Never>] = [:]

    init(bridge: CTSignBridge, port: Int, allowlist: OriginAllowlist, store: OriginStore?) {
        self.bridge = bridge; self.port = port; self.allowlist = allowlist; self.store = store
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h):
            head = h
            body.clear()
        case .body(var b):
            guard body.readableBytes + b.readableBytes <= 32 << 20 else {
                context.close(promise: nil); return
            }
            body.writeBuffer(&b)
        case .end:
            guard let h = head else { return }
            head = nil
            let bytes = Data(body.readableBytesView)
            let channel = context.channel, loop = context.eventLoop, id = UUID()
            requests[id] = Task {
                defer { loop.execute { self.requests[id] = nil } }
                let allow = await self.store?.allowlist() ?? self.allowlist
                let origin = h.headers.first(name: "Origin")
                let guarder = WebGuard(port: self.port)
                switch guarder.check(host: h.headers.first(name: "Host"), origin: origin, allowlist: allow) {
                case .ok: break
                case .unknownOrigin(let origin):
                    await self.store?.notePending(origin)
                    Self.write(channel: channel, loop: loop, status: .forbidden, headers: [:], body: Data("{}".utf8))
                    return
                case .badHost:
                    Self.write(channel: channel, loop: loop, status: .forbidden, headers: [:], body: Data("{}".utf8))
                    return
                }
                if h.method == .OPTIONS {
                    let headers = guarder.preflightHeaders(origin: origin, allowlist: allow,
                        requestedHeaders: h.headers.first(name: "Access-Control-Request-Headers"))
                    Self.write(channel: channel, loop: loop, status: .ok, headers: headers, body: Data())
                    return
                }
                let path = String(h.uri.split(separator: "?").first ?? "")
                let (status, json) = await self.bridge.handle(method: h.method.rawValue, path: path, body: bytes, origin: origin ?? "local")
                var headers = guarder.corsHeaders(origin: origin, allowlist: allow)
                headers["Content-Type"] = "application/json"
                guard !Task.isCancelled else { return }
                Self.write(channel: channel, loop: loop, status: HTTPResponseStatus(statusCode: status), headers: headers, body: json)
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        for task in requests.values { task.cancel() }
        requests.removeAll()
        context.fireChannelInactive()
    }

    static func write(channel: Channel, loop: EventLoop, status: HTTPResponseStatus,
                      headers: [String: String], body: Data) {
        loop.execute {
            var h = HTTPHeaders()
            for (k, v) in headers { h.add(name: k, value: v) }
            h.add(name: "Content-Length", value: "\(body.count)")
            let head = HTTPResponseHead(version: .http1_1, status: status, headers: h)
            channel.write(NIOAny(HTTPServerResponsePart.head(head)), promise: nil)
            var buf = channel.allocator.buffer(capacity: body.count)
            buf.writeBytes(body)
            channel.write(NIOAny(HTTPServerResponsePart.body(.byteBuffer(buf))), promise: nil)
            channel.writeAndFlush(NIOAny(HTTPServerResponsePart.end(nil)), promise: nil)
        }
    }
}
