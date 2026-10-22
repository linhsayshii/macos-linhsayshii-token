import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
import NIOWebSocket

/// WebSocket server on 127.0.0.1. One text frame in →
/// `handler(text, origin)` → one text frame out. Host/Origin are checked at the
/// handshake by WebGuard; a failing handshake gets a plain 403.
public final class WSServer: @unchecked Sendable {
    public enum StartError: Error { case portInUse, failed(String) }
    public typealias Handler = @Sendable (_ text: String, _ origin: String) async -> String

    private let ports: [Int]
    private let pathPrefix: String
    private let store: OriginStore
    private let handler: Handler
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?

    /// `ports` are tried in order (primary, fallback); the first free one wins.
    public init(ports: [Int], pathPrefix: String, store: OriginStore, handler: @escaping Handler) {
        self.ports = ports; self.pathPrefix = pathPrefix; self.store = store; self.handler = handler
    }

    public func start() async throws -> Int {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        for port in ports {
            let bound = PortBox(port)   // Host check must use the real port (matters when port is 0)
            let (pathPrefix, store, handler) = (self.pathPrefix, self.store, self.handler)
            let bootstrap = ServerBootstrap(group: group)
                .serverChannelOption(ChannelOptions.backlog, value: 64)
                .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { ch in
                    let upgrader = NIOWebSocketServerUpgrader(
                        maxFrameSize: 1 << 24,
                        shouldUpgrade: { channel, head in
                            let p = channel.eventLoop.makePromise(of: HTTPHeaders?.self)
                            let (host, origin) = (head.headers.first(name: "Host"), head.headers.first(name: "Origin"))
                            // "/plugin" matches "/plugin", "/plugin/" and "/plugin/x" (the DVC portal opens plain /plugin).
                            let path = String(head.uri.split(separator: "?", omittingEmptySubsequences: false).first ?? "")
                            let base = pathPrefix.hasSuffix("/") ? String(pathPrefix.dropLast()) : pathPrefix
                            let ok = base.isEmpty ? path.hasPrefix("/") : (path == base || path.hasPrefix(base + "/"))
                            Task {
                                let allow = await store.allowlist()
                                switch WebGuard(port: bound.value).check(host: host, origin: origin, allowlist: allow) {
                                case .ok where ok: p.succeed(HTTPHeaders())
                                case .unknownOrigin(let o): await store.notePending(o); p.succeed(nil)
                                default: p.succeed(nil)
                                }
                            }
                            return p.futureResult
                        },
                        upgradePipelineHandler: { channel, head in
                            let origin = head.headers.first(name: "Origin") ?? "local"
                            return channel.pipeline.removeHandler(name: "reject").flatMap {
                                channel.pipeline.addHandler(FrameHandler(origin: origin, handler: handler))
                            }
                        })
                    let config: NIOHTTPServerUpgradeConfiguration = (upgraders: [upgrader], completionHandler: { _ in })
                    return ch.pipeline.configureHTTPServerPipeline(withServerUpgrade: config)
                        .flatMap { ch.pipeline.addHandler(RejectHandler(), name: "reject") }
                }
            do {
                self.channel = try await bootstrap.bind(host: "127.0.0.1", port: port).get()
                bound.value = self.channel?.localAddress?.port ?? port
                return bound.value
            } catch let e as IOError where e.errnoCode == EADDRINUSE {
                continue
            } catch {
                try? await group.shutdownGracefully()
                throw StartError.failed("\(error)")
            }
        }
        try? await group.shutdownGracefully()
        throw StartError.portInUse
    }

    public func stop() async {
        try? await channel?.close().get()
        try? await group?.shutdownGracefully()
    }
}

private final class PortBox: @unchecked Sendable {
    private let lock = NSLock(); private var v: Int
    init(_ v: Int) { self.v = v }
    var value: Int { get { lock.lock(); defer { lock.unlock() }; return v } set { lock.lock(); v = newValue; lock.unlock() } }
}

/// Answers any request that did not upgrade (wrong path, host, origin) with 403.
private final class RejectHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard case .head = unwrapInboundIn(data) else { return }
        var h = HTTPHeaders(); h.add(name: "Content-Length", value: "0"); h.add(name: "Connection", value: "close")
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: .forbidden, headers: h))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in context.close(promise: nil) }
    }
}

private final class FrameHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame
    let origin: String
    let handler: WSServer.Handler
    private var partial = ByteBuffer()
    private var requests: [UUID: Task<Void, Never>] = [:]

    init(origin: String, handler: @escaping WSServer.Handler) { self.origin = origin; self.handler = handler }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var frame = unwrapInboundIn(data)
        switch frame.opcode {
        case .text, .continuation:
            var chunk = frame.unmaskedData
            guard partial.readableBytes + chunk.readableBytes <= 32 << 20 else { context.close(promise: nil); return }
            partial.writeBuffer(&chunk)
            guard frame.fin else { return }
            let text = partial.readString(length: partial.readableBytes) ?? ""
            partial.clear()
            let (channel, loop, origin, handler) = (context.channel, context.eventLoop, self.origin, self.handler)
            let id = UUID()
            requests[id] = Task {
                let reply = await handler(text, origin)
                loop.execute {
                    self.requests[id] = nil
                    guard channel.isActive else { return }
                    var buf = channel.allocator.buffer(capacity: reply.utf8.count)
                    buf.writeString(reply)
                    channel.writeAndFlush(WebSocketFrame(fin: true, opcode: .text, data: buf), promise: nil)
                }
            }
        case .ping:
            context.writeAndFlush(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)), promise: nil)
        case .connectionClose:
            context.close(promise: nil)
        default: break
        }
    }
    func channelInactive(context: ChannelHandlerContext) {
        for task in requests.values { task.cancel() }
        requests.removeAll()
        context.fireChannelInactive()
    }

}
