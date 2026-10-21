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
    private let store: OriginStore
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?

    public init(bridge: CTSignBridge, port: Int = 32001, store: OriginStore) {
        self.bridge = bridge
        self.port = port
        self.store = store
    }

    public func start() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        let bridge = self.bridge
        let port = self.port
        let store = self.store
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 64)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { ch in
                ch.pipeline.configureHTTPServerPipeline().flatMap {
                    ch.pipeline.addHandler(RequestHandler(bridge: bridge, port: port, store: store))
                }
            }
        do {
            self.channel = try await bootstrap.bind(host: "127.0.0.1", port: port).get()
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
}

private final class RequestHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let bridge: CTSignBridge
    let port: Int
    let store: OriginStore

    private var head: HTTPRequestHead?
    private var body = ByteBuffer()

    init(bridge: CTSignBridge, port: Int, store: OriginStore) {
        self.bridge = bridge; self.port = port; self.store = store
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h):
            head = h
            body.clear()
        case .body(var b):
            body.writeBuffer(&b)
        case .end:
            guard let h = head else { return }
            let bodyData = Data(body.readableBytesView)
            let origin = h.headers.first(name: "Origin")
            let host = h.headers.first(name: "Host")
            let requestedHeaders = h.headers.first(name: "Access-Control-Request-Headers")
            let loop = context.eventLoop
            let channel = context.channel
            let method = h.method
            let path = String(h.uri.split(separator: "?").first ?? "")
            let guardian = WebGuard(port: port)
            Task {
                let allow = await self.store.allowlist()
                switch guardian.check(host: host, origin: origin, allowlist: allow) {
                case .badHost:   // DNS-rebinding guard
                    Self.write(channel: channel, loop: loop, status: .forbidden, headers: [:], body: Data("{}".utf8))
                case .unknownOrigin(let o):
                    await self.store.notePending(o)
                    // Preflight gets no CORS headers, so the browser blocks the real request.
                    let st: HTTPResponseStatus = method == .OPTIONS ? .ok : .forbidden
                    Self.write(channel: channel, loop: loop, status: st, headers: [:], body: method == .OPTIONS ? Data() : Data("{}".utf8))
                case .ok:
                    var headers = guardian.corsHeaders(origin: origin, allowlist: allow)
                    if method == .OPTIONS {
                        headers = guardian.preflightHeaders(origin: origin, allowlist: allow, requestedHeaders: requestedHeaders)
                        Self.write(channel: channel, loop: loop, status: .ok, headers: headers, body: Data())
                        return
                    }
                    let (status, json) = await self.bridge.handle(method: method.rawValue, path: path, body: bodyData, origin: origin ?? "local")
                    headers["Content-Type"] = "application/json"
                    Self.write(channel: channel, loop: loop, status: HTTPResponseStatus(statusCode: status),
                               headers: headers, body: json)
                }
            }
        }
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
