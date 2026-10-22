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
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?

    public init(bridge: CTSignBridge, port: Int = 32001, allowlist: OriginAllowlist) {
        self.bridge = bridge
        self.port = port
        self.allowlist = allowlist
    }

    public func start() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        let bridge = self.bridge
        let port = self.port
        let allowlist = self.allowlist
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 64)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { ch in
                ch.pipeline.configureHTTPServerPipeline().flatMap {
                    ch.pipeline.addHandler(RequestHandler(bridge: bridge, port: port, allowlist: allowlist))
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
    let allowlist: OriginAllowlist

    private var head: HTTPRequestHead?
    private var body = ByteBuffer()
    private var requests: [UUID: Task<Void, Never>] = [:]

    init(bridge: CTSignBridge, port: Int, allowlist: OriginAllowlist) {
        self.bridge = bridge; self.port = port; self.allowlist = allowlist
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
            let bodyData = Data(body.readableBytesView)
            let origin = h.headers.first(name: "Origin")
            let hostOK = isHostAllowed(h.headers.first(name: "Host"))
            let originOK = origin.map { allowlist.contains($0) } ?? true
            let loop = context.eventLoop
            let channel = context.channel

            // DNS-rebinding guard: reject a mismatched Host outright.
            guard hostOK && originOK else {
                Self.write(channel: channel, loop: loop, status: .forbidden,
                           headers: [:], body: Data("{}".utf8))
                return
            }

            // CORS preflight.
            if h.method == .OPTIONS {
                var headers: [String: String] = [:]
                if let origin, allowlist.contains(origin) {
                    headers["Access-Control-Allow-Origin"] = origin
                    headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                    headers["Access-Control-Allow-Headers"] = "Content-Type"
                    headers["Access-Control-Allow-Private-Network"] = "true"
                }
                Self.write(channel: channel, loop: loop, status: .ok, headers: headers, body: Data())
                return
            }

            let method = h.method.rawValue
            let path = String(h.uri.split(separator: "?").first ?? "")
            let id = UUID()
            requests[id] = Task {
                let (status, json) = await self.bridge.handle(method: method, path: path, body: bodyData, origin: origin ?? "local")
                var headers: [String: String] = ["Content-Type": "application/json"]
                if let origin, self.allowlist.contains(origin) {
                    headers["Access-Control-Allow-Origin"] = origin
                    headers["Access-Control-Allow-Private-Network"] = "true"
                }
                loop.execute { self.requests[id] = nil }
                guard !Task.isCancelled else { return }
                Self.write(channel: channel, loop: loop,
                           status: HTTPResponseStatus(statusCode: status), headers: headers, body: json)
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        for task in requests.values { task.cancel() }
        requests.removeAll()
        context.fireChannelInactive()
    }

    private func isHostAllowed(_ host: String?) -> Bool {
        guard let host else { return false }
        return host == "127.0.0.1:\(port)" || host == "localhost:\(port)"
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
