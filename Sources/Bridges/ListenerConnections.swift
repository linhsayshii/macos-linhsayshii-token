import Foundation
import NIOCore

/// Closing the listening socket alone leaves accepted HTTP/WebSocket clients alive.
/// Track them before pipeline setup, including clients accepted during shutdown.
final class ListenerConnections: @unchecked Sendable {
    private let lock = NSLock()
    private var channels: [ObjectIdentifier: Channel] = [:]
    private var stopping = false

    func add(_ channel: Channel) {
        let id = ObjectIdentifier(channel)
        let close = lock.withLock {
            if stopping { return true }
            channels[id] = channel
            return false
        }
        if close { channel.close(promise: nil); return }
        channel.closeFuture.whenComplete { [weak self] _ in
            guard let self else { return }
            _ = self.lock.withLock { self.channels.removeValue(forKey: id) }
        }
    }

    func closeAll() async {
        let active = lock.withLock {
            stopping = true
            let active = Array(channels.values)
            channels.removeAll()
            return active
        }
        for channel in active { try? await channel.close().get() }
    }
}
