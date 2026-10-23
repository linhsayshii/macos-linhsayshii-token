import Foundation
import SwiftUI
import Testing
import Core
import Bridges
@testable import App

@MainActor private struct ServicePrompt: SigningPromptPresenting {
    func present<Content: View>(title: String, content: Content, onCancel: @escaping () -> Void) {}
    func dismiss() {}
}

private actor ListenerProbe {
    var starts: [BridgeKind] = []
    var stops: [BridgeKind] = []
    var fail: BridgeKind?
    var gate: CheckedContinuation<Void, Never>?
    var paused = false
    func start(_ kind: BridgeKind) async throws {
        starts.append(kind)
        if paused { await withCheckedContinuation { gate = $0 } }
        if kind == fail { throw WSServer.StartError.portInUse }
    }
    func stop(_ kind: BridgeKind) { stops.append(kind) }
    func setFailure(_ kind: BridgeKind?) { fail = kind }
    func pause() { paused = true }
    func resume() { paused = false; gate?.resume(); gate = nil }
}

@MainActor private func serviceModel(_ directory: URL, probe: ListenerProbe) -> AppModel {
    AppModel(broker: TokenBroker(helperURL: URL(fileURLWithPath: "/nonexistent"),
        shimURL: URL(fileURLWithPath: "/nonexistent"), moduleDirs: []), promptWindow: ServicePrompt(),
        supportDirectory: directory, listenerFactory: { endpoint in
            BridgeListener(start: { try await probe.start(endpoint.kind) }, stop: { await probe.stop(endpoint.kind) })
        })
}
private func serviceDirectory() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent("services-\(UUID())") }

@Test @MainActor func serviceSwitchesGroupPortsPersistAndRespectDisabledStartup() async throws {
    let directory = serviceDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let probe = ListenerProbe(), model = serviceModel(directory, probe: probe)
    #expect(model.enabledServices == Set(BridgeService.allCases))
    model.setServiceEnabled(.esigner, false)
    model.setServiceEnabled(.vnpt, false)
    #expect(model.bridges.filter { [.esigner,.esignerAlternate,.vnpt,.vnptDVC].contains($0.id) }.allSatisfy { $0.status == .disabled })
    #expect(model.enabledBridges.map(\.id) == [.ctsign,.minvoice])
    let reopened = serviceModel(directory, probe: probe)
    #expect(reopened.enabledServices == [.ctsign,.minvoice])
    reopened.startBridgeServices(); await reopened.waitForServiceChanges()
    #expect(Set(await probe.starts) == [.ctsign,.minvoice])
    reopened.setServiceEnabled(.esigner, true)
    await reopened.waitForServiceChanges()
    #expect(reopened.bridges.filter { $0.id.service == .esigner }.allSatisfy { $0.status == .up })
    reopened.setServiceEnabled(.esigner, false)
    await reopened.waitForServiceChanges()
    #expect(Set(await probe.stops) == [.esigner,.esignerAlternate])
    #expect(reopened.bridges.filter { $0.id.service == .ctsign || $0.id.service == .minvoice }.allSatisfy { $0.status == .up })
    reopened.setServiceEnabled(.vnpt, true); await reopened.waitForServiceChanges()
    #expect(reopened.bridges.filter { $0.id.service == .vnpt }.allSatisfy { $0.status == .up })
    for service in BridgeService.allCases {
        reopened.setServiceEnabled(service, false); await reopened.waitForServiceChanges()
    }
    #expect(reopened.enabledBridges.isEmpty && reopened.bridges.allSatisfy { $0.status == .disabled })
    #expect(serviceModel(directory, probe: probe).enabledServices.isEmpty)
}

@Test @MainActor func serviceChangesCannotRaceStartupOrInterruptApprovalAndCanRecoverFromBusyPort() async throws {
    let directory = serviceDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let probe = ListenerProbe(), model = serviceModel(directory, probe: probe)
    for service in BridgeService.allCases where service != .esigner { model.setServiceEnabled(service, false) }
    await probe.pause()
    model.startBridgeServices()
    #expect(!model.canChangeServices)
    model.setServiceEnabled(.esigner, false)
    #expect(model.serviceEnabled(.esigner))
    for _ in 0..<100 {
        if await probe.gate != nil { break }
        try await Task.sleep(for: .milliseconds(5))
    }
    await probe.setFailure(.esignerAlternate)
    await probe.resume(); await model.waitForServiceChanges()
    #expect(model.bridges.first { $0.id == .esigner }?.status == .up)
    #expect(model.bridges.first { $0.id == .esignerAlternate }?.status == .portInUse)
    #expect(await probe.stops == [.esignerAlternate]) // failed start still disposes resources
    model.originPrompt = "https://fixture.example.test"
    model.setServiceEnabled(.esigner, false)
    #expect(model.serviceEnabled(.esigner))
    model.originPrompt = nil
    model.setServiceEnabled(.esigner, false); await model.waitForServiceChanges()
    await probe.setFailure(nil)
    model.setServiceEnabled(.esigner, true); await model.waitForServiceChanges()
    #expect(model.bridges.filter { $0.id.service == .esigner }.allSatisfy { $0.status == .up })
    model.setServiceEnabled(.esigner, false); await model.waitForServiceChanges()
}

@Test @MainActor func servicePreferenceSaveFailureDoesNotPretendToDisableListener() throws {
    let directory = serviceDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    try Data("not a directory".utf8).write(to: directory)
    let model = serviceModel(directory, probe: ListenerProbe())
    model.setServiceEnabled(.ctsign, false)
    #expect(model.serviceEnabled(.ctsign) && model.serviceSettingsError != nil)
}

private func servicePortIsOpen(_ port: Int) -> Bool {
    let fd = socket(AF_INET, SOCK_STREAM, 0); defer { close(fd) }
    var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); address.sin_port = UInt16(port).bigEndian
    return withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
    } }
}

@Test @MainActor func realServiceGroupsCanStopAndRestartIndependentlyWithoutScanningOrSigning() async throws {
    let directory = serviceDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    // Isolate all six real listeners from the running user app and parallel fixtures.
    let offset = try #require((15000...15100).first { offset in
        (try! BridgeCatalog.endpoints(offset: offset)).allSatisfy { !servicePortIsOpen($0.port) }
    })
    let model = AppModel(broker: TokenBroker(helperURL: URL(fileURLWithPath: "/nonexistent"),
        shimURL: URL(fileURLWithPath: "/nonexistent"), moduleDirs: []),
        promptWindow: ServicePrompt(), supportDirectory: directory, portOffset: offset)
    model.startBridgeServices(); await model.waitForServiceChanges()
    #expect(model.bridges.allSatisfy { $0.status == .up && servicePortIsOpen($0.endpoint.port) })
    for service in BridgeService.allCases {
        model.setServiceEnabled(service, false); await model.waitForServiceChanges()
        for row in model.bridges {
            #expect(servicePortIsOpen(row.endpoint.port) == (row.id.service != service))
        }
        model.setServiceEnabled(service, true); await model.waitForServiceChanges()
        #expect(model.bridges.allSatisfy { $0.status == .up && servicePortIsOpen($0.endpoint.port) })
    }
    for service in BridgeService.allCases {
        model.setServiceEnabled(service, false); await model.waitForServiceChanges()
    }
    #expect(model.bridges.allSatisfy { !servicePortIsOpen($0.endpoint.port) })
}
