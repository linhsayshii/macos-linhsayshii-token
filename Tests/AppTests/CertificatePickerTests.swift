import Testing
import SwiftUI
import Security
import X509
import SwiftASN1
import Core
@testable import Bridges
@testable import App

@MainActor private final class Presenter: SigningPromptPresenting {
    var titles: [String] = []
    var onCancel: (() -> Void)?
    func present<Content: View>(title: String, content: Content, onCancel: @escaping () -> Void) {
        titles.append(title); self.onCancel = onCancel
    }
    func dismiss() { onCancel = nil }
}

private func fixture(token: String = "USB-A", expired: Bool = false, flags: [String] = []) throws -> SigningTarget {
    let key = try #require(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false] as CFDictionary, nil))
    let privateKey = try Certificate.PrivateKey(key)
    let name = try DistinguishedName { CommonName("Công ty thử nghiệm") }
    let cert = try Certificate(version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: privateKey.publicKey,
        notValidBefore: Date().addingTimeInterval(-3600), notValidAfter: Date().addingTimeInterval(expired ? -60 : 3600),
        issuer: name, subject: name, signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: Certificate.Extensions {}, issuerPrivateKey: privateKey)
    var serializer = DER.Serializer(); try serializer.serialize(cert)
    return SigningTarget(tokenSerial: token, module: ModuleInfo(ca: "FastCA", moduleName: "fixture", arch: .universal),
        cert: CertInfo(id: "key-A", derB64: Data(serializer.serializedBytes).base64EncodedString(),
            subject: "CN=Công ty thử nghiệm", issuer: "CN=CA thử nghiệm", serialHex: "AABBCC", notBefore: "2026-01-01", notAfter: "2026-12-31"), flags: flags)
}

@MainActor private func model(_ targets: [SigningTarget], _ presenter: any SigningPromptPresenting) -> AppModel {
    // These tests cancel before PIN submission: no helper or hardware is used.
    AppModel(broker: TokenBroker(helperURL: URL(fileURLWithPath: "/nonexistent/TokenHelper"),
        shimURL: URL(fileURLWithPath: "/nonexistent/libTSShim.dylib"), moduleDirs: []),
        promptWindow: presenter, targets: targets)
}

@MainActor private func waitFor(_ predicate: () -> Bool) async throws {
    for _ in 0..<200 {
        if predicate() { return }
        try await Task.sleep(for: .milliseconds(5))
    }
    Issue.record("Prompt did not reach the expected state")
    throw CancellationError()
}

@Test @MainActor func incomingSigningAutomaticallyPresentsPickerThenApprovalAndPIN() async throws {
    let target = try fixture(), presenter = Presenter()
    let app = model([target], presenter)
    let task = Task { try await app.sign(origin: "https://test.example", serial: "", dataB64: Data("test".utf8).base64EncodedString(), operation: "Ký thử", docCount: 1) }
    try await waitFor { app.certificatePrompt != nil }
    #expect(presenter.titles == ["Chọn chữ ký số"])
    #expect(app.selectedCertificateID == nil)
    #expect(app.approvalPrompt == nil && app.pinPrompt == nil)
    let choice = try #require(app.certificatePrompt?.choices.first)
    app.selectedCertificateID = choice.id
    app.submitCertificate(choice.id)
    try await waitFor { app.approvalPrompt != nil }
    #expect(app.approvalPrompt?.subject == target.cert.subject)
    app.submitApproval(.once)
    try await waitFor { app.pinPrompt != nil }
    #expect(app.pinPrompt?.serial == target.tokenSerial)
    app.pinDraft = "draft-must-clear"
    presenter.onCancel?()
    do { _ = try await task.value; Issue.record("Cancelled PIN must not sign") } catch {}
    #expect(app.pinDraft.isEmpty && app.pinPrompt == nil)
    #expect(presenter.titles == ["Chọn chữ ký số", "Yêu cầu ký số", "Đăng nhập token"])
}

@Test @MainActor func pickerUpdatesOnHotplugAndRejectsRemovedOrWrongCertificate() async throws {
    let target = try fixture(), presenter = Presenter()
    let app = model([], presenter)
    let task = Task { try await app.selectCertificate(origin: "Minvoice", serial: "aabbcc") }
    try await waitFor { app.certificatePrompt != nil }
    #expect(app.certificatePrompt?.choices.isEmpty == true)
    app.updateCertificateTargets([target])
    let id = try #require(app.certificatePrompt?.choices.first?.id)
    app.selectedCertificateID = id
    app.updateCertificateTargets([])
    #expect(app.selectedCertificateID == nil)
    app.submitCertificate(id)
    #expect(app.certificatePrompt != nil)
    let wrongCert = CertInfo(id: target.cert.id, derB64: target.cert.derB64, subject: target.cert.subject,
        issuer: target.cert.issuer, serialHex: "DIFFERENT", notBefore: "", notAfter: "")
    app.updateCertificateTargets([SigningTarget(tokenSerial: "USB-B", module: target.module, cert: wrongCert, flags: [])])
    #expect(app.certificatePrompt?.choices.first?.canSelect == false)
    app.submitCertificate(app.certificatePrompt?.choices.first?.id)
    #expect(app.certificatePrompt != nil)
    app.submitCertificate(nil)
    do { _ = try await task.value; Issue.record("Cancelled chooser must fail") } catch is CancellationError {} catch { Issue.record("Unexpected error") }
    #expect(presenter.titles == ["Chọn chữ ký số"])
}

@Test @MainActor func discoveryRemembersOnlyTheExplicitChoiceAndOnlyForItsOrigin() async throws {
    let first = try fixture(), second = SigningTarget(tokenSerial: "USB-B", module: first.module, cert: first.cert, flags: [])
    let presenter = Presenter(), app = model([first, second], presenter)
    let task = Task { try await app.selectCertificate(origin: "tenant-A", serial: nil) }
    try await waitFor { app.certificatePrompt != nil }
    let choices = try #require(app.certificatePrompt?.choices)
    #expect(choices.count == 2 && choices.allSatisfy(\.canSelect))
    let selected = try #require(choices.first { $0.target.tokenSerial == "USB-B" })
    app.submitCertificate(selected.id)
    #expect(try await task.value.serialHex == first.cert.serialHex)
    _ = try await app.selectCertificate(origin: "tenant-A", serial: nil)
    #expect(presenter.titles.count == 1)
    let another = Task { try await app.selectCertificate(origin: "tenant-B", serial: nil) }
    try await waitFor { app.certificatePrompt != nil }
    presenter.onCancel?()
    _ = try? await another.value
    #expect(presenter.titles.count == 2)
}

@Test @MainActor func taskCancellationDismissesChooserReleasesLockAndRejectsConcurrentRequest() async throws {
    let presenter = Presenter(), app = model([], presenter)
    let task = Task { try await app.selectCertificate(origin: "first", serial: nil) }
    try await waitFor { app.certificatePrompt != nil }
    do { _ = try await app.selectCertificate(origin: "second", serial: nil); Issue.record("Expected busy") }
    catch MinvoiceError.busy {} catch { Issue.record("Wrong busy error") }
    #expect(app.certificatePrompt?.origin == "first")
    task.cancel()
    _ = try? await task.value
    #expect(app.certificatePrompt == nil && presenter.onCancel == nil)
    let next = Task { try await app.selectCertificate(origin: "next", serial: nil) }
    try await waitFor { app.certificatePrompt?.origin == "next" }
    presenter.onCancel?()
    _ = try? await next.value
}

@Test func certificatePolicyUsesDERValidityAndPhysicalIdentity() throws {
    let expired = try fixture(expired: true)
    #expect(SigningCertificateChoice(target: expired).canSelect)
    #expect(SigningCertificateChoice(target: expired).warning != nil)
    #expect(!SigningCertificateChoice(target: expired, requireValid: true).canSelect)
    #expect(!SigningCertificateChoice(target: expired, requestedSerial: "wrong").canSelect)
    #expect(!SigningCertificateChoice(target: expired, tokenSerial: "wrong").canSelect)
    let locked = SigningTarget(tokenSerial: expired.tokenSerial, module: expired.module, cert: expired.cert, flags: ["USER_PIN_LOCKED"])
    #expect(!SigningCertificateChoice(target: locked).canSelect)
    let copy = SigningTarget(tokenSerial: "USB-COPY", module: expired.module, cert: expired.cert, flags: [])
    #expect(SigningCertificateChoice.identity(copy) != SigningCertificateChoice.identity(expired))
    #expect(SigningCertificateChoice.list([expired, copy]).count == 2)
    let ambiguous = SigningCertificateChoice.list([expired, expired])
    #expect(ambiguous.count == 1 && !ambiguous[0].canSelect)
}

@Test @MainActor func CTSignKeepsRequestedSerialAndCancellationDismissesApproval() async throws {
    let target = try fixture(), presenter = Presenter()
    let app = model([], presenter)
    let other = CertInfo(id: target.cert.id, derB64: target.cert.derB64, subject: "Other certificate",
        issuer: target.cert.issuer, serialHex: "112233", notBefore: "", notAfter: "")
    app.updateCertificateTargets([target, SigningTarget(tokenSerial: "USB-OTHER", module: target.module, cert: other, flags: [])])
    let task = Task { try await Backend(model: app).sign(serial: "aabbcc", digestB64: Data(repeating: 1, count: 32).base64EncodedString()) }
    try await waitFor { app.certificatePrompt != nil }
    #expect(app.certificatePrompt?.requestedSerial == "aabbcc")
    #expect(app.certificatePrompt?.choices.filter(\.canSelect).count == 1)
    app.submitCertificate(SigningCertificateChoice.identity(target))
    try await waitFor { app.approvalPrompt != nil }
    task.cancel()
    _ = try? await task.value
    #expect(app.approvalPrompt == nil && app.pinPrompt == nil)
    #expect(presenter.onCancel == nil)
}

@Test @MainActor func minvoiceWithoutSerialRequiresChoiceAndApprovalBeforeItsOperation() async throws {
    let target = try fixture(), presenter = Presenter()
    let app = model([target], presenter)
    let task = Task {
        try await MinvoiceBackend(model: app).withApproval(origin: "https://hddt.minvoice.com.vn", serial: "") { _, _ in
            Issue.record("REST/sign operation must not run before user approval")
        }
    }
    try await waitFor { app.certificatePrompt != nil }
    app.submitCertificate(SigningCertificateChoice.identity(target))
    try await waitFor { app.approvalPrompt != nil }
    app.submitApproval(.deny)
    do { try await task.value; Issue.record("Denied request must fail") } catch {}
    #expect(app.pinPrompt == nil && presenter.titles == ["Chọn chữ ký số", "Yêu cầu ký số"])
}

@Test @MainActor func nativeCertificatePickerRendersWithMultipleTokens() async throws {
    guard let output = ProcessInfo.processInfo.environment["TOKENSIGNER_PICKER_SNAPSHOT"] else { return }
    let target = try fixture()
    let second = SigningTarget(tokenSerial: "USB-B", module: ModuleInfo(ca: "VNPT", moduleName: "fixture", arch: .universal), cert: target.cert, flags: [])
    let expired = try fixture(token: "USB-EXPIRED", expired: true)
    let app = model([target, second, expired], SigningPromptWindow())
    NSApplication.shared.setActivationPolicy(.accessory)
    let task = Task { try await app.selectCertificate(origin: "https://hddt.minvoice.com.vn", serial: nil) }
    try await waitFor { app.certificatePrompt != nil }
    try await Task.sleep(for: .milliseconds(250))
    let panel = try #require(NSApplication.shared.windows.first { $0.title == "Chọn chữ ký số" })
    let view = try #require(panel.contentView)
    view.layoutSubtreeIfNeeded()
    #expect(panel.isVisible && panel.frame.width > 400 && panel.frame.height > 450)
    let rep = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
    view.cacheDisplay(in: view.bounds, to: rep)
    let png = try #require(rep.representation(using: .png, properties: [:]))
    try png.write(to: URL(fileURLWithPath: output))
    panel.performClose(nil)
    _ = try? await task.value
    #expect(app.certificatePrompt == nil)
}

@Test @MainActor func minvoiceTokenInfoUsesNativeSelectionWithMultipleCertificates() async throws {
    let target = try fixture(), presenter = Presenter()
    let copy = SigningTarget(tokenSerial: "USB-B", module: target.module, cert: target.cert, flags: [])
    let app = model([target, copy], presenter)
    let bridge = MinvoiceBridge(backend: MinvoiceBackend(model: app))
    let task = Task { await bridge.dispatch("{\"PlugCommand\":{\"CommandName\":\"TokenInfo\"}}", origin: "https://hddt.minvoice.com.vn") }
    try await waitFor { app.certificatePrompt != nil }
    app.submitCertificate(SigningCertificateChoice.identity(copy))
    let response = try #require(try JSONSerialization.jsonObject(with: Data(await task.value.utf8)) as? [String: Any])
    #expect(response["code"] as? Int == 1)
    let data = try #require(response["data"] as? [String: Any])
    let token = try #require(data["token"] as? [String: String])
    #expect(token["SerialNumber"] == target.cert.serialHex)
    #expect(app.approvalPrompt == nil && app.pinPrompt == nil)
}

@Test @MainActor func eSignerUsesNativeSelectionApprovalAndPINWithCallerOrigin() async throws {
    let target = try fixture(), presenter = Presenter()
    let app = model([target], presenter), service = AppSigningService(model: app)
    let ctx = BridgeContext(bridge: "esigner", origin: "https://thuedientu.gdt.gov.vn")
    let task = Task { try await service.signMessage(ctx, serial: nil, message: Data("prepared bytes".utf8), hash: .sha256) }
    try await waitFor { app.certificatePrompt != nil }
    #expect(app.certificatePrompt?.origin == ctx.origin)
    app.submitCertificate(SigningCertificateChoice.identity(target))
    try await waitFor { app.approvalPrompt != nil }
    #expect(app.approvalPrompt?.origin == ctx.origin)
    app.submitApproval(.once)
    try await waitFor { app.pinPrompt != nil }
    task.cancel()
    _ = try? await task.value
    #expect(app.pinPrompt == nil && app.pinDraft.isEmpty)
}

@Test @MainActor func CTSignXMLRejectsUnsafeInputBeforeOpeningPrompt() async throws {
    let presenter = Presenter(), app = model([], Presenter())
    let service = AppSigningService(model: app)
    let xml = Data("<!DOCTYPE root [<!ENTITY x SYSTEM 'file:///etc/hosts'>]><root>&x;</root>".utf8)
    do {
        _ = try await service.signXML(BridgeContext(bridge: "ctsigninghub", origin: "https://thuedientu.gdt.gov.vn"), serial: nil, xml: xml, options: XMLSignOptions())
        Issue.record("Unsafe XML accepted")
    } catch XMLDSigError.rejected(.declarations) {} catch { Issue.record("Unexpected error") }
    #expect(app.certificatePrompt == nil && presenter.titles.isEmpty)
}

@Test @MainActor func CTSignXMLRejectsDuplicateReferencedIDBeforeOpeningPrompt() async throws {
    let presenter = Presenter()
    let app = model([], presenter)
    let service = AppSigningService(model: app)
    var options = XMLSignOptions(); options.signElements = ["HSoKhaiThue"]
    let xml = Data("<HSoThueDTu><HSoKhaiThue id='ID_1'/><Other ID='ID_1'/></HSoThueDTu>".utf8)
    await #expect(throws: XMLDSigError.rejected(.duplicateID)) {
        _ = try await service.signXML(BridgeContext(bridge: "ctsigninghub", origin: "https://thuedientu.gdt.gov.vn"), serial: nil, xml: xml, options: options)
    }
    #expect(app.certificatePrompt == nil && app.pinPrompt == nil && presenter.titles.isEmpty)
}

@Test @MainActor func CTSignXMLWithRepeatedBusinessIDsReachesCertificateChooser() async throws {
    let presenter = Presenter(), app = model([], presenter)
    let service = AppSigningService(model: app)
    var options = XMLSignOptions(); options.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu"); options.signElements = ["HSoKhaiThue"]
    let xml = Data("<HSoThueDTu><HSoKhaiThue id='ID_1'><Row id='1'/><Row id='1'/></HSoKhaiThue></HSoThueDTu>".utf8)
    let task = Task { try await service.signXML(BridgeContext(bridge: "ctsigninghub", origin: "https://thuedientu.gdt.gov.vn"), serial: nil, xml: xml, options: options) }
    try await waitFor { app.certificatePrompt != nil }
    #expect(presenter.titles == ["Chọn chữ ký số"])
    task.cancel(); _ = try? await task.value
    #expect(app.certificatePrompt == nil && app.pinPrompt == nil)
}

@Test @MainActor func minvoiceBatchApprovalShowsWholeInvoiceCountBeforePIN() async throws {
    let target = try fixture(), presenter = Presenter()
    let app = model([], presenter)
    app.updateCertificateTargets([target])
    let backend = MinvoiceBackend(model: app)
    let task = Task {
        try await backend.withApproval(origin: "https://hddt.minvoice.com.vn", serial: target.cert.serialHex, invoiceCount: 300) { _, _ in }
    }
    try await waitFor { app.certificatePrompt != nil }
    app.submitCertificate(SigningCertificateChoice.identity(target))
    try await waitFor { app.approvalPrompt != nil }
    #expect(app.approvalPrompt?.docCount == 300 && app.approvalPrompt?.countUnit == "hóa đơn" && app.pinPrompt == nil)
    task.cancel(); _ = try? await task.value
    #expect(app.certificatePrompt == nil && app.pinPrompt == nil && presenter.titles == ["Chọn chữ ký số", "Yêu cầu ký số"])
}

@Test @MainActor func minvoicePINIsPromptedOnceAndDoesNotSurviveSessionClearOrCancellation() async throws {
    let session = MinvoicePINSession()
    var prompts = 0
    for _ in 0..<300 {
        let pin = try await session.pin { prompts += 1; return "fixture-only" }
        #expect(pin == "fixture-only")
    }
    #expect(prompts == 1)
    session.clear()
    _ = try await session.pin { prompts += 1; return "fixture-next-session" }
    #expect(prompts == 2)
    session.clear()
    await #expect(throws: CancellationError.self) {
        _ = try await session.pin { throw CancellationError() }
    }
    _ = try await session.pin { prompts += 1; return "fixture-after-cancel" }
    #expect(prompts == 3)
    session.clear()
}

@Test @MainActor func minvoiceMenuCancellationDismissesPINAndReleasesBatchLock() async throws {
    let target = try fixture(), presenter = Presenter()
    let app = model([target], presenter), backend = MinvoiceBackend(model: app)
    let task = Task {
        try await backend.withApproval(origin: "https://hddt.minvoice.com.vn", serial: target.cert.serialHex, invoiceCount: 300) { _, sign in
            _ = try await sign(Data("fixture".utf8))
        }
    }
    try await waitFor { app.certificatePrompt != nil }
    app.submitCertificate(SigningCertificateChoice.identity(target))
    try await waitFor { app.approvalPrompt != nil }
    app.submitApproval(.once)
    try await waitFor { app.pinPrompt != nil && app.minvoiceBatchActive }
    app.cancelMinvoiceBatch()
    do { try await task.value; Issue.record("Cancelled batch completed") } catch is CancellationError {} catch { Issue.record("Unexpected error") }
    #expect(app.pinPrompt == nil && !app.minvoiceBatchActive && app.pinDraft.isEmpty)
    let next = Task { try await app.selectCertificate(origin: "next", serial: nil) }
    try await waitFor { app.certificatePrompt != nil }
    app.submitCertificate(nil); _ = try? await next.value
}
