import Foundation

struct SigningResult {
    enum Kind { case success, cancelled, failure, warning }
    let kind: Kind
    let message: String
    var title: String {
        switch kind {
        case .success: "Ký và xác minh thành công"
        case .cancelled: "Đã hủy yêu cầu ký"
        case .failure: "Yêu cầu ký chưa hoàn tất"
        case .warning: "Cần kiểm tra kết quả upload"
        }
    }
    var tone: NoticeTone {
        switch kind { case .success: .success; case .cancelled: .neutral; case .failure: .danger; case .warning: .warning }
    }
}
