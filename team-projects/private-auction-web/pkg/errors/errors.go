package errors

// AppError는 애플리케이션 에러를 나타냅니다.
type AppError struct {
	Code     string
	Message  string // 사용자에게 노출
	Internal error  // 로그에만 기록
}

func (e *AppError) Error() string {
	return e.Message
}

// 인증 에러
var (
	ErrAuthInvalid = &AppError{Code: "ERR_AUTH_001", Message: "인증 정보가 올바르지 않습니다."}
	ErrForbidden   = &AppError{Code: "ERR_AUTH_002", Message: "해당 작업에 대한 권한이 없습니다."}
)

// 입찰 에러
var (
	ErrBidPeriodClosed = &AppError{Code: "ERR_BID_001", Message: "현재 입찰 가능한 기간이 아닙니다."}
	ErrRevealTooEarly  = &AppError{Code: "ERR_BID_002", Message: "경매가 종료된 후에 결과를 확인할 수 있습니다."}
	ErrDuplicateBid    = &AppError{Code: "ERR_BID_003", Message: "이미 해당 경매에 유효한 입찰 기록이 존재합니다."}
	ErrInvalidHashFmt  = &AppError{Code: "ERR_BID_004", Message: "전달된 데이터 형식이 유효하지 않습니다."}
)

// 검증 에러
var (
	ErrHashMismatch = &AppError{Code: "ERR_VER_001", Message: "데이터 무결성 검증에 실패했습니다."}
	ErrInvalidPrice = &AppError{Code: "ERR_VER_002", Message: "입력하신 가격 형식이 올바르지 않습니다."}
	ErrInvalidInput = &AppError{Code: "ERR_VER_003", Message: "입력된 데이터의 형식이 올바르지 않거나 허용되지 않은 문자가 포함되어 있습니다."}
)

// 레이트 제한 에러
var (
	ErrRateLimit = &AppError{Code: "ERR_RATE_001", Message: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요."}
)

// 시스템 에러
var (
	ErrSystemError = &AppError{Code: "ERR_SYS_001", Message: "시스템 내부 오류가 발생했습니다. 관리자에게 문의하세요."}
)
