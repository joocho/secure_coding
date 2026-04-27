package log

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// LogEntry는 JSON Lines 포맷의 로그 항목입니다.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Event     string `json:"event"`
	AuctionID string `json:"auction_id"`
	UserID    string `json:"user_id"`
	RequestID string `json:"request_id"`
	Message   string `json:"message"`
	ErrorCode string `json:"error_code"`
}

// Audit는 감시 로그를 출력합니다.
func Audit(event, auctionID, userID, reqID, msg string) {
	writeLog("AUDIT", event, auctionID, userID, reqID, msg, "")
}

// Warn은 경고 로그를 출력합니다.
func Warn(event, auctionID, userID, reqID, msg, errCode string) {
	writeLog("WARN", event, auctionID, userID, reqID, msg, errCode)
}

// Error는 에러 로그를 출력합니다.
func Error(event, auctionID, userID, reqID, msg, errCode string) {
	writeLog("ERROR", event, auctionID, userID, reqID, msg, errCode)
}

func writeLog(level, event, auctionID, userID, reqID, msg, errCode string) {
	// 민감 정보 필터링 (간이 마스킹)
	sensitiveKeywords := []string{"password", "secret", "key", "bid", "price"}
	lowerMsg := strings.ToLower(msg)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lowerMsg, kw) {
			msg = "[MASKED: SENSITIVE INFORMATION]"
			break
		}
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Event:     event,
		AuctionID: auctionID,
		UserID:    userID,
		RequestID: reqID,
		Message:   msg,
		ErrorCode: errCode,
	}

	data, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stdout, string(data))
}
