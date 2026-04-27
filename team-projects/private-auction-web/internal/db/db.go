package db

import (
	"database/sql"
	"embed"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaFS embed.FS

// InitDB는 SQLite 데이터베이스를 초기화하고 최신 v2 스키마를 적용합니다.
func InitDB(dbPath string) (*sql.DB, error) {
	// 1. 디렉토리 보안 강화: 소유자만 접근 가능하도록 설정 (0700)
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	// 2. 파일 보안 강화: 소유자 외 접근 차단 (0600)
	// 파일이 이미 존재하더라도 권한을 다시 강제 설정합니다.
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	// 운영체제 레벨에서 파일 권한 제한 (Unix/Linux 0600 대응)
	_ = os.Chmod(dbPath, 0600)

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}

	if err := applyV2Schema(db); err != nil {
		return nil, err
	}

	return db, nil
}

func applyV2Schema(db *sql.DB) error {
	schemaBytes, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}

	_, err = db.Exec(string(schemaBytes))
	return err
}
