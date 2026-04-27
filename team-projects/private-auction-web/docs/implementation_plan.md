# Implementation Plan (Blind Auction v2)

## 1. 개요
기존의 단순 해시 기반 입찰 시스템을 폐기하고, **KMS 연동 봉투 암호화(Envelope Encryption)** 기반의 고성능/고보안 시스템으로 전환합니다.

## 2. 주요 로직 변경사항
### A. 경매 생성 로직 (`internal/auction/service.go`)
- [ ] `crypto/rsa` 패키지를 사용하여 RSA-4096 키쌍 생성.
- [ ] `internal/security/kms.go` (신규)를 통해 개인키를 KMS로 암호화.
- [ ] `public_key` (PEM) 및 `encrypted_private_key` (BLOB)를 SQLite에 저장.

### B. 입찰 제출 로직 (`internal/bid/service.go`)
- [ ] 평문 입찰가를 받던 기존 로직을 제거하고, `encrypted_payload` 및 `signature`만 수신하도록 변경.
- [ ] 서버는 복호화 시도 없이 데이터 형식 및 중복 입찰 여부만 확인 후 DB 저장.

### C. 결과 공개 워커 (`cmd/reveal/main.go`)
- [ ] 마감된 경매를 조회하여 KMS에 `UnwrapKey` 요청.
- [ ] 복호화된 개인키로 모든 `encrypted_payload`를 RSA-OAEP 복호화.
- [ ] 서명 검증 및 최고가 산출 로직 실행.
- [ ] 최종 결과 공시 및 메모리 내 평문 데이터 즉각 삭제.

## 3. 보안 체크리스트 (구현 시 주의사항)
- [x] RSA 암호화 시 반드시 `OAEP` 패딩 사용 (`PKCS#1 v1.5` 금지).
- [x] 평문 입찰가가 로그, 예외 메시지, 캐시에 남지 않도록 검토.
- [x] 클라이언트 측에서 입찰가 암호화 시 충분한 길이의 `Nonce` 추가 유도.

## 4. 단계별 실행 계획
1. **Infrastructure**: KMS 연동을 위한 Mock 및 SDK 초기화 모듈 개발.
2. **Schema**: `db/schema.sql` 업데이트 (BLOB 필드 추가 및 감사 로그 테이블 생성).
3. **Core**: RSA 키 생성 및 KMS 래핑 로직 구현.
4. **Service**: 입찰 제출 API 고도화 (암호문 저장 전용).
5. **Worker**: 마감 후 자동 복호화 및 결과 처리 배치 엔진 개발.
6. **Testing**: 마감 전 복호화 시도 차단 테스트 및 위협 모델 기반 침투 테스트.
