# PKI 실습 - GunPG 이용

## 실행 순서

① 키 생성
Alice 키 생성
```
bashgpg --full-generate-key
```
질문에 대한 답 예시 (자신에 맞게 변경)
```
키 종류    → 1 (RSA and RSA)
키 크기    → 2048
만료 기간  → 0 (만료 없음)
Real name  → Alice
Email      → alice@test.com
Comment    → (엔터)
확인       → O
암호문(passphrase) → 123456 (실습용)
```

Bob 키 생성 (같은 방식으로)
```bash
gpg --full-generate-key
```

```
Real name  → Bob
Email      → bob@test.com
암호문     → 123456
```


② 키 확인

```bash
gpg --list-keys
```

Alice와 Bob 두 개의 키가 보여야 해요.

③ 공개키 내보내기

```bash
gpg --armor --export alice@test.com > alice_pub.asc
gpg --armor --export bob@test.com   > bob_pub.asc
cat alice_pub.asc   # 내용 확인
```


④ 메시지 암호화 (Alice → Bob)
Bob의 공개키로 암호화:
```bash
echo "안녕 Bob! 비밀 메시지야. - Alice" > message.txt
gpg --armor --encrypt --recipient bob@test.com message.txt
```

```bash
# message.txt.asc 파일 생성됨
cat message.txt.asc   # 암호문 확인
```

⑤ 복호화 (Bob이 읽기)

Bob의 개인키로 복호화:
```bash
gpg --decrypt message.txt.asc
# passphrase 입력: 123456
```

원문이 출력되면 성공!

⑥ 서명 + 암호화 동시에

```bash
gpg --armor --sign --encrypt \
    --local-user alice@test.com \
    --recipient bob@test.com \
    message.txt

gpg --decrypt message.txt.asc
# 복호화 + "Good signature from Alice" 확인
```

⑦ 서명만 (무결성 검증 실습)

Bob이 서명
```bash
gpg --armor --clearsign --local-user bob@test.com message.txt
# message.txt.asc 생성
```

Alice가 검증
```bash
gpg --verify message.txt.asc

# 파일 변조 후 재검증 → BAD signature 확인
echo "변조!" >> message.txt.asc
gpg --verify message.txt.asc
```
