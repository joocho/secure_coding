#!/bin/bash
# End-to-end security test suite for qa-board.
# Run from the project root: bash tests/e2e.sh
set -u
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BIN="$SCRIPT_DIR/../target/debug/qa-board"
if [ ! -x "$BIN" ]; then
  echo "binary not built — run \`cargo build\` first" >&2
  exit 2
fi
PORT=3344
URL="http://127.0.0.1:$PORT"

TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Fresh tokens
$BIN generate --db board.db --count 5 --output tokens.txt >/dev/null

# Start server
$BIN serve --db board.db --bind 127.0.0.1:$PORT > server.log 2>&1 &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null" EXIT
sleep 1.5

# Read tokens (skip first 5 header lines, blank line at line 5)
TOKEN1=$(awk 'NR==6' tokens.txt)
TOKEN2=$(awk 'NR==7' tokens.txt)
TOKEN3=$(awk 'NR==8' tokens.txt)
TOKEN4=$(awk 'NR==9' tokens.txt)

echo "=== Test 1: GET /ask issues CSRF cookie + form field ==="
curl -sS -c c1.txt -D headers1.txt "$URL/ask" -o ask1.html -w "HTTP %{http_code}\n"
CSRF1=$(grep -oP 'name="csrf" value="\K[^"]+' ask1.html)
SETCOOKIE=$(grep -i '^set-cookie:' headers1.txt)
if [ -n "$CSRF1" ]; then pass "CSRF form field present (${#CSRF1} chars)"; else fail "no CSRF field"; fi
echo "$SETCOOKIE" | grep -q 'qa_csrf=' && pass "Set-Cookie qa_csrf=..." || fail "no qa_csrf in Set-Cookie"
echo "$SETCOOKIE" | grep -qi 'HttpOnly' && pass "cookie is HttpOnly" || fail "cookie missing HttpOnly"
echo "$SETCOOKIE" | grep -qi 'SameSite=Strict' && pass "cookie is SameSite=Strict" || fail "cookie missing SameSite=Strict"
echo "$SETCOOKIE" | grep -qi 'Secure' && pass "cookie has Secure flag" || fail "cookie missing Secure"

echo
echo "=== Test 2: Security headers present ==="
HEADERS=$(curl -sSI "$URL/ask")
echo "$HEADERS" | grep -qi "x-content-type-options: nosniff" && pass "X-Content-Type-Options" || fail "X-Content-Type-Options"
echo "$HEADERS" | grep -qi "x-frame-options: DENY" && pass "X-Frame-Options DENY" || fail "X-Frame-Options"
echo "$HEADERS" | grep -qi "referrer-policy: no-referrer" && pass "Referrer-Policy" || fail "Referrer-Policy"
echo "$HEADERS" | grep -qi "content-security-policy:" && pass "CSP" || fail "CSP"
echo "$HEADERS" | grep -qi "strict-transport-security:" && pass "HSTS" || fail "HSTS"

echo
echo "=== Test 3: Submit valid question ==="
curl -sS -b c1.txt -c c1.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF1" \
  --data-urlencode "token=$TOKEN1" \
  --data-urlencode "content=교수님, 수업 잘 들었습니다." \
  -o submit1.html -w "HTTP %{http_code}\n"
if grep -q "제출되었습니다" submit1.html; then pass "valid submission accepted"; else fail "valid submission rejected"; fi

echo
echo "=== Test 4: Token reuse blocked ==="
curl -sS -c c2.txt "$URL/ask" -o ask2.html
CSRF2=$(grep -oP 'name="csrf" value="\K[^"]+' ask2.html)
curl -sS -b c2.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF2" \
  --data-urlencode "token=$TOKEN1" \
  --data-urlencode "content=second use should fail" \
  -o reuse.html -w "HTTP %{http_code}\n"
if grep -q "Invalid or already-used" reuse.html; then pass "token reuse rejected"; else fail "token reuse NOT rejected"; fi
if grep -q "제출되었습니다" reuse.html; then fail "REUSE ACCEPTED (bug)"; fi

echo
echo "=== Test 5: CSRF cookie missing -> blocked ==="
curl -sS -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF2" \
  --data-urlencode "token=$TOKEN2" \
  --data-urlencode "content=no cookie" \
  -o no_cookie.html -w "HTTP %{http_code}\n"
if grep -q "Session expired" no_cookie.html; then pass "no-cookie blocked"; else fail "no-cookie NOT blocked"; fi

echo
echo "=== Test 6: CSRF cookie/form mismatch -> blocked ==="
curl -sS -b c2.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=wrongwrongwrongwrong" \
  --data-urlencode "token=$TOKEN2" \
  --data-urlencode "content=wrong csrf" \
  -o csrf_mismatch.html -w "HTTP %{http_code}\n"
if grep -q "Session expired" csrf_mismatch.html; then pass "CSRF mismatch blocked"; else fail "CSRF mismatch NOT blocked"; fi

echo
echo "=== Test 7: Verify only TOKEN1 used after CSRF rejections ==="
STATS=$($BIN stats --db board.db)
USED=$(echo "$STATS" | grep '^tokens\.used' | awk -F'=' '{print $2}' | tr -d ' ')
if [ "$USED" = "1" ]; then pass "only 1 token used (TOKEN1)"; else fail "expected 1 used, got $USED"; fi

echo
echo "=== Test 8: Malformed token -> generic error ==="
curl -sS -b c2.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF2" \
  --data-urlencode "token=NOTAREALTOKEN" \
  --data-urlencode "content=garbage token" \
  -o malformed.html -w "HTTP %{http_code}\n"
if grep -q "Invalid or already-used" malformed.html; then pass "malformed token rejected with generic message"; else fail "malformed token error wrong"; fi

echo
echo "=== Test 9: Unknown but well-formed token -> generic error ==="
curl -sS -b c2.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF2" \
  --data-urlencode "token=AAAAAAAAAAAAAAAAAAAAAAAAAA" \
  --data-urlencode "content=fake token" \
  -o unknown.html -w "HTTP %{http_code}\n"
if grep -q "Invalid or already-used" unknown.html; then pass "unknown token gets same error as used"; else fail "unknown token error differs"; fi

echo
echo "=== Test 10: XSS in content is escaped ==="
curl -sS -c c3.txt "$URL/ask" -o ask3.html
CSRF3=$(grep -oP 'name="csrf" value="\K[^"]+' ask3.html)
curl -sS -b c3.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF3" \
  --data-urlencode "token=$TOKEN2" \
  --data-urlencode "content=<script>alert(1)</script> & <img onerror=alert(1) src=x>" \
  -o submit_xss.html -w "HTTP %{http_code}\n"
curl -sS "$URL/" -o list.html
if grep -q "&lt;script&gt;" list.html; then pass "XSS: script tag escaped"; else fail "XSS: script tag NOT escaped"; fi
if grep -q "<script>alert(1)</script>" list.html; then fail "XSS: raw script in output (BUG)"; else pass "XSS: no raw script"; fi
if grep -q "&lt;img" list.html; then pass "XSS: img tag escaped"; else fail "XSS: img tag NOT escaped"; fi

echo
echo "=== Test 11: Body size limit enforced ==="
HUGE=$(head -c 20000 /dev/urandom | base64 | tr -d '\n' | head -c 20000)
HTTP_CODE=$(curl -sS -b c3.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF3" \
  --data-urlencode "token=$TOKEN3" \
  --data-urlencode "content=$HUGE" \
  -o /dev/null -w "%{http_code}")
echo "  big POST returned HTTP $HTTP_CODE"
if [ "$HTTP_CODE" = "413" ] || [ "$HTTP_CODE" = "400" ]; then pass "oversized body rejected"; else fail "oversized body accepted ($HTTP_CODE)"; fi

echo
echo "=== Test 12: Verify TOKEN3 still unused after oversized body ==="
STATS=$($BIN stats --db board.db)
USED=$(echo "$STATS" | grep '^tokens\.used' | awk -F'=' '{print $2}' | tr -d ' ')
# TOKEN1 + TOKEN2 used (TOKEN2 via XSS test) = 2
if [ "$USED" = "2" ]; then pass "TOKEN3 preserved (used=$USED)"; else fail "expected used=2, got $USED"; fi

echo
echo "=== Test 13: Empty question rejected ==="
curl -sS -c c4.txt "$URL/ask" -o ask4.html
CSRF4=$(grep -oP 'name="csrf" value="\K[^"]+' ask4.html)
curl -sS -b c4.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF4" \
  --data-urlencode "token=$TOKEN3" \
  --data-urlencode "content=   " \
  -o empty.html -w "HTTP %{http_code}\n"
if grep -q "질문 내용을 입력" empty.html; then pass "empty content rejected"; else fail "empty content accepted"; fi

echo
echo "=== Test 14: Token decoded case-insensitively + with dashes ==="
TOKEN3_FORMATTED=$(echo "$TOKEN3" | tr 'A-Z' 'a-z' | sed 's/.\{5\}/&-/g')
echo "  using formatted: $TOKEN3_FORMATTED"
curl -sS -b c4.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$CSRF4" \
  --data-urlencode "token=$TOKEN3_FORMATTED" \
  --data-urlencode "content=lowercase with dashes" \
  -o lower.html -w "HTTP %{http_code}\n"
if grep -q "제출되었습니다" lower.html; then pass "lowercase + dashes accepted"; else fail "lowercase + dashes rejected"; fi

echo
echo "=== Test 15: Token does not leak in server.log ==="
if grep -qF "$TOKEN1" server.log; then
  fail "TOKEN1 found in server.log (leak!)"
elif grep -qF "$TOKEN3" server.log; then
  fail "TOKEN3 found in server.log (leak!)"
else
  pass "no raw tokens in server.log"
fi

# ==================== CLAIM CODE FLOW ====================

echo
echo "=== Test 16: Create claim code via CLI ==="
CLAIM_CODE=$($BIN create-claim --db board.db --tokens-per-claim 3 --max-claims 2 --expires-in 1h 2>/dev/null)
if [ -n "$CLAIM_CODE" ]; then pass "claim code generated: $CLAIM_CODE"; else fail "claim code generation"; fi

echo
echo "=== Test 17: GET /claim shows form and CSRF cookie ==="
curl -sS -c cclaim1.txt -D claim_h1.txt "$URL/claim" -o claim_form1.html -w "HTTP %{http_code}\n"
CLAIM_CSRF1=$(grep -oP 'name="csrf" value="\K[^"]+' claim_form1.html)
if [ -n "$CLAIM_CSRF1" ]; then pass "claim form has CSRF field"; else fail "no CSRF on claim form"; fi
grep -i '^set-cookie:.*qa_csrf' claim_h1.txt >/dev/null && pass "claim form sets csrf cookie" || fail "no csrf cookie"

echo
echo "=== Test 18: GET /claim?code=xxx pre-fills form ==="
curl -sS -c cclaim_pre.txt "$URL/claim?code=ABC123" -o claim_prefill.html
if grep -q 'value="ABC123"' claim_prefill.html; then pass "code prefilled from query"; else fail "code not prefilled"; fi

echo
echo "=== Test 19: POST /claim with valid code issues tokens ==="
curl -sS -b cclaim1.txt -c cclaim1.txt -D claim_h2.txt -X POST "$URL/claim" \
  --data-urlencode "csrf=$CLAIM_CSRF1" \
  --data-urlencode "code=$CLAIM_CODE" \
  -o claim_ok.html -w "HTTP %{http_code}\n"
ISSUED_COUNT=$(grep -oE 'class="token">[A-Z0-9]{26}<' claim_ok.html | wc -l)
if [ "$ISSUED_COUNT" = "3" ]; then pass "3 tokens issued"; else fail "expected 3, got $ISSUED_COUNT"; fi

echo
echo "=== Test 20: Claim success response is no-store ==="
if grep -qi '^cache-control:.*no-store' claim_h2.txt; then pass "Cache-Control: no-store set"; else fail "missing no-store"; fi
if grep -qi '^pragma:.*no-cache' claim_h2.txt; then pass "Pragma: no-cache set"; else fail "missing Pragma"; fi

echo
echo "=== Test 21: Claim success sets dedup cookie ==="
grep -i '^set-cookie:.*qa_claimed_' claim_h2.txt >/dev/null && pass "dedup cookie set" || fail "no dedup cookie"

echo
echo "=== Test 22: Same browser cannot re-claim same code ==="
curl -sS -b cclaim1.txt "$URL/claim" -o cf2.html -c cclaim1.txt
CSRF22=$(grep -oP 'name="csrf" value="\K[^"]+' cf2.html)
curl -sS -b cclaim1.txt -X POST "$URL/claim" \
  --data-urlencode "csrf=$CSRF22" \
  --data-urlencode "code=$CLAIM_CODE" \
  -o reclaim.html -w "HTTP %{http_code}\n"
if grep -q "already redeemed" reclaim.html; then pass "same-browser re-claim blocked"; else fail "re-claim not blocked"; fi

echo
echo "=== Test 23: Different browser (no dedup cookie) CAN claim ==="
curl -sS -c cclaim2.txt "$URL/claim" -o cf3.html
CSRF23=$(grep -oP 'name="csrf" value="\K[^"]+' cf3.html)
curl -sS -b cclaim2.txt -X POST "$URL/claim" \
  --data-urlencode "csrf=$CSRF23" \
  --data-urlencode "code=$CLAIM_CODE" \
  -o claim2.html -w "HTTP %{http_code}\n"
ISSUED2=$(grep -oE 'class="token">[A-Z0-9]{26}<' claim2.html | wc -l)
if [ "$ISSUED2" = "3" ]; then pass "second browser got 3 tokens"; else fail "second browser got $ISSUED2"; fi

echo
echo "=== Test 24: Third claim (exceeds max_claims=2) is rejected ==="
curl -sS -c cclaim3.txt "$URL/claim" -o cf4.html
CSRF24=$(grep -oP 'name="csrf" value="\K[^"]+' cf4.html)
curl -sS -b cclaim3.txt -X POST "$URL/claim" \
  --data-urlencode "csrf=$CSRF24" \
  --data-urlencode "code=$CLAIM_CODE" \
  -o claim3.html -w "HTTP %{http_code}\n"
if grep -q "Invalid, exhausted, or expired" claim3.html; then pass "max_claims enforced (3rd rejected)"; else fail "max_claims NOT enforced"; fi

echo
echo "=== Test 25: Unknown code → same generic error ==="
curl -sS -c cclaim4.txt "$URL/claim" -o cf5.html
CSRF25=$(grep -oP 'name="csrf" value="\K[^"]+' cf5.html)
curl -sS -b cclaim4.txt -X POST "$URL/claim" \
  --data-urlencode "csrf=$CSRF25" \
  --data-urlencode "code=NEVEREXISTED1234" \
  -o claim_unknown.html -w "HTTP %{http_code}\n"
if grep -q "Invalid, exhausted, or expired" claim_unknown.html; then pass "unknown code gets same error as exhausted"; else fail "unknown code error differs"; fi

echo
echo "=== Test 26: Malformed code → same generic error ==="
curl -sS -b cclaim4.txt -X POST "$URL/claim" \
  --data-urlencode "csrf=$CSRF25" \
  --data-urlencode "code=!@#" \
  -o claim_bad.html -w "HTTP %{http_code}\n"
if grep -q "Invalid, exhausted, or expired" claim_bad.html; then pass "malformed code: generic error"; else fail "malformed code error differs"; fi

echo
echo "=== Test 27: Token issued via claim works on /ask ==="
# Pull a token from the first claim response.
ISSUED_TOKEN=$(grep -oE 'class="token">[A-Z0-9]{26}<' claim_ok.html | head -1 | sed 's/class="token">//; s/<$//')
echo "  using issued token: $ISSUED_TOKEN"
curl -sS -c cuse.txt "$URL/ask" -o use_form.html
USE_CSRF=$(grep -oP 'name="csrf" value="\K[^"]+' use_form.html)
curl -sS -b cuse.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$USE_CSRF" \
  --data-urlencode "token=$ISSUED_TOKEN" \
  --data-urlencode "content=question via claim-issued token" \
  -o use_result.html -w "HTTP %{http_code}\n"
if grep -q "제출되었습니다" use_result.html; then pass "claim-issued token works on /ask"; else fail "claim-issued token rejected"; fi

echo
echo "=== Test 28: Used token cannot be reused ==="
curl -sS -b cuse.txt "$URL/ask" -o uf2.html -c cuse.txt
USE_CSRF2=$(grep -oP 'name="csrf" value="\K[^"]+' uf2.html)
curl -sS -b cuse.txt -X POST "$URL/ask" \
  --data-urlencode "csrf=$USE_CSRF2" \
  --data-urlencode "token=$ISSUED_TOKEN" \
  --data-urlencode "content=should fail" \
  -o reuse2.html -w "HTTP %{http_code}\n"
if grep -q "Invalid or already-used" reuse2.html; then pass "claim-issued token, second use rejected"; else fail "reuse not blocked"; fi

echo
echo "=== Test 29: Claim code does not leak in server.log ==="
if grep -qF "$CLAIM_CODE" server.log; then
  fail "CLAIM_CODE found in server.log (leak!)"
else
  pass "no claim code in server.log"
fi

echo
echo "=== Test 30: list-claims CLI shows usage stats ==="
LIST_OUT=$($BIN list-claims --db board.db)
if echo "$LIST_OUT" | grep -q "2/2"; then pass "list-claims shows 2/2 usage"; else fail "list-claims output unexpected: $LIST_OUT"; fi

echo
echo "===================="
echo "PASSED: $PASS  FAILED: $FAIL"
echo "===================="
exit $FAIL
