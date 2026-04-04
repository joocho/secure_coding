/*
 * Schnorr Protocol — Interactive Zero-Knowledge Proof
 * 실습용 구현 (교육 목적)
 *
 * 컴파일: gcc -o schnorr schnorr.c
 * 실행:   ./schnorr
 *
 * 시나리오:
 *   1. 정상 증명 (x 알고 있음)
 *   2. 사기 시도 (x 모름)
 *   3. r 재사용 공격 → 비밀키 복구
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ────────────────────────────────────────────
 * 파라미터
 *
 * 실습용 작은 소수 사용.
 * 실제 구현은 2048-bit 이상의 safe prime 사용.
 *
 * safe prime: p = 2q + 1 (q도 소수)
 * 여기서는 p=23, q=11 인 작은 safe prime 사용
 * g=7 은 mod 23 에서 위수 11인 generator
 * ──────────────────────────────────────────── */
#define P  23LL     /* 소수 modulus          */
#define G   2LL     /* generator (원시근)     */
#define Q  11LL     /* 위수: g^Q ≡ 1 (mod P) */

typedef long long ll;

/* ────────────────────────────────────────────
 * 수학 유틸리티
 * ──────────────────────────────────────────── */

ll mod_exp(ll base, ll exp, ll mod) {
    ll result = 1;
    base %= mod;
    if (base < 0) base += mod;
    while (exp > 0) {
        if (exp & 1) result = result * base % mod;
        exp >>= 1;
        base = base * base % mod;
    }
    return result;
}

ll mod_inv(ll a, ll p) {
    /* 페르마 소정리: a^(p-2) mod p */
    return mod_exp(a % p, p - 2, p);
}

/* 안전한 모듈러 뺄셈 (음수 방지) */
ll mod_sub(ll a, ll b, ll mod) {
    return ((a - b) % mod + mod) % mod;
}

/* ────────────────────────────────────────────
 * 구분선 출력 헬퍼
 * ──────────────────────────────────────────── */
void print_sep(void)  { printf("  %s\n", "─────────────────────────────────"); }
void print_dsep(void) { printf("%s\n",   "══════════════════════════════════════════"); }

/* ────────────────────────────────────────────
 * 시나리오 1: 정상 증명
 * Prover가 x를 알고 있는 경우
 * ──────────────────────────────────────────── */
void scenario_honest(ll x, ll Y) {
    printf("\n【 시나리오 1: 정상 증명 — Prover는 x를 알고 있음 】\n");
    print_sep();

    /* Step 1: Prover — commitment */
    ll r = rand() % (Q - 1) + 1;   /* r ∈ [1, Q-1] */
    ll R = mod_exp(G, r, P);

    printf("  [Prover]\n");
    printf("    r = %lld  (비밀 랜덤값, 절대 공개 안 함)\n", r);
    printf("    R = g^r mod p = %lld^%lld mod %lld = %lld\n", G, r, P, R);
    printf("    → Verifier에게 R = %lld 전송\n\n", R);

    /* Step 2: Verifier — challenge */
    ll c = rand() % (Q - 1) + 1;   /* c ∈ [1, Q-1] */

    printf("  [Verifier]\n");
    printf("    c = %lld  (랜덤 challenge)\n", c);
    printf("    → Prover에게 c = %lld 전송\n\n", c);

    /* Step 3: Prover — response */
    ll s = (r + c * x) % Q;        /* ← mod Q 필수! */

    printf("  [Prover]\n");
    printf("    s = (r + c·x) mod q\n");
    printf("      = (%lld + %lld·%lld) mod %lld\n", r, c, x, Q);
    printf("      = %lld\n", s);
    printf("    → Verifier에게 s = %lld 전송\n\n", s);

    /* Step 4: Verifier — verify */
    ll lhs = mod_exp(G, s, P);
    ll rhs = mod_exp(R, 1, P) * mod_exp(Y, c, P) % P;

    printf("  [Verifier] 검증\n");
    printf("    좌변: g^s mod p = %lld^%lld mod %lld = %lld\n", G, s, P, lhs);
    printf("    우변: R·Y^c mod p = %lld·%lld^%lld mod %lld = %lld\n", R, Y, c, P, rhs);

    if (lhs == rhs)
        printf("    결과: ✓ 검증 성공 — Prover는 x를 알고 있음\n");
    else
        printf("    결과: ✗ 검증 실패\n");
}

/* ────────────────────────────────────────────
 * 시나리오 2: 사기 시도
 * Prover가 x를 모르고 랜덤 s를 찍는 경우
 * ──────────────────────────────────────────── */
void scenario_cheat(ll Y) {
    printf("\n【 시나리오 2: 사기 시도 — Prover는 x를 모름 】\n");
    print_sep();

    /* 사기꾼 전략: s를 먼저 랜덤 선택, R을 역산 시도
     * → 하지만 c를 미리 모르므로 R을 제대로 만들 수 없음 */

    /* 단순히 랜덤 r로 R을 만들고 s를 찍는 경우 */
    ll fake_r = rand() % (Q - 1) + 1;
    ll R      = mod_exp(G, fake_r, P);

    printf("  [사기꾼 Prover]\n");
    printf("    x를 모르므로 fake_r = %lld 로 R 생성\n", fake_r);
    printf("    R = %lld 전송\n\n", R);

    /* Verifier가 c를 전송 — 사기꾼은 이걸 예측 못 함 */
    ll c = rand() % (Q - 1) + 1;

    printf("  [Verifier]\n");
    printf("    c = %lld 전송\n\n", c);

    /* 사기꾼: x 없이 s를 만들 수 없으므로 그냥 랜덤 s 전송 */
    ll fake_s = rand() % (Q - 1) + 1;

    printf("  [사기꾼 Prover]\n");
    printf("    x 모르므로 fake_s = %lld 랜덤 전송\n\n", fake_s);

    /* Verifier 검증 */
    ll lhs = mod_exp(G, fake_s, P);
    ll rhs = R * mod_exp(Y, c, P) % P;

    printf("  [Verifier] 검증\n");
    printf("    좌변: g^s mod p = %lld\n", lhs);
    printf("    우변: R·Y^c mod p = %lld\n", rhs);

    if (lhs == rhs)
        printf("    결과: (우연히 통과 — 확률 1/q)\n");
    else
        printf("    결과: ✗ 검증 실패 — 사기 탐지!\n");

    printf("\n  ※ 라운드를 t번 반복하면 사기 성공 확률 = (1/q)^t ≈ 0\n");
}

/* ────────────────────────────────────────────
 * 시나리오 3: r 재사용 공격
 * 같은 r을 두 번 쓰면 비밀키 x가 노출됨
 * ──────────────────────────────────────────── */
void scenario_reuse_attack(ll x, ll Y) {
    printf("\n【 시나리오 3: r 재사용 공격 → 비밀키 복구 】\n");
    print_sep();

    /* Prover가 실수로 같은 r을 두 번 사용 */
    ll r = rand() % (Q - 1) + 1;
    ll R = mod_exp(G, r, P);

    printf("  [Prover — 실수] 같은 r = %lld 을 두 번 사용\n\n", r);

    /* 1회 세션 */
    ll c1 = rand() % (Q - 1) + 1;
    ll s1 = (r + c1 * x) % Q;
    printf("  1회 세션: R = %lld, c1 = %lld, s1 = %lld\n", R, c1, s1);

    /* 2회 세션 — 같은 R (같은 r 사용) */
    ll c2;
    do { c2 = rand() % (Q - 1) + 1; } while (c2 == c1);  /* c2 ≠ c1 */
    ll s2 = (r + c2 * x) % Q;
    printf("  2회 세션: R = %lld, c2 = %lld, s2 = %lld\n\n", R, c2, s2);

    /* 공격자의 비밀키 복구
     *
     * s1 = r + c1·x  (mod q)
     * s2 = r + c2·x  (mod q)
     * ─────────────────────────
     * s1 - s2 = (c1 - c2)·x  (mod q)
     * x = (s1 - s2) · (c1 - c2)^(-1)  (mod q)
     */
    printf("  [공격자] 복구 과정:\n");
    printf("    s1 - s2 = %lld - %lld = %lld (mod %lld)\n",
           s1, s2, mod_sub(s1, s2, Q), Q);
    printf("    c1 - c2 = %lld - %lld = %lld (mod %lld)\n",
           c1, c2, mod_sub(c1, c2, Q), Q);

    ll numerator   = mod_sub(s1, s2, Q);
    ll denominator = mod_sub(c1, c2, Q);
    ll recovered_x = numerator * mod_inv(denominator, Q) % Q;

    printf("    x = (s1-s2)·(c1-c2)^(-1) mod q\n");
    printf("      = %lld · %lld^(-1) mod %lld\n", numerator, denominator, Q);
    printf("      = %lld · %lld mod %lld\n", numerator, mod_inv(denominator, Q), Q);
    printf("      = %lld\n\n", recovered_x);

    printf("  실제 비밀키 x = %lld\n", x);
    printf("  복구된 키     = %lld\n", recovered_x);

    if (recovered_x == x)
        printf("  결과: ✓ 비밀키 완전 복구 성공!\n");
    else
        printf("  결과: ✗ 복구 실패 (모듈러 범위 확인 필요)\n");

    printf("\n  ※ Sony PS3, 초기 Bitcoin 지갑에서 실제 발생한 사고\n");
}

/* ────────────────────────────────────────────
 * 메인
 * ──────────────────────────────────────────── */
int main(void) {
    srand((unsigned)time(NULL));

    print_dsep();
    printf("  Schnorr Protocol — Interactive ZKP 실습\n");
    print_dsep();

    /* 공개 파라미터 출력 */
    printf("\n[ 공개 파라미터 ]\n");
    printf("  p = %lld  (소수 modulus)\n", P);
    printf("  g = %lld  (generator)\n",    G);
    printf("  q = %lld  (g의 위수, g^q ≡ 1 mod p)\n\n", Q);

    /* 키 생성 */
    ll x = rand() % (Q - 1) + 1;      /* 비밀키: x ∈ [1, Q-1] */
    ll Y = mod_exp(G, x, P);           /* 공개키: Y = g^x mod p */

    printf("[ 키 생성 ]\n");
    printf("  비밀키 x = %lld  (Prover만 알고 있음)\n", x);
    printf("  공개키 Y = g^x mod p = %lld^%lld mod %lld = %lld\n\n", G, x, P, Y);

    /* 시나리오 실행 */
    scenario_honest(x, Y);
    print_dsep();

    scenario_cheat(Y);
    print_dsep();

    scenario_reuse_attack(x, Y);
    print_dsep();

    printf("\n[ 핵심 정리 ]\n");
    printf("  1. r은 매 세션마다 반드시 새로 생성\n");
    printf("  2. s = (r + c·x) mod q  ← mod q 필수\n");
    printf("  3. x를 모르면 c를 예측하기 전까지 유효한 s 생성 불가\n");
    printf("  4. r 재사용 시 단 2회 세션으로 비밀키 완전 노출\n\n");

    return 0;
}
