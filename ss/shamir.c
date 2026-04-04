/*
 * Shamir's Secret Sharing - 실습용 구현
 *
 * 컴파일: gcc -o shamir shamir.c
 * 실행:   ./shamir
 *
 * 주의: 실습/교육 목적 코드입니다.
 *       실제 보안 시스템에는 GMP 등 big integer 라이브러리와
 *       cryptographically secure RNG를 사용하세요.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ────────────────────────────────────────────
 * 상수 설정
 * ──────────────────────────────────────────── */

/* 소수 p: 모든 연산은 mod p 로 수행
 * 실습용으로 작은 소수 사용 (실제 구현은 2^127-1 등 사용)
 * 비밀값 S 는 반드시 p 보다 작아야 함 */
#define PRIME 1000000007LL   /* 10^9 + 7, 자주 쓰이는 소수 */

typedef long long ll;

/* ────────────────────────────────────────────
 * 수학 유틸리티
 * ──────────────────────────────────────────── */

/* 모듈러 지수: base^exp mod m
 * 반복 제곱법(fast exponentiation) 사용 */
ll mod_exp(ll base, ll exp, ll mod) {
    ll result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1)
            result = result * base % mod;
        exp >>= 1;
        base = base * base % mod;
    }
    return result;
}

/* 모듈러 역원: a^(-1) mod p
 * 페르마 소정리: a^(p-1) ≡ 1 (mod p)
 *                a^(-1)  ≡ a^(p-2) (mod p)
 * 조건: p는 소수, gcd(a, p) = 1 */
ll mod_inv(ll a, ll p) {
    return mod_exp(a % p, p - 2, p);
}

/* 안전한 모듈러 덧셈 (음수 방지) */
ll mod_add(ll a, ll b, ll p) {
    return ((a % p) + (b % p) + p) % p;
}

/* 안전한 모듈러 곱셈 */
ll mod_mul(ll a, ll b, ll p) {
    return (a % p) * (b % p) % p;
}

/* ────────────────────────────────────────────
 * 조각(Share) 구조체
 * ──────────────────────────────────────────── */
typedef struct {
    ll x;   /* x 좌표 (참여자 번호, 1부터 시작) */
    ll y;   /* y 좌표 = f(x)                   */
} Share;

/* ────────────────────────────────────────────
 * 비밀 분산 (Split)
 *
 * 다항식 f(x) = S + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
 * 각 참여자 i 에게 (i, f(i)) 전달
 * ──────────────────────────────────────────── */
void split_secret(ll secret, int k, int n, Share shares[]) {
    if (secret >= PRIME) {
        printf("[오류] 비밀값이 소수 p(%lld)보다 크거나 같습니다.\n", (ll)PRIME);
        exit(1);
    }

    /* k-1 개의 랜덤 계수 생성 */
    ll *coeffs = (ll *)malloc(k * sizeof(ll));
    coeffs[0] = secret;  /* 상수항 = 비밀값 */

    printf("  다항식 계수: f(x) = %lld", secret);
    for (int i = 1; i < k; i++) {
        coeffs[i] = rand() % (PRIME - 1) + 1;  /* 1 ~ PRIME-1 */
        printf(" + %lld·x^%d", coeffs[i], i);
    }
    printf("\n\n");

    /* 각 참여자에게 f(i) 계산 후 전달 */
    for (int i = 1; i <= n; i++) {
        ll x = (ll)i;
        ll y = 0;
        ll x_pow = 1;  /* x^j */

        for (int j = 0; j < k; j++) {
            y = mod_add(y, mod_mul(coeffs[j], x_pow, PRIME), PRIME);
            x_pow = mod_mul(x_pow, x, PRIME);
        }

        shares[i - 1].x = x;
        shares[i - 1].y = y;
    }

    free(coeffs);
}

/* ────────────────────────────────────────────
 * 비밀 복구 (Reconstruct)
 *
 * Lagrange 보간법:
 *   L(0) = Σ yᵢ · Π (0 - xⱼ)/(xᵢ - xⱼ)   (j ≠ i)
 *
 * mod p 위에서:
 *   분자: Π (-xⱼ) mod p  =  Π (p - xⱼ) mod p
 *   분모: Π (xᵢ - xⱼ) mod p  →  역원으로 나눗셈 처리
 * ──────────────────────────────────────────── */
ll reconstruct_secret(Share shares[], int k) {
    ll secret = 0;

    for (int i = 0; i < k; i++) {
        ll xi = shares[i].x;
        ll yi = shares[i].y;

        ll numerator   = 1;
        ll denominator = 1;

        for (int j = 0; j < k; j++) {
            if (j == i) continue;

            ll xj = shares[j].x;

            /* 분자: (0 - xj) mod p = (p - xj) mod p */
            numerator = mod_mul(numerator, (PRIME - xj) % PRIME, PRIME);

            /* 분모: (xi - xj) mod p */
            ll diff = (xi - xj % PRIME + PRIME) % PRIME;
            denominator = mod_mul(denominator, diff, PRIME);
        }

        /* yᵢ · (numerator / denominator) mod p */
        ll term = mod_mul(yi, mod_mul(numerator, mod_inv(denominator, PRIME), PRIME), PRIME);
        secret = mod_add(secret, term, PRIME);
    }

    return secret;
}

/* ────────────────────────────────────────────
 * 출력 헬퍼
 * ──────────────────────────────────────────── */
void print_shares(Share shares[], int n) {
    printf("  %-10s  %-20s\n", "참여자", "조각 (x, y)");
    printf("  %-10s  %-20s\n", "--------", "--------------------");
    for (int i = 0; i < n; i++) {
        printf("  %-10d  (%lld, %lld)\n", i + 1, shares[i].x, shares[i].y);
    }
}

/* ────────────────────────────────────────────
 * 메인
 * ──────────────────────────────────────────── */
int main(void) {
    srand((unsigned)time(NULL));  /* 시드 초기화 */

    printf("==============================================\n");
    printf("   Shamir's Secret Sharing 실습\n");
    printf("==============================================\n\n");

    /* ── 파라미터 설정 ── */
    ll secret = 1234;   /* 비밀값 */
    int k = 3;          /* 복구에 필요한 최소 조각 수 */
    int n = 5;          /* 총 조각 수 */

    printf("비밀값 S = %lld\n", secret);
    printf("설정: (%d, %d) — %d명 중 %d명 이상 필요\n\n", k, n, n, k);

    /* ── 1단계: 비밀 분산 ── */
    printf("[ 1단계: 비밀 분산 ]\n");
    Share all_shares[n];
    split_secret(secret, k, n, all_shares);
    printf("  생성된 조각:\n");
    print_shares(all_shares, n);

    /* ── 2단계: 정상 복구 (k개 조각 사용) ── */
    printf("\n[ 2단계: 정상 복구 — 참여자 1, 3, 5 사용 ]\n");
    Share selected[3] = { all_shares[0], all_shares[2], all_shares[4] };
    ll recovered = reconstruct_secret(selected, k);
    printf("  복구된 비밀값: %lld %s\n", recovered,
           recovered == secret ? "✓ (일치)" : "✗ (불일치!)");

    /* ── 3단계: 조각 부족 — 복구 실패 시연 ── */
    printf("\n[ 3단계: 조각 부족 — 참여자 1, 2만 사용 (k-1개) ]\n");
    Share insufficient[2] = { all_shares[0], all_shares[1] };
    /* k=2로 보간하면 1차 다항식이 되어 엉뚱한 값 복구 */
    ll wrong = reconstruct_secret(insufficient, 2);
    printf("  복구된 값: %lld %s\n", wrong,
           wrong == secret ? "(우연히 일치)" : "✗ (다른 값 — 복구 실패)");
    printf("  ※ k-1개로는 비밀값에 대한 정보를 얻을 수 없습니다.\n");

    /* ── 4단계: 가짜 조각 — 오염 시연 ── */
    printf("\n[ 4단계: 가짜 조각 제출 — Bob이 y값 조작 ]\n");
    Share tampered[3] = { all_shares[0], all_shares[1], all_shares[2] };
    printf("  원본 조각[1]: (%lld, %lld)\n", tampered[1].x, tampered[1].y);
    tampered[1].y = (tampered[1].y + 999) % PRIME;  /* 조작 */
    printf("  조작 조각[1]: (%lld, %lld)\n", tampered[1].x, tampered[1].y);
    ll corrupted = reconstruct_secret(tampered, k);
    printf("  복구된 값: %lld %s\n", corrupted,
           corrupted == secret ? "(우연히 일치)" : "✗ (오염된 값)");
    printf("  ※ VSS(Verifiable Secret Sharing) 없이는 탐지 불가!\n");

    /* ── 5단계: 다른 조합으로도 복구 가능 ── */
    printf("\n[ 5단계: 다른 조합 — 참여자 2, 4, 5 사용 ]\n");
    Share combo2[3] = { all_shares[1], all_shares[3], all_shares[4] };
    ll recovered2 = reconstruct_secret(combo2, k);
    printf("  복구된 비밀값: %lld %s\n", recovered2,
           recovered2 == secret ? "✓ (일치)" : "✗ (불일치!)");

    printf("\n==============================================\n");
    printf("  실습 완료\n");
    printf("==============================================\n");

    return 0;
}
