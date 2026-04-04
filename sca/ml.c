#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * Montgomery Ladder 예제
 * - 단순화를 위해 정수 그룹에서의 거듭제곱(x^k mod p)으로 시연
 * - ECC에서도 동일한 ladder 구조를 사용함
 */

typedef unsigned long long u64;
typedef unsigned __int128  u128;

/* 모듈러 곱셈 (오버플로 방지를 위해 __int128 사용) */
static u64 mulmod(u64 a, u64 b, u64 mod) {
    return (u128)a * b % mod;
}

/*
 * Montgomery Ladder: base^exp mod m
 *
 * R0 = 1      (항등원)
 * R1 = base
 * exp의 최상위 비트부터 순회하며:
 *   비트=0: R1 = R0*R1, R0 = R0*R0
 *   비트=1: R0 = R0*R1, R1 = R1*R1
 * 항상 동일한 횟수의 연산 수행 → 타이밍 일정
 */
u64 montgomery_ladder_powmod(u64 base, u64 exp, u64 mod) {
    u64 R0 = 1;
    u64 R1 = base % mod;

    /* 64비트 최상위 비트부터 순회 */
    for (int bit = 63; bit >= 0; bit--) {
        u64 b = (exp >> bit) & 1;

        /*
         * 조건 없는 연산: 비트 값으로 스왑을 제어
         * 분기(if/else) 없이 constant-time 구현
         */
        u64 mask = -(u64)b;          /* b=1 -> 0xFFFF..., b=0 -> 0x0000... */

        /* 조건부 스왑 (branchless) */
        u64 diff = (R0 ^ R1) & mask;
        R0 ^= diff;
        R1 ^= diff;

        /* 항상: R1 = R0*R1, R0 = R0*R0 */
        R1 = mulmod(R0, R1, mod);
        R0 = mulmod(R0, R0, mod);

        /* 다시 스왑 (원래 순서 복원) */
        diff = (R0 ^ R1) & mask;
        R0 ^= diff;
        R1 ^= diff;
    }

    return R0;
}

/*
 * 비교용: 일반 Double-and-Add (취약)
 * 비트가 1일 때만 추가 연산 → 타이밍 차이 발생
 */
u64 naive_powmod(u64 base, u64 exp, u64 mod) {
    u64 result = 1;
    u64 b = base % mod;

    while (exp > 0) {
        if (exp & 1)          /* ← 이 분기가 타이밍 차이를 만듦 */
            result = mulmod(result, b, mod);
        b = mulmod(b, b, mod);
        exp >>= 1;
    }

    return result;
}

/* 검증 */
int main(void) {
    /* 작은 소수 p=17로 테스트 */
    u64 base = 3, mod = 1000000007ULL;

    printf("=== Montgomery Ladder vs Naive ===\n\n");

    u64 exponents[] = {0, 1, 2, 10, 100, 12345678ULL, 999999999ULL};
    int n = sizeof(exponents) / sizeof(exponents[0]);

    for (int i = 0; i < n; i++) {
        u64 e   = exponents[i];
        u64 ml  = montgomery_ladder_powmod(base, e, mod);
        u64 nv  = naive_powmod(base, e, mod);
        char *ok = (ml == nv) ? "OK" : "MISMATCH";

        printf("  %llu^%llu mod %llu\n", base, e, mod);
        printf("    Montgomery Ladder : %llu\n", ml);
        printf("    Naive             : %llu\n", nv);
        printf("    결과              : %s\n\n", ok);
    }

    return 0;
}