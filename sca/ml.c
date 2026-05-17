#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/*
 * ============================================================
 *  Montgomery Ladder 예제 (타이밍 측정 포함 확장판)
 * ============================================================
 *  - 정수 그룹에서의 거듭제곱(base^exp mod m)으로 시연
 *  - ECC scalar multiplication 도 동일한 ladder 구조 사용
 *
 *  Part 1) 정확성 검증  : 두 구현의 결과가 같은가?
 *  Part 2) 타이밍 측정  : 두 구현의 "실행 시간"은 같은가?
 *
 *  핵심 교훈:
 *    결과는 같아야 정상이다 (같은 수학 연산).
 *    Montgomery Ladder의 가치는 "다른 답"이 아니라
 *    "같은 답을, 비밀이 새지 않는 방식으로" 계산하는 것이다.
 *
 *  빌드: gcc -O2 -o ladder ml.c
 *  실행: ./ladder
 * ============================================================
 */

typedef unsigned long long u64;
typedef unsigned __int128  u128;

/* 모듈러 곱셈 (오버플로 방지를 위해 __int128 사용) */
static u64 mulmod(u64 a, u64 b, u64 mod) {
    return (u128)a * b % mod;
}

/*
 * ------------------------------------------------------------
 *  Montgomery Ladder: base^exp mod m   (constant-time)
 * ------------------------------------------------------------
 *  R0 = 1      (항등원)
 *  R1 = base
 *  exp의 최상위 비트부터 순회하며:
 *    비트=0: R1 = R0*R1, R0 = R0*R0
 *    비트=1: R0 = R0*R1, R1 = R1*R1
 *  -> 비트 값과 무관하게 매번 동일한 연산을 수행
 *  -> 분기(if/else)도 branchless swap으로 제거
 */
u64 montgomery_ladder_powmod(u64 base, u64 exp, u64 mod) {
    u64 R0 = 1;
    u64 R1 = base % mod;

    /* 64비트 최상위 비트부터 순회 (항상 64회 반복) */
    for (int bit = 63; bit >= 0; bit--) {
        u64 b = (exp >> bit) & 1;

        /*
         * 조건 없는 연산: 비트 값으로 스왑을 제어
         * b=1 -> mask=0xFFFF...,  b=0 -> mask=0x0000...
         */
        u64 mask = -(u64)b;

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
 * ------------------------------------------------------------
 *  비교용: 일반 Double-and-Add  (취약 — 타이밍이 새어나감)
 * ------------------------------------------------------------
 *  - 비트가 1일 때만 곱셈을 추가로 수행 -> 시간이 지수에 의존
 *  - while 조건이 exp 의 비트길이에 의존 -> 반복 횟수도 노출
 */
u64 naive_powmod(u64 base, u64 exp, u64 mod) {
    u64 result = 1;
    u64 b = base % mod;

    while (exp > 0) {
        if (exp & 1)          /* <- 이 분기가 타이밍 차이를 만든다 */
            result = mulmod(result, b, mod);
        b = mulmod(b, b, mod);
        exp >>= 1;
    }

    return result;
}

/* exp 의 1-비트 개수 (Hamming weight) */
static int hamming_weight(u64 x) {
    int c = 0;
    while (x) { c += (int)(x & 1); x >>= 1; }
    return c;
}

/*
 * 한 지수를 iter 번 반복 실행한 평균 시간(ns) 측정.
 *  - volatile sink: -O2 가 호출을 통째로 제거하지 못하도록 결과를 누적
 *  - CLOCK_MONOTONIC: 시스템 시간 변경의 영향을 받지 않는 단조 증가 시계
 */
static double bench(u64 (*fn)(u64, u64, u64),
                    u64 base, u64 exp, u64 mod, int iter) {
    volatile u64 sink = 0;
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iter; i++)
        sink ^= fn(base, exp, mod);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    (void)sink;

    double ns = (double)(t1.tv_sec - t0.tv_sec) * 1e9
              + (double)(t1.tv_nsec - t0.tv_nsec);
    return ns / iter;
}

/* ============================================================
 *  Part 1) 정확성 검증
 * ============================================================ */
static void verify_correctness(u64 base, u64 mod) {
    printf("============================================\n");
    printf(" Part 1)  정확성 검증 — 결과가 같아야 정상\n");
    printf("============================================\n\n");

    u64 exps[] = {0, 1, 2, 10, 100, 12345678ULL, 999999999ULL};
    int n = (int)(sizeof(exps) / sizeof(exps[0]));

    int all_ok = 1;
    for (int i = 0; i < n; i++) {
        u64 e  = exps[i];
        u64 ml = montgomery_ladder_powmod(base, e, mod);
        u64 nv = naive_powmod(base, e, mod);
        const char *ok = (ml == nv) ? "OK" : "MISMATCH";
        if (ml != nv) all_ok = 0;

        printf("  %llu^%llu mod %llu\n", base, e, mod);
        printf("    Montgomery Ladder : %llu\n", ml);
        printf("    Naive             : %llu\n", nv);
        printf("    결과              : %s\n\n", ok);
    }

    printf("  -> 두 구현은 %s 동일한 값을 계산한다.\n",
           all_ok ? "모든 경우" : "(오류!)");
    printf("     같은 결과가 나오는 것이 '정상'이며,\n");
    printf("     이것이 Montgomery Ladder 구현이 옳다는 검증이다.\n\n");
}

/* ============================================================
 *  Part 2) 타이밍 측정 — 무엇이 다른가?
 * ============================================================ */
static void measure_timing(u64 base, u64 mod) {
    printf("============================================\n");
    printf(" Part 2)  타이밍 측정 — 실행 시간은 다르다\n");
    printf("============================================\n\n");

    /*
     * 모든 지수의 비트길이는 64로 동일하게 고정(최상위 비트 set).
     * 오직 Hamming weight(1-비트 개수)만 다르게 하여,
     * "naive 의 시간이 비밀 지수의 1-비트 수에 의존한다"는 점을
     * 깨끗하게 분리해서 보여준다.
     */
    u64 exps[] = {
        0x8000000000000000ULL,  /* HW = 1  */
        0x8000000000000001ULL,  /* HW = 2  */
        0x80000000FFFFFFFFULL,  /* HW = 33 */
        0xFFFFFFFFFFFFFFFEULL,  /* HW = 63 */
        0xFFFFFFFFFFFFFFFFULL,  /* HW = 64 */
    };
    int n = (int)(sizeof(exps) / sizeof(exps[0]));
    int ITER = 200000;

    /* 워밍업: 캐시/분기예측기를 안정 상태로 (측정 노이즈 감소) */
    for (int i = 0; i < n; i++) {
        bench(naive_powmod,            base, exps[i], mod, 5000);
        bench(montgomery_ladder_powmod, base, exps[i], mod, 5000);
    }

    printf("  %-9s | %-22s | %-22s\n",
           "HW(exp)", "Naive (ns/call)", "Montgomery (ns/call)");
    printf("  ----------+------------------------+----------------------\n");

    double naive_min = 1e18, naive_max = 0.0;
    double ml_min    = 1e18, ml_max    = 0.0;

    for (int i = 0; i < n; i++) {
        int hw = hamming_weight(exps[i]);
        double tn = bench(naive_powmod,            base, exps[i], mod, ITER);
        double tm = bench(montgomery_ladder_powmod, base, exps[i], mod, ITER);

        printf("  %-9d | %-22.2f | %-22.2f\n", hw, tn, tm);

        if (tn < naive_min) naive_min = tn;
        if (tn > naive_max) naive_max = tn;
        if (tm < ml_min)    ml_min    = tm;
        if (tm > ml_max)    ml_max    = tm;
    }

    double naive_spread = (naive_max - naive_min) / naive_min * 100.0;
    double ml_spread    = (ml_max    - ml_min)    / ml_min    * 100.0;

    printf("\n");
    printf("  Naive      : %.1f ~ %.1f ns   편차 %.1f%%\n",
           naive_min, naive_max, naive_spread);
    printf("               -> 실행 시간이 지수의 Hamming weight 를 노출한다.\n");
    printf("                  공격자는 시간만 측정해도 비밀 비트 정보를 얻는다.\n");
    printf("                  (2003 Boneh & Brumley, OpenSSL RSA timing attack)\n\n");
    printf("  Montgomery : %.1f ~ %.1f ns   편차 %.1f%%\n",
           ml_min, ml_max, ml_spread);
    printf("               -> 지수와 무관하게 일정 (편차는 측정 노이즈 수준).\n");
    printf("                  비밀이 실행 시간으로 새어나가지 않는다.\n\n");

    printf("  [관찰] Montgomery Ladder 가 오히려 더 느리다.\n");
    printf("         항상 64회 반복 x (mulmod 2회 + branchless swap) 을\n");
    printf("         수행하기 때문이다. 빠른 경로(early exit, 분기)를\n");
    printf("         일부러 포기하는 것 — 이것이 보안<->성능 트레이드오프이며\n");
    printf("         constant-time 구현의 본질이다.\n\n");
}

int main(void) {
    /* base, 그리고 충분히 큰 소수 modulus */
    u64 base = 3;
    u64 mod  = 1000000007ULL;

    printf("\n");
    printf("################################################\n");
    printf("#  Montgomery Ladder vs Naive Double-and-Add    #\n");
    printf("#  결과는 같다. 그러나 '시간'은 다르다.         #\n");
    printf("################################################\n\n");

    verify_correctness(base, mod);
    measure_timing(base, mod);

    return 0;
}
