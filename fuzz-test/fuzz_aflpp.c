/*
 * fuzz_aflpp.c  —  AFL++ harness (stdin / __AFL_FUZZ_TESTCASE_BUF 방식)
 * ─────────────────────────────────────────────────────────────────
 *  빌드 (AFL++ 컴파일러 래퍼 사용):
 *    afl-clang-fast -g -O1 -fsanitize=address \
 *                   fuzz_aflpp.c vulnerable_lib.c \
 *                   -o fuzz_aflpp
 *
 *  초기 코퍼스 만들기:
 *    mkdir -p corpus_afl seeds_afl
 *    echo -n "HEADER:hello" > seeds_afl/seed1
 *    printf '\x00\x05hello'  > seeds_afl/seed2
 *    printf '\x00\x01\x00\x01\xff' > seeds_afl/seed3
 *
 *  실행:
 *    afl-fuzz -i seeds_afl -o corpus_afl -- ./fuzz_aflpp
 *
 *  병렬 실행 (마스터 1 + 슬레이브 3):
 *    afl-fuzz -i seeds_afl -o corpus_afl -M main   -- ./fuzz_aflpp &
 *    afl-fuzz -i seeds_afl -o corpus_afl -S slave1 -- ./fuzz_aflpp &
 *    afl-fuzz -i seeds_afl -o corpus_afl -S slave2 -- ./fuzz_aflpp &
 *
 *  크래시 확인:
 *    ls corpus_afl/main/crashes/
 * ─────────────────────────────────────────────────────────────────
 */

#include "vulnerable_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * AFL++ persistent mode 매크로.
 * __AFL_FUZZ_TESTCASE_BUF / __AFL_FUZZ_TESTCASE_LEN 를 쓰면
 * 프로세스를 재시작하지 않아 throughput 이 크게 오름.
 */
#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int main(void)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    /* ── Persistent mode (afl-clang-fast 로 빌드한 경우) ── */
    __AFL_INIT();

    uint8_t *data = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        size_t size = __AFL_FUZZ_TESTCASE_LEN;
        if (size < 1) continue;

        uint8_t selector = data[0] % 6;
        const uint8_t *payload = data + 1;
        size_t         psize   = size - 1;

        switch (selector) {
            case 0: parse_header(payload, psize);      break;
            case 1: process_data(payload, psize);      break;
            case 2: compute_checksum(payload, psize);  break;
            case 3: manage_buffer(payload, psize);     break;
            case 4: parse_config(payload, psize);      break;
            case 5: decompress_rle(payload, psize);    break;
        }
    }

#else
    /* ── 일반 stdin 모드 (afl-gcc 또는 일반 clang/gcc) ── */
    uint8_t buf[4096];
    size_t  size = fread(buf, 1, sizeof(buf), stdin);

    if (size < 1) return 0;

    uint8_t selector = buf[0] % 6;
    const uint8_t *payload = buf + 1;
    size_t         psize   = size - 1;

    switch (selector) {
        case 0: parse_header(payload, psize);      break;
        case 1: process_data(payload, psize);      break;
        case 2: compute_checksum(payload, psize);  break;
        case 3: manage_buffer(payload, psize);     break;
        case 4: parse_config(payload, psize);      break;
        case 5: decompress_rle(payload, psize);    break;
    }
#endif

    return 0;
}
