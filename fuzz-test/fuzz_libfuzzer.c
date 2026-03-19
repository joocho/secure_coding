/*
 * fuzz_libfuzzer.c  —  libFuzzer harness
 * ─────────────────────────────────────────────────────────────────
 *  빌드:
 *    clang -g -O1 -fsanitize=address,fuzzer \
 *          fuzz_libfuzzer.c vulnerable_lib.c \
 *          -o fuzz_libfuzzer
 *
 *  실행:
 *    mkdir -p corpus_libfuzzer
 *    ./fuzz_libfuzzer corpus_libfuzzer/ -max_len=512 -jobs=4
 *
 *  크래시 재현:
 *    ./fuzz_libfuzzer crash-<hash>
 * ─────────────────────────────────────────────────────────────────
 */

#include "vulnerable_lib.h"
#include <stdint.h>
#include <stddef.h>

/*
 * libFuzzer 진입점.
 * 퍼저가 생성한 data/size 를 각 취약 함수에 차례로 전달한다.
 * data[0] 을 "라우터 바이트"로 사용해 어느 함수를 호출할지 결정함.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    /* 첫 바이트로 분기 */
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

    return 0;
}
