/*
 * fuzz_honggfuzz.c  —  Honggfuzz harness (HF_ITER / libhfuzz 방식)
 * ─────────────────────────────────────────────────────────────────
 *  빌드 (honggfuzz 소스 내 hfuzz-clang 래퍼 사용):
 *    hfuzz-clang -g -O1 -fsanitize=address \
 *                fuzz_honggfuzz.c vulnerable_lib.c \
 *                -o fuzz_honggfuzz
 *
 *  초기 코퍼스 만들기:
 *    mkdir -p corpus_hf seeds_hf
 *    echo -n "HEADER:test" > seeds_hf/seed1
 *    printf '\x01\x03abc' > seeds_hf/seed2
 *
 *  실행 (멀티스레드, 4 병렬):
 *    honggfuzz -i seeds_hf -W corpus_hf -n 4 \
 *              --sanitizers -- ./fuzz_honggfuzz
 *
 *  Intel PT 하드웨어 커버리지 사용 (Linux + 지원 CPU):
 *    honggfuzz -i seeds_hf -W corpus_hf -n 4 \
 *              --linux_perf_ipt -- ./fuzz_honggfuzz
 *
 *  크래시 확인:
 *    ls corpus_hf/  (HONGGFUZZ.REPORT.TXT 참조)
 * ─────────────────────────────────────────────────────────────────
 */

#include "vulnerable_lib.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Honggfuzz in-process 방식: HF_ITER 매크로로 반복 루프.
 * hfuzz-clang 으로 빌드하면 libhfuzz 가 자동 링크됨.
 */

/* libhfuzz 헤더 (honggfuzz 설치 경로에 있음) */
extern int HF_ITER(const uint8_t **buf_ptr, size_t *len_ptr);

int main(void)
{
    const uint8_t *data;
    size_t         size;

    /* HF_ITER 가 0 을 반환하면 퍼징 종료 */
    while (HF_ITER(&data, &size)) {
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

    return 0;
}
