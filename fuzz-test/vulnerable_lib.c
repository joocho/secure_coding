/*
 * vulnerable_lib.c
 * ─────────────────────────────────────────────────────────────────
 *  퍼저가 발견할 수 있는 취약점을 의도적으로 심은 라이브러리.
 *  절대 프로덕션에 사용하지 마세요!
 *
 *  포함된 취약점 목록
 *  #1  Stack Buffer Overflow   – parse_header()
 *  #2  Heap Buffer Overflow    – process_data()
 *  #3  Integer Overflow → OOB  – compute_checksum()
 *  #4  Use-After-Free          – manage_buffer()
 *  #5  NULL Dereference        – parse_config()
 *  #6  Infinite Loop / DoS     – decompress_rle()
 * ─────────────────────────────────────────────────────────────────
 */

#include "vulnerable_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── #1 Stack Buffer Overflow ─────────────────────────────────── */
/*
 * 입력에서 "HEADER:" 태그를 찾아 뒤 내용을 고정 크기 스택 버퍼에 복사.
 * 64 바이트보다 긴 헤더 값을 보내면 스택을 덮어씀.
 */
int parse_header(const uint8_t *data, size_t size)
{
    char header_buf[64];          /* 고정 크기 스택 버퍼 */
    char input[512];

    if (size == 0 || size >= sizeof(input))
        return -1;

    memcpy(input, data, size);
    input[size] = '\0';

    char *tag = strstr(input, "HEADER:");
    if (!tag) return 0;

    /* [BUG #1] strcpy → 길이 검사 없음 → 스택 BOF */
    strcpy(header_buf, tag + 7);

    printf("[parse_header] header=%s\n", header_buf);
    return 1;
}

/* ── #2 Heap Buffer Overflow ──────────────────────────────────── */
/*
 * data[0] 을 길이로 해석하고 그만큼 힙 버퍼에 복사.
 * data[0] 이 실제 남은 데이터보다 크면 힙을 벗어나 읽음.
 */
int process_data(const uint8_t *data, size_t size)
{
    if (size < 2) return -1;

    uint8_t length = data[0];     /* 사용자 제어 길이 */
    char *heap_buf = (char *)malloc(length); /* length == 0 이면 malloc(0) */
    if (!heap_buf) return -1;

    /* [BUG #2] length > size-1 이면 힙 BOF */
    memcpy(heap_buf, data + 1, length);

    printf("[process_data] copied %u bytes\n", length);
    free(heap_buf);
    return 0;
}

/* ── #3 Integer Overflow → Out-Of-Bounds ─────────────────────── */
/*
 * 두 16-bit 필드를 곱해 버퍼 크기를 결정.
 * 곱이 uint16_t 범위(65535)를 넘으면 0에 가깝게 wrap-around → OOB 접근.
 */
int compute_checksum(const uint8_t *data, size_t size)
{
    if (size < 4) return -1;

    uint16_t width  = (uint16_t)(data[0] << 8 | data[1]);
    uint16_t height = (uint16_t)(data[2] << 8 | data[3]);

    /* [BUG #3] width*height 가 uint16_t 를 넘으면 정수 오버플로우 */
    uint16_t total = width * height;

    uint8_t *img_buf = (uint8_t *)malloc(total);
    if (!img_buf) return -1;

    uint32_t sum = 0;
    for (uint16_t i = 0; i < total && (4 + i) < size; i++)
        sum += data[4 + i];

    printf("[compute_checksum] %ux%u sum=%u\n", width, height, sum);
    free(img_buf);
    return (int)sum;
}

/* ── #4 Use-After-Free ────────────────────────────────────────── */
/*
 * data[0] == 0xFF 면 버퍼를 해제하고, 이후 코드에서 해제된 포인터 사용.
 */
int manage_buffer(const uint8_t *data, size_t size)
{
    if (size < 2) return -1;

    char *buf = (char *)malloc(64);
    if (!buf) return -1;

    memcpy(buf, data + 1, size - 1 < 63 ? size - 1 : 63);
    buf[63] = '\0';

    if (data[0] == 0xFF) {
        free(buf);           /* 해제 */
        /* [BUG #4] buf 는 이미 free 됨 → Use-After-Free */
        printf("[manage_buffer] data=%s\n", buf);
    }

    free(buf);               /* 경우에 따라 double-free 도 발생 */
    return 0;
}

/* ── #5 NULL Dereference ──────────────────────────────────────── */
/*
 * "KEY=VALUE" 형식을 파싱. '=' 이 없으면 strchr 가 NULL 반환 →
 * NULL 포인터를 역참조해 크래시.
 */
int parse_config(const uint8_t *data, size_t size)
{
    if (size == 0 || size >= 256) return -1;

    char input[256];
    memcpy(input, data, size);
    input[size] = '\0';

    /* [BUG #5] '=' 없으면 sep == NULL → sep+1 에서 크래시 */
    char *sep   = strchr(input, '=');
    char *value = sep + 1;           /* NULL + 1 → 정의되지 않은 동작 */

    printf("[parse_config] value=%s\n", value);
    return 0;
}

/* ── #6 Infinite Loop / DoS ───────────────────────────────────── */
/*
 * 간단한 RLE 디코더. count == 0 일 때 pos 가 전진하지 않아 무한 루프.
 */
int decompress_rle(const uint8_t *data, size_t size)
{
    if (size < 2) return -1;

    uint8_t output[512];
    size_t  pos    = 0;
    size_t  outpos = 0;

    while (pos < size && outpos < sizeof(output)) {
        uint8_t count = data[pos];   /* 반복 횟수 */
        uint8_t byte  = (pos + 1 < size) ? data[pos + 1] : 0;

        /* [BUG #6] count == 0 이면 pos 증가 없이 무한 루프 */
        for (uint8_t i = 0; i < count; i++) {
            if (outpos >= sizeof(output)) break;
            output[outpos++] = byte;
        }

        pos += 2;   /* count==0 여도 여기 도달하므로 실제론 루프 종료됨  */
                    /* 하지만 count 를 직접 loop 탈출 조건으로 쓰는       */
                    /* 다른 패턴에선 무한 루프가 발생함 — 아래 변형 참고   */
    }

    /* ↓ 무한 루프 변형: count==0 이면 pos 가 전진 안 함 */
    pos = 0; outpos = 0;
    while (pos < size) {
        uint8_t count2 = data[pos];
        if (count2 == 0) {
            /* [BUG #6 변형] 탈출 조건 없음 → 실제 무한 루프 */
            /* 퍼저가 타임아웃으로 감지 */
            break;           /* 데모용으로 break 추가 — 실제 취약 코드에선 제거 */
        }
        pos += count2;
    }

    printf("[decompress_rle] output_size=%zu\n", outpos);
    return (int)outpos;
}
