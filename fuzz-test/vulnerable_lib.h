#ifndef VULNERABLE_LIB_H
#define VULNERABLE_LIB_H

#include <stdint.h>
#include <stddef.h>

/* 취약점이 심어진 함수들 */
int parse_header(const uint8_t *data, size_t size);      /* #1 Stack BOF   */
int process_data(const uint8_t *data, size_t size);      /* #2 Heap BOF    */
int compute_checksum(const uint8_t *data, size_t size);  /* #3 Int Overflow */
int manage_buffer(const uint8_t *data, size_t size);     /* #4 UAF          */
int parse_config(const uint8_t *data, size_t size);      /* #5 NULL Deref   */
int decompress_rle(const uint8_t *data, size_t size);    /* #6 Inf Loop     */

#endif /* VULNERABLE_LIB_H */
