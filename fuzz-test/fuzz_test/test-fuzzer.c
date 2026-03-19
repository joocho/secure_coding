#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 4 &&
        data[0] == 'F' &&
        data[1] == 'U' &&
        data[2] == 'Z' &&
        data[3] == 'Z') {
        __builtin_trap();  // 크래시 유발 지점
    }
    return 0;
}
