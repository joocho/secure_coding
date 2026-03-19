#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void memory_leak_demo() {
    char *ptr = (char *)malloc(100);
    strcpy(ptr, "Hello, Static Analysis!");
    // free(ptr); // 의도적인 메모리 누수
}

void buffer_overflow_demo(char *input) {
    char buffer[10];
    // 입력값의 길이를 체크하지 않아 버퍼 오버플로우 위험
    strcpy(buffer, input); 
    printf("Buffer: %s\n", buffer);
}

void uninitialized_variable_demo() {
    int x;
    // x가 초기화되지 않은 상태에서 사용됨
    if (x > 10) { 
        printf("X is large\n");
    }
}

int divide_by_zero_demo(int a) {
    int b = 0;
    return a / b; // 0으로 나누기 오류
}

int main(int argc, char **argv) {
    memory_leak_demo();
    
    if (argc > 1) {
        buffer_overflow_demo(argv[1]);
    }

    uninitialized_variable_demo();
    
    int result = divide_by_zero_demo(10);
    printf("Result: %d\n", result);

    return 0;
}
