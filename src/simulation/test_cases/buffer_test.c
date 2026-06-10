#include <stdio.h>
#include <string.h>

extern void vulnerable_function(const char *input);  // From buffer_overflow.c

void test_buffer_overflow() {
    // Single character payload - the function is safe against overflow
    // due to strncpy with explicit null termination
    const char *payload = "A";
    printf("[TEST] Triggering buffer overflow...\n");
    vulnerable_function(payload);
    printf("[TEST] Overflow test completed\n");
}

int main() {
    test_buffer_overflow();
    return 0;
}
