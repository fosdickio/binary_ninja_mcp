#include <stdio.h>
#include <stdint.h>
#include <string.h>

static inline uint8_t rol8(uint8_t x, unsigned r) {
    r &= 7;
    return (uint8_t)(((x << r) | (x >> (8 - r))) & 0xFF);
}

// 對輸入做位移 + 滾動 XOR 的目標結果（作者預先計算好）
// Shift + rolling XOR applied to the input with the target result
static const uint8_t EXPECTED[32] = {
    0x1c, 0x2e, 0x74, 0xd0, 0x52, 0xe2, 0xd4, 0x86,
    0x0e, 0xa6, 0xec, 0x39, 0x75, 0x21, 0x17, 0x8d,
    0x13, 0x68, 0x88, 0xe2, 0x00, 0xa0, 0x11, 0x17,
    0x3f, 0x60, 0x90, 0x51, 0xb3, 0x68, 0x00, 0x02
};

int main(void) {
    char buf[256];
    puts("Enter flag:");
    if (!fgets(buf, sizeof(buf), stdin)) {
        puts("Read error");
        return 1;
    }

    // 去除換行
    size_t n = strcspn(buf, "\r\n");
    buf[n] = '\0';

    // 簡單長度與格式檢查（避免垃圾輸入）
    if (n != 32 || strncmp(buf, "FLAG{", 5) != 0 || buf[n-1] != '}') {
        puts("Nope");
        return 1;
    }

    // 轉換並比對
    uint8_t acc[32];
    for (size_t i = 0; i < n; i++) {
        uint8_t b = (uint8_t)buf[i];
        b ^= (uint8_t)(0x5A + i);
        b = rol8(b, (unsigned)(i & 7));
        acc[i] = b;
    }

    if (memcmp(acc, EXPECTED, 32) == 0) {
        puts("Correct! 🎉");
        return 0;
    } else {
        puts("Nope");
        return 1;
    }
}

