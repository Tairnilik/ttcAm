#include <stdint.h>

__declspec(dllexport) void badseq(uint8_t* packet_bytes, int ip_header_len, uint32_t offset) {
    // первые 4 байта TCP заголовка
    uint32_t* seq = (uint32_t*)(packet_bytes + ip_header_len + 4);
    *seq = *seq + offset; // сдвигаем seq_num
}

__declspec(dllexport) void badsum(uint8_t* packet_bytes, int ip_header_len) {
    // Обычно cksum находится на 16-м байте TCP-заголовка
    packet_bytes[ip_header_len + 16] = 0;
    packet_bytes[ip_header_len + 17] = 0;
}

__declspec(dllexport) void md5sig(uint8_t* packet_bytes, int packet_len) {
    int ip_header_len = (packet_bytes[0] & 0x0F) * 4;
    uint8_t* tcp_header = packet_bytes + ip_header_len;
    
    int option_offset = ip_header_len+20;

    // MD5 Signature Option
    packet_bytes[option_offset + 0] = 19;
    // 2 байта заголовок + 16 байт подпись
    packet_bytes[option_offset + 1] = 18;
    
    for (int i = 0; i < 16; i++) {
        packet_bytes[option_offset + 2 + i] = 'A'; 
    }

    // выровняем длину опции(чтобы она была кратно 4 байтам)
    packet_bytes[option_offset + 18] = 1;
    packet_bytes[option_offset + 19] = 1;
}