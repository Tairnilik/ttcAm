#include <stdint.h>

// Экспортируем функцию для Python
__declspec(dllexport) int check_l7_protocol(const uint8_t* data, int data_len) {
    if (data_len == 0) return 0; // no_data
    
    uint8_t header_type=data[0];

    if (data_len >= 2 && data[0] == 0x16 && data[1] == 0x03) {
        return 1; // tls
    } else if (data_len >= 4) {
        if ((data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') ||
            (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') ||
            (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && data[4] == '/' && data[5] == '1' && data[6] == '.')) {
            return 2; // http
        }
    } else if ((header_type & 0x80) && data_len >=5) {
        if (data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00 && data[4] == 0x01) {
            uint8_t packet_type = (header_type & 0x30) >> 4;

            if (packet_type == 0) {
                return 3; // quic_initial
            } else if (packet_type == 2) 
            {
                return 4; // quic_handshake
            }
            return 5; // quic_other_long
        }
    }

    return 0; // unknown
}