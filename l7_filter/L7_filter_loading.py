# filter_l7 mode 

def l7(data):
    if len(data)==0: return "no_data"
    
    header_type = data[0]
    
    if data[0] == 0x16 and data[1]==0x03:
        return "tls"
    elif data.startswith((b"GET ", b"POST ", b"HTTP/1.")):
        return "http"
    elif (header_type & 0x80):
        quic_version = data[1:5]
        if quic_version == b"\x00\x00\x00\x01":
            packet_type = (header_type & 0x30) >> 4
            if packet_type == 0:
                return "quic_initial"
            elif packet_type == 2:
                return "quic_handshake"
            return "quic_other_long"
    else:
        return "unknown"

# usage
# from l7_filter.l7_filter_loading import l7        
# with pydivert.WinDivert("tcp and outbound") as w:
#    for packet in w:
#        protocol=l7(packet.payload)
#        if protocol=="tls"/"http"/"MTProto"/"unknown":
#           do something