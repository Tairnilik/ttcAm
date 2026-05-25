function analyze_packet(packet)
    if packet.payload_len>packet.args.split_pos then
        if packet.payload_len>=1200 then -- обычно quic пакет имеет больше 1200 байтов
            return "MODIFY_UDPLEN"
        else
            return "PASS"
        end
    else
        return "PASS"
    end
end