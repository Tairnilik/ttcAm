function analyze_packet(packet)
    if packet.payload_len>=1200 then
        return "MODIFY_UDPLEN"
    else
        return "PASS"
    end
end