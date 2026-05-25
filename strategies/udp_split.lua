function analyze_packet(packet)
    local s_p = packet.args.split_pos
    if type(s_p) == "string" then
        s_p = 2 -- Дефолтное смещение для QUIC, если ввели "random"
    end

    if packet.payload_len>s_p then
        if packet.payload_len>=1200 then -- обычно --quic пакет имеет больше 1200 байтов
            packet.part1 = string.sub(packet.payload, 1, s_p)
		    packet.part2 = string.sub(packet.payload, s_p + 1)	
            return "MODIFY_FRAGMENTATION"
        else
            return "PASS"
        end
    else
        return "PASS"
    end
end