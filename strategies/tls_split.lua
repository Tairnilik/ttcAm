function analyze_packet(packet)
    if type(packet.args.split_pos) == "string" then
        local s_p = math.random(1, 5)
        
        if packet.payload_len > s_p then
            packet.part1 = string.sub(packet.payload, 1, s_p)
            packet.part2 = string.sub(packet.payload, s_p + 1) 
            return "MODIFY_FRAGMENTATION"
        end
    else
        if packet.payload_len > packet.args.split_pos then
            packet.part1 = string.sub(packet.payload, 1, packet.args.split_pos)
            packet.part2 = string.sub(packet.payload, packet.args.split_pos + 1)       
            return "MODIFY_FRAGMENTATION"
        end
    end
    
    return "PASS"
end