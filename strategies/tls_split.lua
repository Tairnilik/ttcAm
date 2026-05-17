local function analyze_packet(packet)
	if packet.payload_len>packet.args.split_pos then
		packet.part1 = string.sub(packet.payload, 1, packet.args.split_pos)
		packet.part2 = string.sub(packet.payload, packet.args.split_pos + 1)			
		return "MODIFY_FRAGMENTATION"
	end
	return "PASS"
end
