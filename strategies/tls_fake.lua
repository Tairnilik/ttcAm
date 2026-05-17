local function analyze_packet(packet)
	if packet.payload_len >= 10 then --если у фейкового payload больше или равно 10 символов то он создат маленькую имитацию tls пакета(16 03 01) + добавит столько рандомных байтов сколько в оригинальном payload
		packet.verdict_type="smart_padding"
		return "MODIFY_FAKE_PACKET"
	else --иначе payload фейка будет умножен на два символами "\x16\x03\x01" + припишет оригинальный payload
		packet.verdict_type="tls_multiplier"
		return "MODIFY_FAKE_PACKET"
	end
	return "PASS"
end