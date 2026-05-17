import pydivert
from lupa import LuaRuntime
from l7_filter.L7_filter_loading import l7 
from l3_filter.L3_filter_loading import l3 
import datetime
import copy
import os

lua = LuaRuntime(unpack_returned_tuples=True) # Lua Virtual Machine

# lua code initializating
lua_name=input("Enter the name of the strategy without .lua: ")
split_pos=int(input("Enter the split position: "))
split_mode=input("Enter the fragmentation mode(split/disorder): ").lower().strip()
ttl=int(input("Enter the Time-To-Live number: "))
repeats=int(input("Send fake packets N times: "))
N_mark=int(input("Enter the number for the window size: "))
ipversion=input("Enter the ip_version(ipv4/ipv6): ").lower().strip()
protocol=input("Enter the protocol(tls/http/quic): ").lower().strip()
print(f"{lua_name=} {split_pos=} {N_mark=} {ttl=} {repeats=}")

with open(f"strategies/{lua_name}.lua", "r", encoding="utf-8") as file:
    lua_code=file.read()

lua_process=lua.execute(lua_code) # Можно было использовать и lua.eval
lua_analyze = lua.globals().analyze_packet 

try:
    print(f"Packet capture started at: {datetime.datetime.now()}", flush=True)
    WinDivert_filter=f"{l3(ipversion)} and tcp.DstPort==443 and outbound"
    with pydivert.WinDivert("tcp.DstPort==443 and outbound") as w: #Фильтр на исходящие протокол TCP и UDP Destination порт 443 пакеты
        for packet in w:
            
            packet_data = { # Это аргументы, которые нужны для lua кода
                "payload": packet.payload.decode('latin1'), # payload
                "payload_len": len(packet.payload), # символов в payload
                "verdict_type": None,
                "args": { # аргументы
                    "split_pos": split_pos,
                    "w_size": N_mark,
                    "fake_ttl": ttl,
                    "repeats":  repeats
                }
            }
            
            l7_protocol=l7(packet.payload)

            if packet.tcp.window_size==N_mark or len(packet.payload) == 0 or l7_protocol != protocol: # Защита от ре-фрагментации уже фрагментированных пакетов + программа не будет фильтровать пакеты, которые имеют другой протокол(Пользователь выбрал TLS, значит windivert будет фильтровать только tls пакеты)
                w.send(packet)
                continue

            verdict=lua_analyze(packet_data) # Какой вердикт выдаст lua код увидев данные о пакете?
            
            if verdict=="MODIFY_FRAGMENTATION": # Условие если lua код выдал вердикт на MODIFY_FRAGMENTATION
                p1_bytes=packet_data["part1"].encode("latin1") # Переводим
                p2_bytes=packet_data["part2"].encode("latin1")
                # Логика фрагментации
                part1=copy.copy(packet)
                part2=copy.copy(packet)
                
                part1.payload=p1_bytes 
                part2.payload=p2_bytes
                
                part2.tcp.seq_num += len(part1.payload)
                part1.tcp.window_size = N_mark
                part2.tcp.window_size = N_mark
                # Конец логики фрагментации. Теперь программа отправит фраг. пакеты в правильном/неправильном порядке
                if split_mode=="split":
                    w.send(part1)
                    w.send(part2)
                    print("fragmented")
                    continue
                elif split_mode=="disorder":
                    w.send(part2)
                    w.send(part1)
                    print("fragmented")
                    continue
                else:
                    w.send(part1)
                    w.send(part2)
                    print("fragmented")
                    continue
            elif verdict=="MODIFY_FAKE_PACKET":
                v_type=packet_data["verdict_type"]
                lena_pay=packet_data["payload_len"]
                for i in range(repeats): # Отправляет столько пакетов сколько вы указали в аргументах  + меняет "размер окна" дабы сервер отправлял мало данных
                    fake_packet=copy.copy(packet)
                    fake_packet.tcp.window_size=N_mark 
                    if v_type == "smart_padding":
                        fake_payload = b'\x16\x03\x01' + os.urandom(lena_pay - 3) # если у фейкового payload больше или равно 3 символов то он создат маленькую имитацию tls пакета(16 03 01) + добавит столько рандомных байтов сколько в оригинальном payload
                        fake_packet.payload = fake_payload
                    elif v_type == "tls_multiplier":
                        fake_payload = (b'\x16\x03\x01' * 2)[:lena_pay] # Иначе payload фейка будет умножен на два символами "\x16\x03\x01" + припишет оригинальный payload
                        fake_packet.payload = fake_payload
                    fake_packet.ip.ttl = packet_data["fake_ttl"]
                    w.send(fake_packet)
                    print("fake_p_sended")
                w.send(packet)
                continue
            w.send(packet) 
except Exception as e:
    print(f"Error: {e}")
except KeyboardInterrupt:
    print("Goodbye!(DPI)") # easter egg