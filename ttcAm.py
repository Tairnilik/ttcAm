import pydivert
from lupa import LuaRuntime
import ctypes
import datetime
import copy
import os
import random
import sys
import io

lua = LuaRuntime(unpack_returned_tuples=True, encoding='latin1') # Lua Virtual Machine
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# lua code initializating
lua_name=input("Enter the name of the strategy without .lua: ")
split_pos=input("Enter the split position(use random of you want random split pos): ")
split_mode=input("Enter the fragmentation mode(split/disorder): ").lower().strip()
ttl=int(input("Enter the Time-To-Live number: "))
repeats=int(input("Send fake packets N times: "))
N_mark=int(input("Enter the number for the window size: "))
ipversion=input("Enter the ip_version(ip/ip6): ").lower().strip()
protocol=input("Enter the protocol(tls/http/quic): ").lower().strip()
print(f"{lua_name=} {split_pos=} {N_mark=} {ttl=} {repeats=}")

with open(f"strategies/{lua_name}.lua", "r", encoding="utf-8") as file:
    lua_code=file.read()

try:
    split_pos = int(split_pos)
except ValueError:
    pass

# Lua
lua_process=lua.execute(lua_code) # Можно было использовать и lua.eval
lua_analyze = lua.globals().analyze_packet 

# C
#l7
dll_path = os.path.abspath("./l7_filter/l7_filter.dll")
l7_lib = ctypes.CDLL(dll_path)
l7_lib.check_l7_protocol.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
l7_lib.check_l7_protocol.restype = ctypes.c_int

proto_args = {
    0: "unknown",
    1: "tls",
    2: "http",
    3: "quic_initial",
    4: "quic_handshake",
    5: "quic_other_long"
}

try:
    print(f"Packet capture started at: {datetime.datetime.now()}", flush=True)
    if protocol == "quic":
        WinDivert_filter = f"{ipversion} and udp.DstPort==443 and outbound"
    else:
        WinDivert_filter = f"{ipversion} and tcp.DstPort==443 and outbound"
    with pydivert.WinDivert(WinDivert_filter) as w: #Фильтр на исходящие протокол TCP и UDP Destination порт 443 пакеты
        for packet in w:
            if (packet.tcp and packet.tcp.window_size == N_mark) or not packet.payload or len(packet.payload) == 0:
                w.send(packet)
                continue
            
            decoded_payload=packet.payload.decode("latin1")
            
            packet_data = { # Это аргументы, которые нужны для lua кода
                "payload": decoded_payload, # payload
                "payload_len": len(packet.payload), # символов в payload
                "verdict_type": None,
                "args": { # аргументы
                    "split_pos": split_pos,
                    "w_size": N_mark,
                    "fake_ttl": ttl,
                    "repeats":  repeats
                }
            }
            
            raw_data = (ctypes.c_ubyte * len(packet.payload)).from_buffer_copy(packet.payload) # Для C кода нужны голые байты, а питон все время кладет в байтах счетчик ссылок, размер, тип объекта и т.п. Поэтому мы переводим из питон байтов в голые байты дабы С спокойно их принял
            res_code = l7_lib.check_l7_protocol(raw_data, packet_data["payload_len"]) # Вызываем C функцию (l7_filter.dll)
            l7_protocol = proto_args.get(res_code, "unknown") # Если C вернул что-то непонятное, код запишет в unknown дефолтную группу

            verdict=lua_analyze(packet_data) # Какой вердикт выдаст lua код увидев данные о пакете?
            
            if verdict=="MODIFY_FRAGMENTATION": # Условие если lua код выдал вердикт на MODIFY_FRAGMENTATION
                # проверка если строка то конвертиурем в latin1 иначе все оставляем как есть
                p1_bytes = packet_data["part1"] if isinstance(packet_data["part1"], bytes) else packet_data["part1"].encode('latin1')
                p2_bytes = packet_data["part2"] if isinstance(packet_data["part2"], bytes) else packet_data["part2"].encode('latin1')
                # Логика фрагментации
                part1=copy.copy(packet)
                part2=copy.copy(packet)
                
                part1.payload=p1_bytes 
                part2.payload=p2_bytes
                
                part1.tcp.window_size = N_mark
                part2.tcp.window_size = N_mark

                part1.recalculate_checksums()
                part2.recalculate_checksums()
                # Конец логики фрагментации. Теперь программа отправит фраг. пакеты в правильном/неправильном порядке
                if split_mode=="split":
                    w.send(part1)
                    w.send(part2)
                    print("fragmented", flush=True)
                    continue
                elif split_mode=="disorder":
                    w.send(part2)
                    w.send(part1)
                    print("fragmented", flush=True)
                    continue
                else:
                    w.send(part1)
                    w.send(part2)
                    print("fragmented", flush=True)
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
                    elif v_type == "multiplier":
                        fake_payload = (b'\x16\x03\x01' * 2)[:lena_pay] # Иначе payload фейка будет умножен на два символами "\x16\x03\x01" + припишет оригинальный payload
                        fake_packet.payload = fake_payload
                    fake_packet.ip.ttl = packet_data["fake_ttl"]
                    w.send(fake_packet)
                    print("fake_p_sended", flush=True)
                w.send(packet)
                continue
            elif verdict=="MODIFY_UDPLEN":
                max_bytes=300 # можете указать свое количество по дефолту стоит 300
                cur_byte=random.randint(50,max_bytes) 
                rand_bytes=os.urandom(max_bytes) # сколько байтов сгенерирует urandom
                packet.payload=packet.payload+rand_bytes # добавляем мусор в конец пакета
                packet.recalculate_checksums() # пересчитывание
                print("udp_len_modified", flush=True)
                w.send(packet)
                continue
            elif verdict=="PASS":
                w.send(packet)
                continue 
except Exception as e:
    print(f"Error: {repr(e)}", flush=True)
except KeyboardInterrupt:
    print("Goodbye!(DPI)") # easter egg