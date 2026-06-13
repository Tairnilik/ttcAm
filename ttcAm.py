import pydivert
import ipaddress
from lupa import LuaRuntime
import ctypes
import time
import datetime
import copy
import os
import random
import sys
import io
import json

def clear_cmd():
    os.system("cls" if os.name=="nt" else "clear")

lua = LuaRuntime(unpack_returned_tuples=True, encoding='latin1') # Lua Virtual Machine
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# json
json_name=input("Enter json config name(without .json): ")
try:
    with open(f"configs/{json_name}.json", "r", encoding="utf-8") as f:
        arguments = json.load(f)
    print("Successfully loaded JSON file", flush=True)
except FileNotFoundError:
    print(f"Error: {json_name}.json not found! Please create it.", flush=True)
    sys.exit(1)

lua_name   = arguments.get("strategy", "tls_split")
split_pos  = arguments.get("split_pos", "random")
split_mode = arguments.get("split_mode", "split").lower().strip()
ttl        = int(arguments.get("fake_ttl", 4))
repeats    = int(arguments.get("repeats", 1))
N_mark     = int(arguments.get("window_size", 1212))
ipversion  = arguments.get("ip_version", "ip").lower().strip()
protocol   = arguments.get("protocol", "tls").lower().strip()
port1     = int(arguments.get("1_port_range", 80))
port2     = int(arguments.get("2_port_range", 443))
fooling_mode = arguments.get("fooling_mode", "badseq")
fooling_args_1   = int(arguments.get("fooling_args_1", 1000))
fooling_args_2   = int(arguments.get("fooling_args_2", 5000))
print(f"Loaded config: {lua_name=} {split_pos=} {split_mode=} {N_mark=} {ttl=} {repeats=} {ipversion=} {protocol=} {port1=} {port2=} {fooling_mode=} {fooling_args_1=} {fooling_args_2=}", flush=True)
time.sleep(5)
clear_cmd()

try:
    with open(f"strategies/{lua_name}.lua", "r", encoding="utf-8") as f:
        lua_code=f.read()
    print("Succesfuly loaded .lua strategy")
except FileNotFoundError:
    print(f"Error: {lua_name}.lua not found! Please create it.", flush=True)
    sys.exit(1)  
time.sleep(2)
clear_cmd()

ipset_networks = []
ipset_exclude_networks = []
try:
    with open("ipset/ipset.txt", "r", encoding="utf-8") as f:
        for line in f:
            cidr_str=line.strip()
            if not cidr_str or line.startswith("#"):
                continue
            try:
                network_obj = ipaddress.ip_network(cidr_str, strict=False)
                ipset_networks.append(network_obj)
            except ValueError:
                print(f"Incorrect CIDR|IP: {cidr_str}")
    print("Succesfuly loaded ipset.txt")
    clear_cmd()
    with open("ipset/ipset-exclude.txt", "r", encoding="utf-8") as f:
        for line in f:
            cidr_str_e=line.strip()
            if not cidr_str_e or line.startswith("#"):
                continue
            try:
                network_obj_e = ipaddress.ip_network(cidr_str_e, strict=False)
                ipset_exclude_networks.append(network_obj_e)
            except ValueError:
                print(f"Incorrect CIDR/IP в ipset-exclude.txt: {cidr_str_e}")
    print("Succesfuly loaded ipset-exclude.txt")
except FileNotFoundError:
    print("Error: ipset|ipset-exclude not found! Please create it.", flush=True)
    sys.exit(1)

try:
    split_pos = int(split_pos)
except ValueError:
    pass

# Lua
lua_process=lua.execute(lua_code) # Можно было использовать и lua.eval
lua_analyze = lua.globals().analyze_packet 

# C
#l7
l7_path = os.path.abspath("./l7_filter/l7_filter.dll")
l7_lib = ctypes.CDLL(l7_path)
l7_lib.check_l7_protocol.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
l7_lib.check_l7_protocol.restype = ctypes.c_int
#fooling
fool_path=os.path.abspath("./fooling_mode/fooling_mode.dll")
fool_lib = ctypes.CDLL(fool_path)
fool_lib.badseq.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.c_uint32]
fool_lib.badsum.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
fool_lib.md5sig.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]

def dst_ip_check(dst_point):
    try:
        ip_obj = ipaddress.ip_address(dst_point)
        for network in ipset_exclude_networks:
            if ip_obj in network:
                return "PASS"
        for network in ipset_networks:
            if ip_obj in network:
                return "MODIFY"
        return "PASS"
    except ValueError:
        return "PASS"

def fooling_func(packet):
    """Вспомогательная функция для автоматического применения Си-модификаций"""
    # Применяем обман ТОЛЬКО для протокола TCP и только если режим включен
    if packet.tcp and fooling_mode != "none":
        try:
            # 1. Считаем длину IP-заголовка
            ip_header_len = (packet.raw_packet[0] & 0x0F) * 4
            
            # 2. Копируем сырые байты пакета в буфер для Си
            packet_raw_bytes = (ctypes.c_ubyte * len(packet.raw_packet)).from_buffer_copy(packet.raw_packet)
            
            # 3. Дергаем нужную Си-функцию
            if fooling_mode == "badsum":
                fool_lib.badsum(packet_raw_bytes, ip_header_len)
            elif fooling_mode == "badseq":
                rand_offset = random.randint(fooling_args_1, fooling_args_2)
                fool_lib.badseq(packet_raw_bytes, ip_header_len, rand_offset)
            elif fooling_mode == "md5sig":
                # Для md5sig нужно убедиться, что в пакете хватает выделенного места под опции!
                fool_lib.md5sig(packet_raw_bytes, len(packet.raw_packet))
            
            # 4. Возвращаем измененные байты обратно в объект pydivert
            packet.raw_packet = bytes(packet_raw_bytes)
        except Exception as e:
            print(f"Error in C-fooling: {e}", flush=True)
    return packet

proto_args = {
    0: "unknown",
    1: "tls",
    2: "http",
    3: "quic_initial",
    4: "quic_handshake",
    5: "quic_other_long"
}
clear_cmd()
try:
    print(f"Packet capture started at: {datetime.datetime.now()}", flush=True)
    if protocol=="quic":
        if port1!=port2:
            WinDivert_filter = f"{ipversion} and udp.DstPort >= {port1} and udp.DstPort <= {port2} and outbound"
        else:
            WinDivert_filter = f"{ipversion} and udp.DstPort == {port1} and outbound"
    else:
        if port1!=port2:
            WinDivert_filter = f"{ipversion} and tcp.DstPort >= {port1} and tcp.DstPort <= {port2} and outbound"
        else:
            WinDivert_filter = f"{ipversion} and  tcp.DstPort == {port1} and outbound"
    with pydivert.WinDivert(WinDivert_filter) as w: #Фильтр на исходящие протокол TCP и UDP Destination порт 443 пакеты
        for packet in w:
            result=dst_ip_check(packet.dst_addr)
            if (packet.tcp and packet.tcp.window_size == N_mark) or not packet.payload or len(packet.payload) == 0 or result=="PASS":
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

                part1 = fooling_func(part1)
                part2 = fooling_func(part2)
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
                    fake_packet.ip.ttl = packet_data["args"]["fake_ttl"]
                    fake_packet = fooling_func(fake_packet)
                    w.send(fake_packet)
                    print("fake_p_sended", flush=True)
                packet = fooling_func(packet)
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
                packet = fooling_func(packet)
                w.send(packet)
                continue 
except Exception as e:
    print(f"Error: {repr(e)}", flush=True)
except KeyboardInterrupt:
    print("Goodbye!(DPI)") # easter egg