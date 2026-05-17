# Fake desync mode
import pydivert
import argparse
from netaddr import IPSet, IPAddress
import datetime
import copy
import random

# LISTS
#ipset
print("ipset loading")
ipset=IPSet()
with open("ipset/ipset.txt", "r", encoding="utf-8") as file:
    ipset = IPSet(line.strip() for line in file if line.strip())
print("Succesfuly loaded")
#ipset-exclude
print("ipset-exclude loading")
with open("ipset/ipset-exclude.txt", "r", encoding="utf-8") as file:
    ipset_exclude = IPSet(line.strip() for line in file if line.strip())
print("ipset-exclude loaded")

parser = argparse.ArgumentParser(description="TB-Software Network Filter")
parser.add_argument("--repeats", type=int, default=3, help="send fake packets N times")
parser.add_argument("--ttl-f", type=int, default=5, help="Time-To-Live for fake packets")
parser.add_argument("--mark", type=int, default=1337, help="Safety")
args = parser.parse_args()

def fake_p():
    # LOGIC
    print(f"Packet capture started at: {datetime.datetime.now()}", flush=True)
    try:
        with pydivert.WinDivert("tcp.DstPort==443 or udp.DstPort==443 and outbound") as w: # Фильтр будет смотреть на пакеты пришедшие с протокола TCP/UDP с порта 443(https) + выходящие из вашего пк
            for packet in w:
                if packet.tcp.window_size == args.mark or len(packet.payload) == 0: # Если попался пустой пакет or попался фейк пакет созданный программой
                        w.send(packet)
                        continue
            
                if IPAddress(packet.dst_addr) in ipset and IPAddress(packet.dst_addr) not in ipset_exclude: # Если ip пакета есть в ipset + нету в ipst-exclude то будет применяться десинхронизация
                    for i in range(args.repeats): 
                        fake_packet=copy.copy(packet)
                        fake_packet.tcp.window_size=args.mark # Отправляет столько пакетов сколько вы указали в аргументах  + меняет "размер окна" дабы сервер отправлял мало данных
                        if len(fake_packet.payload)>=3:
                            fake_packet.payload = b'\x16\x03\x01' + random.randbytes(len(packet.payload)-3) # если у фейкового payload больше или равно 3 символов то он создат маленькую имитацию tls пакета(16 03 01) + добавит столько рандомных байтов сколько в оригинальном payload
                        else:
                            orig_len = len(packet.payload)
                            fake_packet.payload = (b'\x16\x03\x01' * 2)[:orig_len] # Иначе payload фейка будет умножен на два символами "\x16\x03\x01" + припишет оригинальный payload
                        fake_packet.ip.ttl=args.ttl_f # Time-To-Live
                        w.send(fake_packet)
                        print("fake_p_sended") 
                w.send(packet)
                continue
    except Exception as e:
        print(f"Error: {e}")
 
if __name__=="__main__":
    fake_p()