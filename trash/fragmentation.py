# Fragmentation desync mode
import pydivert
import argparse
from netaddr import IPSet, IPAddress
import datetime
import copy

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
parser.add_argument("--split-mode", type=str, choices=["split", "disorder"], help="fragmentation mode")
parser.add_argument("--split-pos", type=int, default=2, help="split position")
parser.add_argument("--mark", type=int, default=1337, help="window_size")
args = parser.parse_args()

def frag():
    # Capture
    print(f"Packet capture started at: {datetime.datetime.now()}", flush=True)
    try:
        with pydivert.WinDivert(f"tcp.DstPort==443 or udp.DstPort==443 and outbound") as w: # Фильтр будет смотреть на пакеты пришедшие с протокола TCP/UDP с порта 443(https) + выходящие из вашего пк
            for packet in w:
                if packet.tcp.window_size == args.mark or len(packet.payload) == 0: # Если попался пустой пакет or попался фейк пакет созданный программой
                        w.send(packet) 
                        continue
                
                if IPAddress(packet.dst_addr) in ipset and IPAddress(packet.dst_addr) not in ipset_exclude: # Если ip есть в списке ipset + нет в списке ipset-exclude
                    if args.split_mode == "split":
                        if len(packet.payload) > args.split_pos: # сделано для защиты пакетов, которые весят меньше чем split_pos
                            part1 = copy.copy(packet)
                            part1.payload = packet.payload[:args.split_pos]
                
                            part2 = copy.copy(packet)
                            part2.payload = packet.payload[args.split_pos:]
                
                            part2.tcp.seq_num += len(part1.payload)
                        
                            part1.tcp.window_size = args.mark
                            part2.tcp.window_size = args.mark
                        
                            w.send(part1)
                            w.send(part2)
                            print("Packet was splitted")
                            continue
                            # Пакет делится на две части на определенных байтах + измененный window_size для разделеных частей пакета дабы сервер отправлял меньше байтов на части
                    elif args.split_mode == "disorder":
                        if len(packet.payload) > args.split_pos:
                            part1 = copy.copy(packet)
                            part1.payload = packet.payload[:args.split_pos]
                
                            part2 = copy.copy(packet)
                            part2.payload = packet.payload[args.split_pos:]
                
                            part2.tcp.seq_num += len(part1.payload)
                            
                            part1.tcp.window_size = args.mark
                            part2.tcp.window_size = args.mark
                        
                            w.send(part2)
                            w.send(part1)
                            print("Packet was disordered")
                            continue
                            # Пакеты отправляются задом наперед
                w.send(packet)
    except Exception as e:
        print(f"Error: {e}")
        
if __name__=="__main__":
    frag()