# Overlap & Junk desync mode
import pydivert
import time
import copy
import random

#Settings
ttl_f_p=int(input("Enter the ttl for fake packet: "))
print(f"TTL: {ttl_f_p}")
time.sleep(1)

with pydivert.WinDivert("tcp.DstPort==443 and outbound and !loopback and tcp.PayloadLength > 0") as w:
    for packet in w:
        fake_packet=copy.copy(packet)
        fake_packet.tcp.window=1337       
        fake_packet.payload = b'\x16\x03\x01' + random.randbytes(len(packet.payload))
        fake_packet.ip.ttl=ttl_f_p
        
        fake_packet.tcp.seq_num=packet.tcp.seq_num
        
        w.send(fake_packet)
        print(f"Succesfully send fake packet")
        
        packet.ip.ttl=64
        
        w.send(packet)