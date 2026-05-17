# libraries
from l7_filter.L7_filter_loading import l7
import pydivert

with pydivert.WinDivert("(tcp.DstPort==443 or udp.DstPort==443) and outbound") as w:
    for packet in w:
        protocol=l7(packet.payload)
        print(f"Detected {protocol} packet")