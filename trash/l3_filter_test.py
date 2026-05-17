# libraries
from l3_filter.L3_filter_loading import l3
import pydivert

typ = input("Введите ipv6, ipv4 или all: ").strip().lower()

l3(typ)