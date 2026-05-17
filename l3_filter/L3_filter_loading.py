# filter_l3 mode
def l3(typ="all"):
    if typ=="ipv4":
        l3_filter="ip"
    elif typ=="ipv6":
        l3_filter="ipv6"
    else:
        l3_filter="(ipv4 or ipv6)"
    return l3_filter

# usage
# l3("ipv6")