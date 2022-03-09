from scapy.all import *

def mac_incr(mac, i=1, octet=6):
    """
    Take a MAC address and increment the specified octet with the specified number.
    :param mac: MAC address to start from.
    :param i: Increment value. Default 1.
    :param octet: Which octet to increment. <1-6>, from left to right. Default, 6 (last).
    :return: The incremented MAC address.
    """
    mac = mac.split(':')
    octet_index = int(octet) - 1

    while i:
        val = int(mac[octet_index], 16)
        mac[octet_index] = ('%2s' % hex((i + val) % 256)[2:]).replace(' ', '0')
        i = (i + val) / 256
        octet_index -= 1

        if octet_index < 0 and i:
            exit('Error: mac-address upper limit reached!')

    return ':'.join(mac)


orig_mac = "00:00:00:01:00:00"

macs = []

for i in range(10000):
    macs.append(mac_incr(orig_mac,i=i))
    
for mac in macs:
    sendp(Ether(src=mac, dst="00:00:00:ff:ff:fe"), count=3, iface='Realtek USB GbE Family Controller')