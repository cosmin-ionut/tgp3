
from scapy.all import *
from time import sleep

class sendtcpreplay(Thread):

    def __init__(self):
        self.e = Ether(src='00:00:00:01:01:01')/Raw(load = RandBin(1200))
        Thread.__init__(self)

    def run(self):
        sendpfast(self.e, iface='eth1')

a = sendtcpreplay()
a.start()
