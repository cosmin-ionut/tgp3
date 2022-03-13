from scapy.all import *
from time import sleep

class e(Thread):

   def __init__(self):
      Thread.__init__(self)

   def run(self):
      self.e = AsyncSniffer()
      self.e.start()
      sleep(5)
      self.x = self.e.stop()


a = e()
a.start()
print(a.e)
print(a.e.results)
print(a.e.results)
sleep(7)
print(a.e)
print(a.e.results)
print(a.x)

