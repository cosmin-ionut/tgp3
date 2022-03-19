from scapy.all import *
from time import sleep


import threading
import ctypes

class twe(threading.Thread):
    def __init__(self, name):
        threading.Thread.__init__(self)
        self.name = name
        self.packet = Ether(dst='00:00:00:01:01:01')/Raw(load=RandBin(1000))
        self.stopFlag = Event()

    def run(self):
        try:
            x.semd()
            if self.stopFlag.is_set():
               self.raise_exception()
        finally:
            print('ended')

    def semd(self):
         sendp(self.packet, count=4000, inter=0.1, iface='Hyper-V Virtual Ethernet Adapter #2')       
    def get_id(self):
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def raise_exception(self):
        thread_id = self.get_id()
        resu = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id,
              ctypes.py_object(SystemExit))
        if resu > 1: 
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            print('Failure in raising exception')      
x = twe('Thread A')



#x.join()

try:
   x.start()
   #x.raise_exception()
   i = 1
   while True:
      sleep(1)
      if i == 5:
         x.stopFlag.set()
         
         print('signal set')
      i += 1
      print(f'send is still alive: {x.is_alive()}')
except KeyboardInterrupt:
   print('Gotcha')




'''

class e(Thread):

   def __init__(self):
      Thread.__init__(self)
      self.packet = Ether(dst='00:00:00:01:01:01')/Raw(load=RandBin(1000))
      self.stopFlag= Event()
      self.daemon = True
      
   def thFunc(self):
      self.procid = threading.get_native_id()
      sendp(self.packet, count=4000, inter=0.1, iface='Hyper-V Virtual Ethernet Adapter #2')

   def run(self):
      self.sendProcess = threading.Thread(target = sendp, args=(self.packet), kwargs = {'count':4000, 'inter':0.1, 'iface':'Hyper-V Virtual Ethernet Adapter #2'})
      #self.sendProcess = threading.Thread(target = self.thFunc)
      self.sendProcess.daemon = True
      self.sendProcess.start()
      while not self.stopFlag.is_set():
         sleep(1)

a = e()
try:
   a.start()
   i = 1
   while True:
      sleep(1)
      if i == 5:
         a.stopFlag.set()
         print('signal set')
      i += 1
      print(f'main is still alive: {a.is_alive()}')
except KeyboardInterrupt:
   print('Gotcha')

'''
