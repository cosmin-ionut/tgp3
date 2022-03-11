from threading import Thread
from collections import OrderedDict
from core.bootstrap import bootstrap
from utils.menuOptValidator import menuOptValidator
from scapy.all import *
from time import sleep

class sniffThCreator(Thread):
    
    def __init__(self, iface=None, sniffOptions=None):
        Thread.__init__(self)
        self.currentPktID = 1
        self.iface = iface
        self.sniffOptions = sniffOptions
        self.stopFlag = Event()
        self.pktList = {}
        
    def asyncCallback(self, pkt):
        self.pktList = (self.currentPktID, pkt)
        self.currentPktID += 1
        
    def scapySniffer(self):
        self.t = AsyncSniffer(prn = self.asyncCallback, store = 0, iface='Intel(R) Wi-Fi 6 AX200 160MHz')
        self.t.start()
        
    def run(self):
        self.scapySniffer()
        while not self.stopFlag.is_set():
            sleep(1)
        # daca buffer > 120000 atunci popitems
        # daca buffer > 160000 atunci recreate list (del)
        self.t.stop()
        print(len(self.pktList))
        
class tSniff(object):
        
    hasUI = True
    showUIMenu = "Packet sniffing"
    
    def __init__(self):
        self.threadsDict = OrderedDict()
    
    def resourceLoader(self):
        if 'environment' not in bootstrap.resources:
            raise Exception('OS critical resources are not available. Check \'environment\' module')
        self.ifacesDict = bootstrap.resources['environment']['ifaces']
        self.os = bootstrap.resources['environment']['os']
        
    def setThreadIndex(self):
        i = 1
        while str(i) in self.threadsDict.keys():
            i += 1
        logging.info(f'The thread has been assigned ID: {i}')
        return str(i)
        
    def startScapySniff(self):

   ############ CHOOSE THE SNIFFING INTERFACE OR EXIT ######################

        userInput = menuOptValidator(text = 'Choose an interface to capture traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('CAPTURE TRAFFIC >> Capture traffic using Scapy >> Choose the interface', 2))

        if not userInput:
            return

        selectedIface = self.ifacesDict[userInput]

        options = ['count', 'store','filter', 'timeout']
        self.parseThreadOptions(options)

        thread = sniffThCreator(iface = selectedIface, sniffOptions = self.sniffOptions)
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread
        logging.info(f'Capturing packets on interface {selectedIface}')
        #self.a = sniffThCreator()
        #self.a.start()
        
    def stop(self):
        self.a.stopFlag.set()
        sleep(2)
        
    def show(self):
        try:
            currentID = 0
            while True:
                if currentID < self.a.currentPktID:
                    print(f'Pkt ID {self.a.pktList[0]} : {self.a.pktList[1].summary()}')
                    currentID = self.a.currentPktID
        except KeyboardInterrupt:
            return
        except Exception:
            return
    
    def exitModule(self):
        self.exitMenu = True
    
    def menuOptions(self):
    
        optionDict = OrderedDict()

        optionDict = {'1' : [self.startScapySniff, 'Capture traffic using Scapy'],
                      '2' : [self.show, 'Show'],
                      '3' : [self.stop, 'Display a packet capture'],
                      '4' : [self.stop, 'Stop'],
                      '9' : [self.exitModule, 'Return to Main Menu']}

        while not self.exitMenu:

            self.userHelpChoice = menuOptValidator(text = 'Enter a menu option: ', menu = optionDict, showMenu = True,
                                                   allowEmpty = False, clearUI = self.os,
                                                   title = ('SEND TRAFFIC - Module Menu', 2))

            optionDict[self.userHelpChoice][0]()
            input('Press ENTER to continue...')

    def launch(self):
        try:
            self.exitMenu = False
            self.resourceLoader()
            self.menuOptions()
            return('send', None)
        except AssertionError:
            logging.error(f'No packets have been crafted. There is nothing to send. Exiting module...')
            input('Press ENTER to continue...')
            return('send', None)
        except KeyboardInterrupt:
            raise
        except Exception as err:
            logging.critical(f'Module exiting... Error: {err}')
            raise