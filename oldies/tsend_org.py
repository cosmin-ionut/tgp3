from collections import OrderedDict
from scapy.all import *
from threading import Thread

class thCreator(Thread):

    def __init__(self, iface, frame, mtuList):
        Thread.__init__(self)
        self.mtuList = mtuList
        self.iface = iface
        self.frame = frame
        self.options = options

    def sendTraffic(self):
        #print (f"Now sending traffic on iface {self.iface} with MTU size {self.mtu}")
        #sendp(self.frame/Raw(load=RandBin(self.mtu)), self.iface, count = 1200)
        pass

    def sendTcpreplayTraffic(self):
        pass


    def run(self):
        for mtu in self.mtuList:
            self.mtu = mtu
            self.sendTraffic()

class generateTraffic(object):

    def __init__(self, ifaces, frame, mtuList = [1500]):
        self.mtuList = mtuList
        self.ifaces = ifaces
        self.frame = frame
        self.threads = {}

    def start(self):
        i = 0
        for iface in self.ifaces:
            self.threads[i] = thCreator(iface, frame = self.frame, mtuList = self.mtuList)
            print (f"Thread id: {i} opened for interface {iface}")
            self.threads[i].start()
            i += 1

class tSend(object):

    hasUI = True
    showUIMenu = "Send packets"

    def __init__(self):
        self.exitMenu = False
        self.ifaces = ['Realtek PCIe GbE Family Controller', 'TAP-Windows Adapter V9', 'Microsoft Wi-Fi Direct Virtual Adapter #5', 'Microsoft Wi-Fi Direct Virtual Adapter #6', 'Intel(R) Dual Band Wireless-AC 7260']
        #self.ifaces = bootstrap.resources['ifaces']
        #if not 'pkt' in bootstrap.resources:
        #    print(f'[WRN] [threadSEND] : There is no crafted packet. There is nothing to send.')
        #    return
        #self.pkt = bootstrap.resources['packet']
        ##### OS #############################
        self.os = 'Windows'
        ##### Generate the dictionary of interfaces that you can use to send packets #############
        self.ifacesDict = {}
        try:
            i = 1
            for iface in self.ifaces: # change to 'for iface in bootstrap.resources['ifaces']'
                self.ifacesDict[str(i)] = iface
                i += 1
        except Exception as err:
            print(f'[FATAL] [tSend] : Couldn\'t generate the interfaces dictionary. Error: {err}')
            return
        ###########################################################################################
        self.pkts = {'pkt1':'First', 'pkt2':'Second'}
        ##### Initiate threads dict #####
        self.threadsDict = OrderedDict()

        ##### Initiate error attribute #####
        self.error = False

    def showAvailablePackets(self):
        '''Displays the crafted packets you have available to send.
        '''
        if self.error:
            print (self.error)
            return
        try: 
            for packet in self.pkts.values():
                print(packet)
                #packet.show2()
        except Exception as e:
            self.error = f'[FATAL] [tSend] : Couldn\'t display the packets. Error: {e}'
            print (self.error)


    def setThreadIndex(self):
        i = 1
        while i in self.threadsDict.keys():
            i += 1
        return i
    
    def selectIface(self):

        selected = False
        print(self.ifacesDict)
        while not selected:
            selectedIface = input('Select an interface to send a packet: ')

            if selectedIface not in self.ifacesDict:
                print('Invalid option! Try again...')
                continue
            else:
                self.selectedIface = self.ifacesDict[selectedIface]
                print(self.selectedIface)
                selected = True
    
    def parseThreadOptions(self, options):
        optionsDict = {}
        for option in options:
            userInput = input(f'Choose a value for \'{option}\' (empty is default): ')
            if not userInput:
                continue
            optionsDict[option] = userInput
        self.sendOptions = optionsDict

    def startThread(self):
        if self.error:
            print (self.error)
            return
        options = ['inter', 'loop', 'count', 'realtime']
        self.selectIface()
        self.parseThreadOptions(options)
        a = self.setThreadIndex()
        #self.threadsDict[a]
        print(f'Thread number {a}: Will send using Scapy, on interface \'{self.selectedIface}\', with additional options {self.sendOptions}')
        #self.threads[self.setThreadIndex()] = thCreator(iface, frame = self.frame, mtuList = self.mtuList)
        #print (f"Thread id: {i} opened for interface {iface}")
        #self.threads[i].start()

    def startTcpreplayThread(self):
        if self.error:
            print (self.error)
            return
        if not self.tcpreplay:
            print('[WRN] [tSend] : Tcpreplay is not available on your system. You cannot use this option.')
        options = ['pps', 'mbps', 'realtime', 'loop', 'file_cache', 'parse_results']
        self.parseThreadOptions(options)

        #self.threads[i] = thCreator(iface, frame = self.frame, mtuList = self.mtuList)
        #print (f"Thread id: {i} opened for interface {iface}")
        #self.threads[i].start()

    
    
    def menuOptions(self):

        optionDict = OrderedDict()

        optionDict = {'1' : [self.showAvailablePackets, '1. Display the available packets to send'],
                      '2' : [self.startThread, '2. Send packets'],
                      '3' : [self.startTcpreplayThread, '3. Send packets using tcpreplay'],
                      '4' : [self.craft, '4. Show and control the sending threads'],
                      '9' : [self.exitModule, '9. Return to Main Menu']}
        
        while not self.exitMenu:
        
            for option in optionDict.values():
                print(option[1])
                           
            self.userHelpChoice = input("Enter a menu option: ")

            os.system('cls') #testing

            optionDict[self.userHelpChoice][0]()

    def launch(self):
        print(self.pkt)
        return{'send_threads':'hello'}

a = tSend()
#print (a.ifacesDict)
#a.selectIface()
#print (a.ifacesDict[15])
#a.chooseOptions()
#o = Ether(src='00:00:00:01:01:01')
#a.showAvailablePackets()
#a.setThreadIndex()
a.startThread()


# foloseste self.error pentru a verifica in functiile de meniu daca nu cumva exista erori.