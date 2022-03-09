from collections import OrderedDict
from scapy.all import *
from threading import Thread
from time import sleep
from math import ceil
#from utils.menuOptValidator import menuOptionValidator


def menuOptionValidator(text, menu):
    while True:
        userChoice = input(text)
        if not userChoice:
            return None
        elif userChoice not in menu:
            print('Invalid option! Try again...')
            continue
        else:
            return userChoice


class thCreator(Thread):

    def __init__(self, sendType, pkt, sendOptions, sendFunction, iface):
        Thread.__init__(self)
        self.pkt = pkt
        self.sendOptions = sendOptions
        self.stopFlag = Event()
        self.sendType = sendType
        self.daemon = True
        self.results = None
        self.sendFunction = sendFunction
        self.iface = iface

    def scapySend(self):
        try:
            sendOptions = self.sendOptions 
            checkCount = 600 #the stop thread condition is checked every 600 packets sent.
            sentCount = 0
            #if sending interval is bigger than 0, then the False check is performed every 3 seconds
            if 'inter' in sendOptions and float(sendOptions['inter']) != float(0):
                checkCount = ceil((1 / float(sendOptions['inter']))*3)

            # if the loop is true, then check the stop condition every
            if 'loop' in sendOptions and bool(sendOptions['loop']):
                sendOptions['count'] = checkCount
                while not self.stopFlag.is_set():
                    sendp(self.pkt, iface=self.iface, **sendOptions)
                    sentCount = sentCount + checkCount
                return
            
            if 'count' in sendOptions:
                totalCount = int(sendOptions['count'])
                if totalCount <= checkCount:
                    sentPackets = totalCount
                    sendp(self.pkt, self.iface, **sendOptions)
                    return
                else:
                    sentPackets = 0
                    sendOptions['count'] = checkCount
                    while not self.stopFlag.is_set() and checkCount < totalCount:
                        sendp(self.pkt, iface=self.iface, **sendOptions)
                        totalCount = totalCount - checkCount
                        sentPackets = sentPackets + checkCount
                    sendOptions['count'] = totalCount
                    sendp(self.pkt, **sendOptions)
                    sentPackets = sentPackets + totalCount
                    return 
        except TypeError as err:
            print(f'[WRN] [thCreator] : Couldn\'t start sending traffic. Error: {err}')
            return

    def run(self):
            if self.sendFunction == 'Scapy':
                self.scapySend()
            elif self.sendFunction == 'tcpReplay':
                self.sendTcpreplay()
            else:
                print('[WRN] [tSend] : Unknown operation requested')

class tSend(object):

    hasUI = True
    showUIMenu = "Send packets"

    def __init__(self):
        #################################################################
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
        self.pkt = Ether(src='00:00:00:01:01:01')/Raw(load=RandBin(1300))
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
        return str(i)
    
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
                #print(self.selectedIface)
                selected = True
    
    def parseThreadOptions(self, options):
        optionsDict = {}
        for option in options:
            userInput = input(f'Choose a value for \'{option}\' (empty is default): ')
            if not userInput:
                continue
            try:
                optionsDict[option] = float(userInput)
            except ValueError:
                optionsDict[option] = userInput
        self.sendOptions = optionsDict           

    def createThread(self):
    
        if self.error:
            print (self.error)
            return

        options = ['inter', 'loop', 'count', 'realtime']

        self.selectIface()
        self.parseThreadOptions(options)

        thread = thCreator(pkt = self.pkt, iface = self.selectedIface, sendType = sendp, sendOptions = self.sendOptions, sendFunction = 'Scapy')
        self.threadsDict[self.setThreadIndex()] = thread
        del(thread)

    def createTCPReplayThread(self):
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
    
    def startThread(self, threadID):
        try:
            print(f'Starting Thread ID: {threadID}...')
            self.threadsDict[threadID].start()
            sleep(1)
            return
        except Exception as err:
            print(f'[WRN] [tSend] : Error: {err}')
            return

    def stopThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                print(f'Stopping Thread ID: {threadID}...')
                sleep(1)
                self.threadsDict[threadID].stopFlag.set()
                #self.threadsDict[threadID].stop()
                sleep(3)
                if self.threadsDict[threadID].is_alive():
                    raise Exception(f'Thread ID: {threadID} termination failed! Please try again')
                elif not self.threadsDict[threadID].is_alive():
                    print(f'Thread ID: {threadID}\'s execution has been stopped')
                    return
            else:
                print(f'Thread ID: {threadID} is not executing.')
                return
        except Exception as err:
            print(f'[WRN] [tSend] : Error: {err}')
            return

    def threadControl(self):
        if len(self.threadsDict) == 0:
            print('No threads have been created yet!')
            return
        
        for threadID, thread in self.threadsDict.items():
            if not thread.is_alive():
                print(f'Thread {threadID} | Status : standby' )
            elif thread.is_alive():
                print(f'Thread {threadID} | Status : alive')

        selectedThread = menuOptionValidator('Select a thread (empty to exit): ', self.threadsDict)
        
        if not selectedThread:
            return

        print(f'------------Thread {selectedThread} status:-------------- \n' \
                  f'Is thread running?: {self.threadsDict[selectedThread].is_alive()} \n'
                  f'Sending interface: {self.threadsDict[selectedThread].iface} \n'
                  f'{self.threadsDict[selectedThread].results} \n' \
                  f'Packet summary: {self.threadsDict[selectedThread].pkt.summary()} \n' \
                  f'Send Type: {self.threadsDict[selectedThread].sendFunction} \n' \
                  f'Send Options: {self.threadsDict[selectedThread].sendOptions}')    

        optionDict = {'1' : [self.startThread, '1. Start thread\s execution'],  
                      '2' : [self.stopThread, '2. Stop thread\'s execution']}
        
        while True:

            for option in optionDict.values():
                print(option[1])

            threadAction = menuOptionValidator('Select an action for this thread (empty to exit): ', optionDict)
            if not threadAction:
                return
            optionDict[threadAction][0](selectedThread)

    def exitModule(self):
        self.exitMenu = True       
    
    def menuOptions(self):

        optionDict = OrderedDict()

        optionDict = {'1' : [self.showAvailablePackets, '1. Display the available packets to send'],
                      '2' : [self.createThread, '2. Send packets'],
                      '3' : [self.createTCPReplayThread, '3. Send packets using tcpreplay'],
                      '4' : [self.threadControl, '4. Show and control the sending threads'],
                      '9' : [self.exitModule, '9. Return to Main Menu']}
        
        while not self.exitMenu:
        
            for option in optionDict.values():
                print(option[1])
                           
            self.userHelpChoice = menuOptionValidator('Enter a menu option: ', optionDict)

            os.system('cls') #testing

            optionDict[self.userHelpChoice][0]()

    def launch(self):
        self.menuOptions()
        #print(self.pkt)
        return{'send_threads':'hello'}


#print (a.ifacesDict)
#a.selectIface()
#print (a.ifacesDict[15])
#a.chooseOptions()
#o = Ether(src='00:00:00:01:01:01')
#a.showAvailablePackets()
#a.setThreadIndex()

'''
a = tSend()
a.createThread()
a.startThread('1')
a.stopThread('1')
#a.threadControl()
'''


# foloseste self.error pentru a verifica in functiile de meniu daca nu cumva exista erori.
# probleme:
#        - cand este un singur packet dat spe sendp(), bucla mareste count pentru fiecare packet
#        - pentru count < 500, bucla nu se opreste