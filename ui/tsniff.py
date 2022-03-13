from threading import Thread
from collections import OrderedDict
#from core.bootstrap import bootstrap
#from utils.menuOptValidator import menuOptValidator
from scapy.all import *
from time import sleep
#from utils.uiUtils import clearConsole, titleFormatter
from os import system

##################################################################################################################
def menuOptValidator(text, menu, showMenu = False, title = (None, None), allowEmpty = True, clearUI = None):
    uiError = ''
    if title[0]:
        formattedTitle = titleFormatter(title[0], level = title[1])
    while True:
        if clearUI:
            clearConsole(clearUI)
        if title[0]:
            print(formattedTitle)
        if showMenu:
            for k,v in menu.items():
                if isinstance(v, list):
                    print(f'{k}. {v[1]}')
                else:
                    print(f'{k}. {v}')
        print('\n' + uiError)            
        userChoice = input(text)
        if not userChoice and allowEmpty:
            return None
        elif not userChoice and not allowEmpty:
            uiError = 'Invalid option! Try again...'
            continue
        elif userChoice not in menu:
            uiError = 'Invalid option! Try again...'
            continue
        else:
            return userChoice

def clearConsole(os):
    if os == 'Linux':
        system('clear')
    elif os == 'Windows':
        system('cls')

def titleFormatter(title, level):
    if level == 1:
        return '#'*(26+len(title))+'\n'+12*'#'+f' {title} '+12*'#'+'\n'+'#'*(26+len(title))+'\n'
    elif level == 2:
        return '+'+'-'*(24+len(title))+'+'+'\n'+'+'+11*'-'+f' {title} '+11*'-'+'+'+'\n'+'+'+'-'*(24+len(title))+'+'+'\n'
    elif level == 3:
        return '|'+(6*'-')+'|'+f' {title} '+'|'+6*'-'+'|' + '\n'
    elif level == 4:
        return '#'*(26+len(title))+'\n'+12*'#'+f' {title} '+12*'#'+'\n'+'#'*(26+len(title))+'\n'

###############################################################################################################################################

class sniffThCreator(Thread):
    
    def __init__(self, iface=None, sniffOptions=None):
        Thread.__init__(self)
        self.currentPktID = 0
        self.iface = iface
        self.sniffOptions = sniffOptions
        self.stopFlag = Event()
        self.pktBuffer = {}
        
    def asyncCallback(self, pkt):
        #self.pktList = (self.currentPktID, pkt)
        self.currentPktID += 1
        self.pktBuffer[self.currentPktID] = pkt
        #self.currentPktID += 1

        
    def scapySniffer(self):
        self.asyncThread = AsyncSniffer(prn = self.asyncCallback, iface = self.iface, **self.sniffOptions)
        self.asyncThread.start()
        print('started capturing')

    def run(self):
        try:
            self.scapySniffer()
            while True:
                sleep(2)
                if len(self.pktBuffer) > 120000:
                    print('I DELETED')
                    self.pktBuffer = {}
                if self.asyncThread.results:
                    break
                if self.stopFlag.is_set():
                    self.asyncThread.stop()
                    break
        except Exception as err:
            self.asyncThread.stop()
            logging.error(err)

class tSniff(object):
        
    hasUI = True
    showUIMenu = "Capture traffic"
    
    def __init__(self):
        self.threadsDict = OrderedDict()
        self.os = 'Windows'############ sterge
        self.ifacesDict = {'1': 'Hyper-V Virtual Ethernet Adapter #2'}

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

    def parseThreadOptions(self, options):
        optionsDict = {}
        for option, type in options.items():
            while True:
                userInput = input(f'Choose a value for \'{option}\' (empty is default): ')
                if not userInput:
                    break
                try:
                    optionsDict[option] = type(userInput)
                    break
                except:
                    print(f'Invalid input {userInput}. Please retry')
                    continue
        return optionsDict
        
    def startScapySniff(self):

   ############ CHOOSE THE SNIFFING INTERFACE OR EXIT ######################

        userInput = menuOptValidator(text = 'Choose an interface to capture traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('CAPTURE TRAFFIC >> Capture traffic using Scapy >> Choose the interface', 2))

        if not userInput:
            return

        selectedIface = self.ifacesDict[userInput]
        
        options = {'count' : int, 'store': bool, 'filter': str, 'timeout': float }
        thread = sniffThCreator(iface = selectedIface, sniffOptions = self.parseThreadOptions(options))
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread 
        logging.info(f'Capturing packets on interface {selectedIface}')
        #self.a = sniffThCreator()
        #self.a.start()
        
    def stop(self):
        pass

    def stopThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                inter = 3
                self.threadsDict[threadID].stopFlag.set()
                sleep(inter)
                if self.threadsDict[threadID].is_alive():
                    logging.error(f'Thread ID: {threadID} termination failed! Please try again')
                    raise
                elif not self.threadsDict[threadID].is_alive():
                    print(f'Thread ID: {threadID}\'s execution has been stopped')
                    return
            else:
                logging.info(f'Thread ID: {threadID} is not executing.')
                return
        except Exception as err:
            logging.error(f'Error occured during thread termination. Error: {err}')
            return
    
    def showRealtimeVerbose(self, threadID):
        try:
            currentID = self.threadsDict[threadID].currentPktID
            while True:
                if currentID <= self.threadsDict[threadID].currentPktID:
                    print(f'Pkt ID {currentID} : {self.threadsDict[threadID].pktBuffer[currentID].show2()}')
                    currentID += 1
        except KeyboardInterrupt:
            return
        except Exception as err:
            logging.error(err)

    def showRealtimeSummary(self, threadID):
        try:
            currentID = self.threadsDict[threadID].currentPktID
            while True:
                if currentID <= self.threadsDict[threadID].currentPktID:
                    print(f'Pkt ID {currentID} : {self.threadsDict[threadID].pktBuffer[currentID].summary()}')
                    currentID += 1
        except KeyboardInterrupt:
            return
        except Exception as err:
            logging.error(err)

    
    def threadControl(self):
        while True:
            clearConsole(self.os)
            print(titleFormatter('SEND TRAFFIC >> Show and control the capturing threads', level=3))

            if len(self.threadsDict) == 0:
                logging.info('No threads have been created yet.')
                return
            for threadID, thread in self.threadsDict.items():
                if not thread.is_alive():
                    print(f'Thread {threadID} | Status : standby' )
                elif thread.is_alive():
                    print(f'Thread {threadID} | Status : running')

            selectedThread = menuOptValidator(text = 'Select a thread (empty to exit): ',
                                              menu = self.threadsDict,
                                              allowEmpty = True)
            if not selectedThread:
                return

            optionDict = {'1' : [self.showRealtimeSummary, 'Display a summary of the captured packets in realtime'],
                          '2' : [self.showRealtimeVerbose, 'Display the whole content of the captured packets in realtime'],
                          '3' : [self.saveCapture, 'Save the capture in a file'],
                          '4' : [self.stopThread, 'Stop thread\'s execution'],
                          '5' : [self.removeThread, 'Remove this thread']}

            while True:

                threadAction = menuOptValidator(text = 'Select an action for this thread (empty to exit): ',
                                                menu = optionDict, showMenu = True, clearUI = self.os, allowEmpty=True,
                                                title = (f'SEND TRAFFIC >> Show and control the sending threads' \
                                                ' >> Thread ID {selectedThread} >> Actions you can take', 3))
                if not threadAction:
                    return

                optionDict[threadAction][0](selectedThread)
                input('Press ENTER to continue...')
                break
        

    
    def exitModule(self):
        self.exitMenu = True

    def show(self):
        pass
    def saveCapture(self):
        pass
    def removeThread(self):
        pass

    def menuOptions(self):
    
        optionDict = OrderedDict()

        optionDict = {'1' : [self.startScapySniff, 'Capture traffic using Scapy'],
                      '2' : [self.show, 'Capture traffic using TCPDump'], 
                      '3' : [self.threadControl, 'Show and control the traffic capturing threads'],
                      '4' : [self.stop, 'Display the contents of a packet capture (pcap file)'],
                      '5' : [self.stop, 'Stop'],
                      '9' : [self.exitModule, 'Return to Main Menu']}

        while not self.exitMenu:

            self.userHelpChoice = menuOptValidator(text = 'Enter a menu option: ', menu = optionDict, showMenu = True,
                                                   allowEmpty = False, clearUI = self.os,
                                                   title = ('CAPTURE TRAFFIC - Module Menu', 2))

            optionDict[self.userHelpChoice][0]()
            input('Press ENTER to continue...')

    def launch(self):
        #try:
            self.exitMenu = False
            #self.resourceLoader()
            self.menuOptions()
            return('send', None)
        #except KeyboardInterrupt:
        #    raise
        #except Exception as err:
        #    logging.critical(f'Module exiting... Error: {err}')
        #    raise

a = tSniff()
a.launch()
#a.parseThreadOptions()