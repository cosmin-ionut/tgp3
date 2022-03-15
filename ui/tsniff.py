from threading import Thread
from collections import OrderedDict
from core.bootstrap import bootstrap
from utils.menuOptValidator import menuOptValidator
from scapy.all import *
from time import sleep
from datetime import datetime
from utils.uiUtils import clearConsole, titleFormatter
from subprocess import Popen, PIPE, signal
from utils.getCaps import getCaps

class sniffThCreator(Thread):
    
    def __init__(self, iface=None, sniffOptions=None, sniffType=None):
        Thread.__init__(self)
        self.currentPktID = 0
        self.iface = iface
        self.daemon = True
        self.sniffOptions = sniffOptions
        self.stopFlag = Event()
        self.pktBuffer = {}
        #self.sniffResults = None
        self.sniffType = sniffType
        
    def scapyAsyncCallback(self, pkt):
        self.currentPktID += 1
        self.pktBuffer[self.currentPktID] = pkt
        
    def scapySniffer(self):
        try:
            if 'store' in self.sniffOptions and self.sniffOptions['store'] == 'no':
                self.sniffOptions['store'] = False
            asyncThread = AsyncSniffer(prn = self.scapyAsyncCallback, iface = self.iface, **self.sniffOptions)
            asyncThread.start()
            while True:
                sleep(2)
                if not asyncThread.running or self.stopFlag.is_set():
                    self.sniffResults = asyncThread.results
                    break
        except Exception as err:
            asyncThread.stop()
            self.pktBuffer = None
            logging.error(err)
    
    def tcpdumpSniffer(self):
        command = ['tcpdump']
        if 'write_to_file' in self.sniffOptions and self.sniffOptions['write_to_file'] == 'yes':
            command.extend(['-w', self.sniffOptions[f'./temp/{str(datetime.now().time())}.pcap']])
        if 'count' in self.sniffOptions:
            command.extend(['-c', str(self.sniffOptions['count'])])
        if 'direction' in self.sniffOptions:
            command.append(f"--direction={self.sniffOptions['direction']}")
        if 'verify_checksums' in self.sniffOptions and self.sniffOptions['verify_checksums'] == 'no':
            command.append('--dont-verify-checksums')
        if 'verbose_level' in self.sniffOptions:
            command.append('-'+'v'*int(self.sniffOptions['verbose_level']))
        command.extend(['-e', '--number','--print', '-i', self.iface])
        if 'filter' in self.sniffOptions:
            command.append(self.sniffOptions['filter'])
        try:
            self.sniffProc = Popen(command, stdout=PIPE,  stderr=PIPE)
            while not self.stopFlag.is_set():
                if self.sniffProc.poll() != None:
                    break
                sleep(1)
            self.sniffProc.send_signal(signal.SIGINT)
            sleep(2)
            error = self.sniffProc.communicate()[1].decode('UTF-8')
            if error:
                raise Exception(error)           
        except Exception as err:
            self.sniffProc.terminate()
            logging.error(err)

    def run(self):
        if self.sniffType == 'Scapy':
            self.scapySniffer()
        elif self.sniffType == 'TCPDump':
            self.tcpdumpSniffer()
            
class tSniff(object):
        
    hasUI = True
    showUIMenu = "Capture traffic"
    
    def __init__(self):
        self.threadsDict = OrderedDict()

    def resourceLoader(self):
        if 'environment' not in bootstrap.resources:
            raise Exception('OS critical resources are not available. Check \'environment\' module')
        self.ifacesDict = bootstrap.resources['environment']['ifaces']
        self.os = bootstrap.resources['environment']['os']
        self.tcpdump = bootstrap.resources['environment']['tcpdump']
        
    def setThreadIndex(self):
        i = 1
        while str(i) in self.threadsDict.keys():
            i += 1
        logging.info(f'The thread has been assigned ID: {i}')
        return str(i)

    def parseThreadOptions(self, options):
        optionsDict = {}
        for option, response in options.items():
            while True:     
                userInput = input(f'Choose a value for \'{option}\' {response} (empty is default): ')
                if not userInput:
                    break
                try:
                    if isinstance(response, list):
                        if not userInput in response:
                            print(f'Invalid input {userInput}. Please retry')
                            continue
                        optionsDict[option] = userInput
                        break
                    else:
                        optionsDict[option] = response(userInput)
                        break
                except:
                    print(f'Invalid input {userInput}. Please retry')
                    continue
        return optionsDict
        
    def startScapySniff(self):

        userInput = menuOptValidator(text = 'Choose an interface to capture traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('CAPTURE TRAFFIC >> Capture traffic using Scapy >> Choose the interface', 2))
        if not userInput:
            return

        selectedIface = self.ifacesDict[userInput]
        
        options = {'count' : int, 'store': ['yes','no'], 'filter': str, 'timeout': float }
        thread = sniffThCreator(iface = selectedIface, sniffOptions = self.parseThreadOptions(options), sniffType = 'Scapy')
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread 
        logging.info(f'Capturing packets on interface {selectedIface}')

    
    def startTCPDumpSniff(self):
        if not self.tcpdump:
            clearConsole(self.os)
            print(titleFormatter('CAPTURE TRAFFIC >> Capture traffic using TCPDump', level=3))
            logging.error('TCPDump is not available on this machine. Cannot proceed!')
            return

        userInput = menuOptValidator(text = 'Choose an interface to capture traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('CAPTURE TRAFFIC >> Capture traffic using TCPDump >> Choose the interface', 2))

        if not userInput:
            return

        selectedIface = self.ifacesDict[userInput]
        
        options = {'count' : int, 'verify_checksums':['yes','no'], 'direction': ['in','out','inout'], 'verbose_level': ['1','2','3'], 'write_to_file':['yes','no'], 'filter': str}
        thread = sniffThCreator(iface = selectedIface, sniffOptions = self.parseThreadOptions(options), sniffType = 'TCPDump')
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread 
        logging.info(f'Capturing packets on interface {selectedIface}')

    def stopThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                self.threadsDict[threadID].stopFlag.set()
                i = 1
                while i <= 2 and self.threadsDict[threadID].is_alive():
                    logging.info(f'Stopping thread ID: {threadID}...attempt number {i}.')
                    sleep(3)
                    i += 1
                if self.threadsDict[threadID].is_alive():
                    logging.error(f'Maximum number of attempts reached. Thread ID: {threadID} termination failed!')
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
        clearConsole(self.os)
        try:
            if self.threadsDict[threadID].is_alive():
                currentID = self.threadsDict[threadID].currentPktID
                while currentID == 0 or not self.threadsDict[threadID].pktBuffer:
                    logging.info('No traffic captured so far...')
                    sleep(3)
                while True:
                    if currentID <= self.threadsDict[threadID].currentPktID:
                        print(f'Pkt ID {currentID} : {self.threadsDict[threadID].pktBuffer[currentID].show2()}')
                        currentID += 1
            else:
                i = 1
                for pkt in self.threadsDict[threadID].sniffResults:
                    print(f'Pkt ID: {i} : {pkt.summary()}')
                    i += 1
        except KeyboardInterrupt:
            return
        except Exception as err:
            logging.error(err)

    def showRealtimeSummary(self, threadID):
        clearConsole(self.os)
        try:
            if self.threadsDict[threadID].is_alive():
                currentID = self.threadsDict[threadID].currentPktID
                while currentID == 0 or not self.threadsDict[threadID].pktBuffer:
                    logging.info('No traffic captured so far...')
                    sleep(3)
                while True:
                    if currentID <= self.threadsDict[threadID].currentPktID:
                        print(f'Pkt ID {currentID} : {self.threadsDict[threadID].pktBuffer[currentID].summary()}')
                        currentID += 1
            else:
                i = 1
                for pkt in self.threadsDict[threadID].sniffResults:
                    print(f'Pkt ID: {i} : {pkt.summary()}')
                    i += 1
        except KeyboardInterrupt:
            return
        except Exception as err:
            logging.error(err)
            
    def showTCPDumpRealtime(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                for line in iter(self.threadsDict[threadID].sniffProc.stdout.readline, ''):
                    print(line)
            else:
                logging.info('The thread selected is not running')
        except KeyboardInterrupt:
            return
    
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
            
            if self.threadsDict[selectedThread].sniffType == 'Scapy':
                optionDict = {'1' : [self.showRealtimeSummary, 'Display a summary of the captured packets in realtime'],
                              '2' : [self.showRealtimeVerbose, 'Display the whole content of the captured packets in realtime'],
                              '3' : [self.saveCapture, 'Save the capture in a file'],
                              '4' : [self.stopThread, 'Stop thread\'s execution'],
                              '5' : [self.removeThread, 'Remove this thread']}
            else:
                optionDict = {'1' : [self.showTCPDumpRealtime, 'Display the captured packets in realtime'],
                              '2' : [self.stopThread, 'Stop thread\'s execution'],
                              '3' : [self.removeThread, 'Remove this thread']}
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

    def readpcap(self):
        captures =  getCaps()
        if not captures:
            logging.info('There are no capture files you can read')
            return
        
        userChoice = menuOptValidator(text = 'Select a capture file (empty to exit): ',
                                      menu = captures, showMenu = True, clearUI = self.os, allowEmpty=True,
                                      title = (f'Display the contents of a packet capture (pcap file)', 3))
        if not userChoice:
            return
        clearConsole(self.os)
        for packet in PcapReader(f'./temp/{captures[userChoice]}'):
            print(packet.summary())

    def saveCapture(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                logging.error(f'You cannot write the capture until the thread. Thread ID: {threadID} is still running')
                return
        except:
            pass

    def removeThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                logging.error(f'You cannot delete a running thread. Thread ID: {threadID} is still running')
                return
            del(self.threadsDict[threadID])
            sleep(1)
            if threadID not in self.threadsDict:
                logging.info(f'Thread ID: {threadID} has been deleted successfully.')
        except Exception:
            logging.error(f'You cannot take this action. Thread ID: {threadID} does not exist')

    def menuOptions(self):
    
        optionDict = OrderedDict()

        optionDict = {'1' : [self.startScapySniff, 'Capture traffic using Scapy'],
                      '2' : [self.startTCPDumpSniff, 'Capture traffic using TCPDump'], 
                      '3' : [self.threadControl, 'Show and control the traffic capturing threads'],
                      '4' : [self.readpcap, 'Display the contents of a packet capture (pcap file)'],
                      #'5' : [self.stop, 'Stop'],
                      '9' : [self.exitModule, 'Return to Main Menu']}

        while not self.exitMenu:

            self.userHelpChoice = menuOptValidator(text = 'Enter a menu option: ', menu = optionDict, showMenu = True,
                                                   allowEmpty = False, clearUI = self.os,
                                                   title = ('CAPTURE TRAFFIC - Module Menu', 2))

            optionDict[self.userHelpChoice][0]()
            input('Press ENTER to continue...')

    def launch(self):
        try:
            self.exitMenu = False
            self.resourceLoader()
            self.menuOptions()
            return('send', None)
        except KeyboardInterrupt:
            raise
        except Exception as err:
            logging.critical(f'Module exiting... Error: {err}')
            raise

#a = tSniff()
#a.launch()
#a.parseThreadOptions()
#print(a)