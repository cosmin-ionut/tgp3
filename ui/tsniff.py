from collections import OrderedDict
from datetime import datetime
from subprocess import Popen, PIPE, signal
from threading import Thread
from time import sleep
from core.bootstrap import bootstrap
from scapy.all import *
from utils.getCaps import getCaps
from utils.menuOptValidator import menuOptValidator
from utils.uiUtils import clearConsole, titleFormatter

class sniffThCreator(Thread):

    def __init__(self, iface=None, sniffOptions=None, sniffType=None, os=None):
        Thread.__init__(self)
        self.currentPktID = 0
        self.iface = iface
        self.daemon = True
        self.os = os
        self.sniffOptions = sniffOptions
        self.stopFlag = Event()
        self.pktBuffer = []
        self.sniffType = sniffType
        self.capname = f'./captures/{sniffType}_{str(datetime.now().time())}.pcap'.replace(':', '_')

    def scapyAsyncCallback(self, pkt):
        self.pktBuffer.append(pkt)
        self.currentPktID += 1
    
    
    #windows implementation of scapy sniffer. It works awesome

    def getId(self):
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def scapyStop(self):
        thread_id = self.getId()
        resu = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread_id), ctypes.py_object(KeyboardInterrupt))
        if resu > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            logging.error('Failure in stopping the thread')
    
    def scapyWinSniffer(self):
        try:
            if 'store' in self.sniffOptions and (self.sniffOptions['store'] == 'yes' or self.sniffOptions['store'] == True):
                self.sniffOptions['store'] = True
            else:
                self.sniffOptions['store'] = False
            sniffResult = sniff(prn = self.scapyAsyncCallback, iface = self.iface, **self.sniffOptions)
            if self.sniffOptions['store']:
                wrpcap(self.capname, sniffResult)
        except KeyboardInterrupt:
            if self.sniffOptions['store']:
                wrpcap(self.capname, sniffResult)
            return
        except Exception as err:
            logging.error(err)
            self.error = err
    ############################################################################

    def scapyLinSniffer(self):
        #Linux version because Linux sux
        try:
            if 'store' in self.sniffOptions and (self.sniffOptions['store'] == 'yes' or self.sniffOptions['store']==True):
                self.sniffOptions['store'] = True
            else:
                self.sniffOptions['store'] = False
            asyncThread = AsyncSniffer(prn=self.scapyAsyncCallback, iface=self.iface, **self.sniffOptions)
            asyncThread.start()
            while True:
                sleep(2)
                if self.stopFlag.is_set():
                    asyncThread.stop()
                    del(self.pktBuffer)
                    if self.sniffOptions['store'] == True:
                        wrpcap(self.capname, asyncThread.results)
                    break
                if not asyncThread.running:
                    del(self.pktBuffer)
                    if self.sniffOptions['store']:
                        wrpcap(self.capname, asyncThread.results)
                    break
        except Exception as err:
            if asyncThread.running:
                asyncThread.stop()
            del(self.pktBuffer)
            logging.error(err)

    def tcpdumpSniffer(self):
        command = ['tcpdump']
        if 'write_to_file' in self.sniffOptions and self.sniffOptions['write_to_file'] == 'yes':
            command.extend(['-w', self.capname])
        if 'count' in self.sniffOptions:
            command.extend(['-c', str(self.sniffOptions['count'])])
        if 'direction' in self.sniffOptions:
            command.append(f"--direction={self.sniffOptions['direction']}")
        if 'verify_checksums' in self.sniffOptions and self.sniffOptions['verify_checksums'] == 'no':
            command.append('--dont-verify-checksums')
        if 'verbose_level' in self.sniffOptions:
            command.append('-'+'v'*int(self.sniffOptions['verbose_level']))
        command.extend(['-e', '--number','--print', '-l', '-i', self.iface])
        if 'filter' in self.sniffOptions:
            command.append(self.sniffOptions['filter'])
        try:
            self.sniffProc = Popen(command, stdout=PIPE, stderr=PIPE, preexec_fn=os.setpgrp)
            self.iterOut = iter(self.sniffProc.stdout)
            while not self.stopFlag.is_set():
                if self.sniffProc.poll() != None:
                    break
                sleep(1)
            self.sniffProc.terminate()
            sleep(2)
            error = self.sniffProc.communicate()[1].decode('UTF-8')
            if error:
                raise Exception(error)
        except Exception as err:
            self.sniffProc.terminate()
            logging.error(err)

    def run(self):
        if self.sniffType == 'Scapy' and self.os == 'Linux':
            self.scapyLinSniffer()
        elif self.sniffType == 'Scapy' and self.os == 'Windows':
            self.scapyWinSniffer()
        elif self.sniffType == 'TCPDump':
            self.tcpdumpSniffer()

class tSniff(object):

    hasUI = True
    showUIMenu = "Capture traffic"
    _instance = None

    def __new__(cls): # singleton. Make sure there can be only one craft object and use that
        if cls._instance is None:
            cls._instance = super(tSniff, cls).__new__(cls)
        return cls._instance

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
        '''- Allows you to capture the traffic on an interface using Scapy\'s AsyncSniffer.\n''' \
        '''- You will be prompted to choose the interface and various other Scapy specific parameters.\n''' \
        '''- The specific parameters are: "count" (number of packets to capture then stop), "store" (save the capture),\n''' \
        '''  "filter" (the BPF syntax packet filter string), "timeout" (interval in seconds after which the capture will stop)'''
        '''- If for the option 'store' you enter 'yes', then, the captured traffic will be saved in a pcap file.\n''' \
        '''- When all the needed options are selected, a thread will be created and traffic will be captured.\n''' \
        '''- AsyncSniffer performance limitations also apply to this implementation'''

        userInput = menuOptValidator(text = 'Choose an interface to capture traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('CAPTURE TRAFFIC >> Capture traffic using Scapy >> Choose the interface', 3))
        if not userInput:
            return

        selectedIface = self.ifacesDict[userInput]

        options = {'count' : int, 'store': ['yes','no'], 'filter': str, 'timeout': float}
        thread = sniffThCreator(iface = selectedIface, sniffOptions = self.parseThreadOptions(options), sniffType = 'Scapy', os = self.os)
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread
        logging.info(f'Capturing packets on interface {selectedIface}')

    def startTCPDumpSniff(self):
        '''- Allows you to capture the traffic on an interface using TCPDump.\n''' \
        '''- You will be prompted to choose the interface and various other TCPDump specific parameters.\n''' \
        '''- The specific parameters are: "count" (number of packets to capture then stop), "verify_checksums" (accept only CRC valid frames or accept everything),\n''' \
        '''  "direction" (capturing direction: ingress, egress or both), "verbose_level" (amount of information to display while monitoring the capture),\n''' \
        '''  "write_to_file" (save the captured packets), "filter" (TCPDump filter string).\n''' \
        '''- When all the needed options are selected, a thread will be created and traffic will be captured.\n''' \
        '''- TCPDump limitations are also applicable.'''

        if not self.tcpdump:
            clearConsole(self.os)
            print(titleFormatter('CAPTURE TRAFFIC >> Capture traffic using TCPDump', level=3))
            logging.info('TCPDump is not available on this machine. Cannot proceed!')
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
                if self.threadsDict[threadID].sniffType == 'Scapy' and self.os == 'Windows':
                    self.threadsDict[threadID].scapyStop()
                else:
                    self.threadsDict[threadID].stopFlag.set()
                i = 1
                while i <= 2 and self.threadsDict[threadID].is_alive():
                    logging.info(f'Stopping thread ID: {threadID}...attempt number {i}.')
                    sleep(3)
                    i += 1
                if self.threadsDict[threadID].is_alive():
                    raise Exception(f'Maximum number of attempts reached. Thread ID: {threadID} termination failed!')
                elif not self.threadsDict[threadID].is_alive():
                    print(f'Thread ID: {threadID}\'s execution has been stopped')
                    return True
            else:
                logging.info(f'Thread ID: {threadID} is not executing.')
                return True
        except Exception as err:
            logging.error(f'Error occured during thread termination. Error: {err}')
            return False

    def restartThread(self, threadID):

        sniffType = self.threadsDict[threadID].sniffType
        iface = self.threadsDict[threadID].iface
        sniffOptions = self.threadsDict[threadID].sniffOptions

        print(sniffType,iface, sniffOptions)

        if not self.stopThread(threadID):
            logging.error(f'Failed to restart thread\'s {threadID} execution')
            return
        
        if not self.removeThread(threadID):
            logging.error(f'Failed to restart thread\'s {threadID} execution')
            return

        thread = sniffThCreator(iface = iface, sniffOptions = sniffOptions, sniffType = sniffType, os = self.os)
        thread.start()
        self.threadsDict[threadID] = thread
        logging.info(f'Thread ID {threadID} has been restarted')

    def showRealtimeVerbose(self, threadID):
        clearConsole(self.os)
        try:
            if self.threadsDict[threadID].is_alive():
                currentID = self.threadsDict[threadID].currentPktID
                while not self.threadsDict[threadID].pktBuffer:
                    logging.info('No traffic captured so far...')
                    sleep(3)
                while True:
                    if currentID < self.threadsDict[threadID].currentPktID:
                        print(f'Pkt ID {currentID} : {self.threadsDict[threadID].pktBuffer[(currentID)].show2()}')
                        currentID += 1
            else:
                logging.info('The thread is not capturing traffic at this moment.')
                return
        except KeyboardInterrupt:
            return
        except Exception as err:
            logging.error(err)

    def showRealtimeSummary(self, threadID):
        clearConsole(self.os)
        try:
            if self.threadsDict[threadID].is_alive():
                currentID = self.threadsDict[threadID].currentPktID
                while not self.threadsDict[threadID].pktBuffer:
                    logging.info('No traffic captured so far...')
                    sleep(3)
                while True:
                    if currentID < self.threadsDict[threadID].currentPktID:
                        print(f'Pkt ID {currentID} : {self.threadsDict[threadID].pktBuffer[(currentID)].summary()}')
                        currentID += 1
            else:
                logging.info('The thread is not capturing traffic at this moment.')
                return
        except KeyboardInterrupt:
            return
        except Exception as err:
            logging.error(err)

    def showTCPDumpRealtime(self, threadID):
        clearConsole(self.os)
        #stdout = self.threadsDict[threadID].sniffProc.stdout
        try:
            if self.threadsDict[threadID].is_alive():
                #for line in iter(self.threadsDict[threadID].sniffProc.stdout.readline, ''):
                 while True:
                    print(next(self.threadsDict[threadID].iterOut))
                 #print(line)
            else:
                logging.info('The thread selected is not running')
                return
        except KeyboardInterrupt:
            return
            #self.threadsDict[threadID].sniffProc.stdout.flush()
        except Exception as err:
            logging.error(err)

    def threadControl(self):
        '''- Provides various actions related to the capturing threads, based on the tool used to capture traffic.\n''' \
        '''- Verbose or summary realtime view of the captured traffic if using Scapy \n''' \
        '''- Detailed realtime view (based on verbose level) of the captured traffic if using TCPDump.\n''' \
        '''- You can restart a thread's execution. This won't interfere with the "capture save" option.\n''' \
        '''- You can stop a thread's execution before its completion or when capturing for an indefinite amount of time.\n''' \
        '''- You can remove a thread (and the information it holds but not saved captures) after its execution is finished'''

        while True:
            clearConsole(self.os)
            print(titleFormatter('CAPTURE TRAFFIC >> Show and control the traffic capturing threads', level=3))

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
                              '3' : [self.restartThread, 'Restart thread\'s execution'],
                              '4' : [self.stopThread, 'Stop thread\'s execution'],
                              '5' : [self.removeThread, 'Remove this thread']}
            else:
                optionDict = {'1' : [self.showTCPDumpRealtime, 'Display the captured packets in realtime'],
                              '2' : [self.restartThread, 'Restart thread\'s execution'],
                              '3' : [self.stopThread, 'Stop thread\'s execution'],
                              '4' : [self.removeThread, 'Remove this thread']}
            while True:

                threadAction = menuOptValidator(text = 'Select an action for this thread (empty to exit): ',
                                                menu = optionDict, showMenu = True, clearUI = self.os, allowEmpty=True,
                                                title = (f'CAPTURE TRAFFIC >> Show and control the traffic capturing threads' \
                                                f' >> Thread ID {selectedThread} >> Actions you can take', 3))
                if not threadAction:
                    return

                optionDict[threadAction][0](selectedThread)
                input('Press ENTER to continue...')
                break

    def exitModule(self):
        self.exitMenu = True

    def readpcap(self):
        '''- Allows you to read the content of a pcap file using Scapy (summary view)'''

        try:
            captures =  getCaps()
            clearConsole(self.os)
            print(titleFormatter('CAPTURE TRAFFIC >> Display the contents of a packet capture (pcap file)', level=3))
            if not captures:
                logging.info('There are no capture files you can read')
                return

            userChoice = menuOptValidator(text = 'Select a capture file (empty to exit): ',
                                      menu = captures, showMenu = True, clearUI = self.os, allowEmpty=True,
                                      title = (f'Display the contents of a packet capture (pcap file)', 3))
            if not userChoice:
                return
            clearConsole(self.os)
            i = 1
            for packet in PcapReader(f'./captures/{captures[userChoice]}'):
                print(f'Pkt ID {i}: {packet.summary()}')
                i += 1
        except Exception as err:
            logging.error(f'Couldn\'t read the capture file. Error: {err}')

    def removeThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                logging.error(f'You cannot delete a running thread. Thread ID: {threadID} is still running')
                return False
            del(self.threadsDict[threadID])
            i = 1
            while threadID in self.threadsDict and i < 5:
                sleep(1)
                i += 1
            if threadID not in self.threadsDict:
                logging.info(f'Thread ID: {threadID} has been deleted successfully.')
                return True
            else:
                raise Exception(f'Thread ID: {threadID} couldn\'t be removed.')
        except Exception as err:
            logging.error(f'Error: \'{err}\' occurred while trying to remove the thread')
            return False

    def menuOptions(self):

        optionDict = OrderedDict()

        optionDict = {'1' : [self.startScapySniff, 'Capture traffic using Scapy'],
                      '2' : [self.startTCPDumpSniff, 'Capture traffic using TCPDump'], 
                      '3' : [self.threadControl, 'Show and control the traffic capturing threads'],
                      '4' : [self.readpcap, 'Display the contents of a packet capture (pcap file)'],
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
            return('capture', None)
        except KeyboardInterrupt:
            raise
        except Exception as err:
            logging.critical(f'CAPTURE TRAFFIC module exiting... Error: {err}')
            raise
