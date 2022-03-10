import logging
import signal
from subprocess import PIPE, Popen
from collections import OrderedDict
from scapy.all import *
from threading import Thread
from time import sleep
from math import ceil
from utils.menuOptValidator import menuOptValidator
from utils.uiUtils import clearConsole, titleFormatter
from utils.getCaps import getCaps
from core.bootstrap import bootstrap

class thCreator(Thread):

    def __init__(self, iface, sendOptions=None, sendFunction=None, pkt=None):
        Thread.__init__(self)
        self.pkt = pkt
        self.sendOptions = sendOptions
        self.stopFlag = Event()
        self.daemon = True
        self.error = None
        self.sentCount = 0
        self.sendFunction = sendFunction
        self.iface = iface

    def scapySend(self):
        try:
            sendOptions = self.sendOptions
            checkCount = 600 #the stop thread condition is checked every 600 packets sent.

            if 'inter' in sendOptions and float(sendOptions['inter']) != float(0):
                checkCount = ceil((1 / float(sendOptions['inter']))*3)

            # if the loop is true, then check the stop condition every
            if 'loop' in sendOptions and bool(sendOptions['loop']):
                sendOptions['count'] = checkCount
                while not self.stopFlag.is_set():
                    sendp(self.pkt, iface=self.iface, verbose = 0, **sendOptions)
                    self.sentCount += checkCount
                return

            if 'count' in sendOptions:
                totalCount = int(sendOptions['count'])
                if totalCount <= checkCount:
                    sendp(self.pkt, self.iface, verbose = 0, **sendOptions)
                    self.sentCount = totalCount
                    return
                else:
                    self.sentCount = 0
                    sendOptions['count'] = checkCount
                    while not self.stopFlag.is_set() and checkCount < totalCount:
                        sendp(self.pkt, iface=self.iface, verbose = 0, **sendOptions)
                        totalCount = totalCount - checkCount
                        self.sentCount += checkCount
                    sendOptions['count'] = totalCount
                    sendp(self.pkt, iface=self.iface, verbose = 0, **sendOptions)
                    self.sentCount += totalCount
                    return
        except Exception as err:
            logging.error(f'Error occured in the traffic send thread. Error: {err}')
            #self.error = err
            return

    def sendTCPReplay(self):

        ###### CREATE THE TCPREPLAY COMMAND BASED ON USER'S INPUT ######
        command = ['tcpreplay', '--quiet', '--preload-pcap', '-i', self.iface]
        if 'mbps' in self.sendOptions:
            command.append(f"--mbps={int(self.sendOptions['mbps'])}")
        elif 'pps' in self.sendOptions:
            command.append(f"--pps={int(self.sendOptions['pps'])}")
        else:
            command.append(f"--topspeed")

        if 'loop' in self.sendOptions:
            command.append(f"--loop={int(self.sendOptions['loop'])}")
        else:
            command.append("--loop=1")
        command.append(self.pkt)
        ###### CALL TCPREPLAY, POPULATE THREAD INFO AND TRY TO CATCH THE ERRORS ########
        try:
            sendProc = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
            while not self.stopFlag.is_set():
                if sendProc.poll() != None:
                    break
                sleep(1)
            sendProc.send_signal(subprocess.signal.SIGINT)
            sleep(2)
            if str(sendProc.communicate()[1]) != '':
                raise Exception(sendProc.communicate()[1])
        except Exception as err:
            self.error = str(err)
            logging.error(err)

    ################# THREADS'S RUN FUNCTION #####################################
    def run(self):
            if self.sendFunction == 'Scapy':
                self.scapySend()
            elif self.sendFunction == 'TCPReplay':
                self.sendTCPReplay()

class tSend(object):

    hasUI = True
    showUIMenu = "Send traffic"
    _instance = None

    def __new__(cls): # singleton. Make sure there can be only one craft object and use that
        if cls._instance is None:
            cls._instance = super(tSend, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.lastScapyConfig = None
        self.lastTcpReplayConfig = None
        self.threadsDict = OrderedDict()

    def resourceLoader(self):
        captures = getCaps()
        packets = 'packets' in bootstrap.resources and bootstrap.resources['packets']

        if 'environment' not in bootstrap.resources:
            raise Exception('OS critical resources are not available. Check \'environment\' module')
        if not captures:
            assert packets
            self.pkts = bootstrap.resources['packets']
        elif captures and packets:
            self.pkts = bootstrap.resources['packets']
            self.pkts.update(captures)
        else:
            self.pkts = captures
        self.ifacesDict = bootstrap.resources['environment']['ifaces']
        self.os = bootstrap.resources['environment']['os']

    def useLastConfig(self, type):

        pass
        #if type == 'Scapy' and self.lastScapyConfig:
        #    print('A previously used Scapy send configuration has been found')
        #
        #    useLast = input('W')
        # DE TERMINAT MANANA

    def showAvailablePackets(self):
        clearConsole(self.os)
        print(titleFormatter('SEND TRAFFIC >> Display the packets available to send', level=3))
        for k,v in self.pkts.items():
            if int(k) < 100:
                print(f'Packet ID {k} : {v.summary()}')
            else:
                print(f'Capture ID {k} : {v}')
        ui = menuOptValidator(text = 'Choose a packet ID (empty to exit): ', menu = self.pkts)
        if not ui:
            return
        if int(ui) < 100:
            self.pkts[ui].show2()
        else:
            for pkt in rdpcap(f'./temp/{self.pkts[ui]}'):
                print(pkt.summary())

    def setThreadIndex(self):
        i = 1
        while str(i) in self.threadsDict.keys():
            i += 1
        logging.info(f'The thread has been assigned ID: {i}')
        return str(i)

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

    def startScapyThread(self):

    ########## CHOOSE THE PACKET TO SEND OR CAPTURE TO REPLAY.... OR EXIT #############
        userInput = menuOptValidator(text = 'Select the packet\capture to send:', menu = self.pkts, showMenu = True,
                                     title = ('SEND TRAFFIC >> Send traffic using Scapy >> Choose a packet to send', 2),
                                     clearUI = self.os, allowEmpty=True)
        if not userInput:
            return
        if int(userInput) < 100:
            selectedTraffic = self.pkts[userInput]
        elif int(userInput) >= 100:
            selectedTraffic = rdpcap(f'./temp/{self.pkts[userInput]}')

   ############ CHOOSE THE SENDING INTERFACE OR EXIT ######################

        userInput = menuOptValidator(text = 'Choose the interface to send traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('SEND TRAFFIC >> Send traffic using Scapy >> Choose sending interface', 2))

        if not userInput:
            return

        selectedIface = self.ifacesDict[userInput]

        options = ['inter', 'loop', 'count', 'realtime']
        self.parseThreadOptions(options)

        thread = thCreator(pkt = selectedTraffic, iface = selectedIface, sendOptions = self.sendOptions, sendFunction = 'Scapy')
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread
        logging.info('The sending thread has been started')

    def startTCPReplayThread(self):
        userInput = menuOptValidator(text = 'Select the packet\capture to send:', menu = self.pkts, showMenu = True,
                                     title = ('SEND TRAFFIC >> Send traffic using TCPReplay >> Choose a packet to send', 2),
                                     clearUI = self.os, allowEmpty=True)
        if not userInput:
            return
        if int(userInput) < 100:
            wrpcap('./temp/tcp_rep_sp.pcap', self.pkts[userInput])
            selectedTraffic = './temp/tcp_rep_sp.pcap'
        elif int(userInput) >= 100:
            selectedTraffic = f'./temp/{self.pkts[userInput]}'

        userInput = menuOptValidator(text = 'Choose the interface to send traffic (empty to exit): ',
                                     menu = self.ifacesDict,
                                     showMenu = True,
                                     allowEmpty = True,
                                     clearUI = self.os,
                                     title = ('SEND TRAFFIC >> Send traffic using Scapy >> Choose sending interface', 2))

        if not userInput:
            return
        selectedIface = self.ifacesDict[userInput]
        options = ['pps', 'mbps', 'loop']
        self.parseThreadOptions(options)

        thread = thCreator(pkt = selectedTraffic, iface = selectedIface, sendOptions = self.sendOptions, sendFunction = 'TCPReplay')
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread
        logging.info('The sending thread has been started')

    def showThreadInfo(self, threadID):
        clearConsole(self.os)
        try:
            print(titleFormatter(f'SEND TRAFFIC >> Show and control the sending threads >> Thread ID {threadID} stats', level=3))
            print(f'------------Thread {threadID} stats:-------------- \n' \
                  f'Is thread still active?: {self.threadsDict[threadID].is_alive()} \n'
                  f'Error encountered: {self.threadsDict[threadID].error} \n' \
                  f'Packet summary: {self.threadsDict[threadID].pkt.summary()} \n' \
                  f'Sending interface: {self.threadsDict[threadID].iface} \n'
                  f'Number of packets sent: {self.threadsDict[threadID].sentCount} \n'
                  f'Send Type: {self.threadsDict[threadID].sendFunction} \n' \
                  f'Send Options: {self.threadsDict[threadID].sendOptions}')
        except Exception:
            logging.error(f'You cannot take this action. Thread ID: {threadID} does not exist')

    def removeThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                logging.error(f'You cannot delete a running thread. Thread ID: {threadID} is still running')
                return
            del(self.threadsDict[threadID])
            if threadID not in self.threadsDict:
                logging.info(f'Thread ID: {threadID} has been deleted successfully.')
        except Exception:
            logging.error(f'You cannot take this action. Thread ID: {threadID} does not exist')

    def stopThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                inter = 3
                if 'inter' in self.threadsDict[threadID].sendOptions:
                    inter = int(self.threadsDict[threadID].sendOptions['inter']) + 3
                logging.info(f'Thread ID: {threadID} will be stopped in {inter} seconds.')
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

    def threadControl(self):
        while True:
            clearConsole(self.os)
            print(titleFormatter('SEND TRAFFIC >> Show and control the sending threads', level=3))

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

            optionDict = {'1' : [self.showThreadInfo, 'Show information about the thread'],
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

    def menuOptions(self):

        optionDict = OrderedDict()

        optionDict = {'1' : [self.showAvailablePackets, 'Display the packets available to send'],
                      '2' : [self.startScapyThread, 'Send traffic using Scapy'],
                      '3' : [self.startTCPReplayThread, 'Send traffic using TCPReplay'],
                      '4' : [self.threadControl, 'Show and control the sending threads'],
                      '9' : [self.exitModule, 'Return to Main Menu']}

        while not self.exitMenu:

            self.userHelpChoice = menuOptValidator(text = 'Enter a menu option: ', menu = optionDict, showMenu = True,
                                                   allowEmpty = False, clearUI = self.os,
                                                   title = ('SEND TRAFFIC - Module Menu', 2))

            optionDict[self.userHelpChoice][0]()
            input('Press ENTER to continue...')

    def launch(self):
#        try:
            self.exitMenu = False
            self.resourceLoader()
            self.menuOptions()
            return('send', None)
#        except AssertionError:
#            logging.error(f'No packets have been crafted. There is nothing to send. Exiting module...')
#            input('Press ENTER to continue...')
#            return('send', None)
#        except KeyboardInterrupt:
#            raise
#        except Exception as err:
#            logging.critical(f'Module exiting... Error: {err}')
#            raise

# foloseste self.error pentru a verifica in functiile de meniu daca nu cumva exista erori.
