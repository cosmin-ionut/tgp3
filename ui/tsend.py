import logging
from subprocess import PIPE, Popen
from collections import OrderedDict
from scapy.all import *
from threading import Thread
from time import sleep
from utils.menuOptValidator import menuOptValidator
from utils.uiUtils import clearConsole, titleFormatter
from utils.getCaps import getCaps
from core.bootstrap import bootstrap

class sendThCreator(Thread):

    def __init__(self, pkt, trafficID, iface, sendOptions=None, sendFunction=None):
        Thread.__init__(self)
        self.pkt = pkt
        self.sendOptions = sendOptions
        self.stopFlag = Event()
        self.daemon = True
        self.error = None
        self.sentCount = 'undefined'
        self.sendFunction = sendFunction
        self.iface = iface
        self.trafficID = trafficID
  
    def getId(self):
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def scapyStop(self):
        thread_id = self.getId()
        resu = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, ctypes.py_object(KeyboardInterrupt))
        if resu > 1: 
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            logging.error('Failure in stopping the thread')

    def scapySend(self):
        try:
            if 'loop' not in self.sendOptions or 'loop' in self.sendOptions and self.sendOptions['loop'] == 'no':
                self.sendOptions['loop'] = False
            else:
                self.sendOptions['loop'] = True
            self.sentCount = len(sendp(self.pkt, iface=self.iface, verbose = 0, return_packets = True, **self.sendOptions))
        except KeyboardInterrupt:
            return
        except Exception as err:
            logging.error(err)
            self.error = err

    def sendTCPReplay(self):

        ###### CREATE THE TCPREPLAY COMMAND BASED ON USER'S INPUT ######
        command = ['tcpreplay', '--quiet', '--preload-pcap', '-i', self.iface]
        if 'mbps' in self.sendOptions:
            command.append(f"--mbps={int(self.sendOptions['mbps'])}")
        elif 'pps' in self.sendOptions:
            command.append(f"--pps={int(self.sendOptions['pps'])}")
        else:
            command.append(f"--topspeed")

        if 'count' in self.sendOptions:
            command.append(f"--loop={int(self.sendOptions['count'])}")
        else:
            command.append("--loop=1")
        command.append(self.pkt)
        ###### CALL TCPREPLAY, POPULATE THREAD INFO AND TRY TO CATCH THE ERRORS ########
        try:
            sendProc = Popen(command, stdout=PIPE, stderr=PIPE)
            while not self.stopFlag.is_set():
                if sendProc.poll() != None:
                    break
                sleep(1)
            sendProc.terminate()
            sleep(2)
            results = sendProc.communicate()[0].decode('UTF-8')
            error = sendProc.communicate()[1].decode('UTF-8')
            if error:
                raise Exception(error)
            self.sendOptions = command
            self.sentCount = results 
            
        except Exception as err:
            self.error = err
            logging.error(err)

    ################# THREADS'S RUN FUNCTION #####################################
    def run(self):
        try:
            if self.sendFunction == 'Scapy':
                self.scapySend()
            elif self.sendFunction == 'TCPReplay':
                self.sendTCPReplay()
        except:
            logging.info('Exception occured')

class tSend(object):

    hasUI = True
    showUIMenu = "Send traffic"
    _instance = None

    def __new__(cls): # singleton. Make sure there can be only one craft object and use that
        if cls._instance is None:
            cls._instance = super(tSend, cls).__new__(cls)
        return cls._instance

    def __init__(self):
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
        self.tcpdump = bootstrap.resources['environment']['tcpdump']

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
            for pkt in rdpcap(f'./captures/{self.pkts[ui]}'):
                print(pkt.summary())

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

    def startScapyThread(self):

    ########## CHOOSE THE PACKET TO SEND OR CAPTURE TO REPLAY.... OR EXIT #############
        userTrInp = menuOptValidator(text = 'Select the packet\capture to send:', menu = self.pkts, showMenu = True,
                                     title = ('SEND TRAFFIC >> Send traffic using Scapy >> Choose a packet to send', 2),
                                     clearUI = self.os, allowEmpty=True)
        if not userTrInp:
            return
        if int(userTrInp) < 100:
            selectedTraffic = self.pkts[userTrInp]
        elif int(userTrInp) >= 100:
            selectedTraffic = rdpcap(f'./captures/{self.pkts[userTrInp]}')

   ############ CHOOSE THE SENDING INTERFACE OR EXIT ######################

        userInput = menuOptValidator(text = 'Choose the interface to send traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('SEND TRAFFIC >> Send traffic using Scapy >> Choose sending interface', 2))

        if not userInput:
            return

        selectedIface = self.ifacesDict[userInput]
        options = {'inter' : float, 'loop': ['yes','no'], 'count': int, 'realtime': ['yes','no']}
        
        thread = sendThCreator(pkt = selectedTraffic, trafficID = userTrInp, iface = selectedIface, sendOptions = self.parseThreadOptions(options), sendFunction = 'Scapy')
        thread.start()
        self.threadsDict[self.setThreadIndex()] = thread
        logging.info('The sending thread has been started')

    def startTCPReplayThread(self):
        if not self.tcpdump:
            clearConsole(self.os)
            print(titleFormatter('SEND TRAFFIC >> Send traffic using TCPReplay', level=3))
            logging.info('TCPDump is not available on this machine. Cannot proceed!')
            return

        userTrInp = menuOptValidator(text = 'Select the packet\capture to send:', menu = self.pkts, showMenu = True,
                                     title = ('SEND TRAFFIC >> Send traffic using TCPReplay >> Choose a packet to send', 2),
                                     clearUI = self.os, allowEmpty=True)
        if not userTrInp:
            return
        if int(userTrInp) < 100:
            wrpcap('./captures/tcp_rep_sp.pcap', self.pkts[userTrInp])
            selectedTraffic = './captures/tcp_rep_sp.pcap'
        elif int(userTrInp) >= 100:
            selectedTraffic = f'./captures/{self.pkts[userTrInp]}'

        userInput = menuOptValidator(text = 'Choose the interface to send traffic (empty to exit): ',
                                     menu = self.ifacesDict, showMenu = True, allowEmpty = True, clearUI = self.os,
                                     title = ('SEND TRAFFIC >> Send traffic using Scapy >> Choose sending interface', 2))

        if not userInput:
            return
        selectedIface = self.ifacesDict[userInput]

        options = {'pps':int, 'mbps':int, 'count':int}

        thread = sendThCreator(pkt = selectedTraffic, trafficID = userTrInp, iface = selectedIface, sendOptions = self.parseThreadOptions(options), sendFunction = 'TCPReplay')
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
                  f'Packet\Capture ID: {self.threadsDict[threadID].trafficID} \n' \
                  f'Sending interface: {self.threadsDict[threadID].iface} \n'
                  f'Send results: {self.threadsDict[threadID].sentCount} \n'
                  f'Send Type: {self.threadsDict[threadID].sendFunction} \n' \
                  f'Send Options: {self.threadsDict[threadID].sendOptions}')
        except Exception as err:
            logging.error(f'You cannot take this action. Error {err} occured while trying to fetch the Thread {threadID}\'s stats')

    def removeThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                logging.error(f'You cannot delete a running thread. Thread ID: {threadID} is still running')
                return False
            del(self.threadsDict[threadID])
            sleep(1)
            if threadID not in self.threadsDict:
                logging.info(f'Thread ID: {threadID} has been deleted successfully.')
                return True
            else:
                raise 
        except Exception as err:
            logging.error(f'Error occured during thread removal. Error: {err}')
            return False
    
    def stopThread(self, threadID):
        try:
            if self.threadsDict[threadID].is_alive():
                if self.threadsDict[threadID].sendFunction == 'Scapy':
                     self.threadsDict[threadID].scapyStop()
                else:
                    self.threadsDict[threadID].stopFlag.set()
                i = 1
                while i <= 3 and self.threadsDict[threadID].is_alive():
                    logging.info(f'Stopping thread ID: {threadID}...attempt number {i}.')
                    sleep(3)
                    i += 1
                if self.threadsDict[threadID].is_alive():
                    logging.error(f'Thread ID: {threadID} termination failed! Please try again')
                    raise
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

        selectedTraffic = self.threadsDict[threadID].pkt
        sendOptions = self.threadsDict[threadID].sendOptions
        trafficID = self.threadsDict[threadID].trafficID
        iface = self.threadsDict[threadID].iface
        sendFunction = self.threadsDict[threadID].sendFunction

        if not self.stopThread(threadID):
            logging.error(f'Failed to restart thread\'s {threadID} execution')
            return
        
        if not self.removeThread(threadID):
            logging.error(f'Failed to restart thread\'s {threadID} execution')
            return

        thread = sendThCreator(pkt = selectedTraffic, trafficID = trafficID, iface = iface, sendOptions = sendOptions, sendFunction = sendFunction)
        thread.start()
        self.threadsDict[threadID] = thread
        logging.info(f'Thread ID {threadID} has been restarted')

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
                          '3' : [self.restartThread, 'Restart thread\'s execution'],
                          '4' : [self.removeThread, 'Remove this thread']}

            while True:

                threadAction = menuOptValidator(text = 'Select an action for this thread (empty to exit): ',
                                                menu = optionDict, showMenu = True, clearUI = self.os, allowEmpty=True,
                                                title = (f'SEND TRAFFIC >> Show and control the sending threads' \
                                                f' >> Thread ID {selectedThread} >> Actions you can take', 3))
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