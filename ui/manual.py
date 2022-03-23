from ui.craft import craft
from ui.tsend import tSend
from ui.tsniff import tSniff
import logging
from utils.menuOptValidator import menuOptValidator
from utils.uiUtils import clearConsole, titleFormatter
from core.bootstrap import bootstrap

class manual(object):
  
    hasUI = True
    showUIMenu = "Manual"

    def __init__(self):
        self.os = 'Windows'

    def resourceLoader(self):
        if 'environment' not in bootstrap.resources:
            raise Exception('OS critical resources are not available. Check \'environment\' module')
        self.os = bootstrap.resources['environment']['os']

    def packetCraftingManual(self):
        clearConsole(self.os)
        print(titleFormatter('MANUAL >> Packet Crafting Manual', level=3))

        d = {'1. Display all packet types that you can craft':'- Displays all types of headers that can be added to a packet when crafting.\n- It is a call to scapy\'s \'ls()\'',
             '2. Display the details about a specific packet type':craft.showPacketDetails.__doc__,
             '3. Search for a packet type':craft.searchPacket.__doc__,
             '4. Craft a packet that you can send':craft.craft.__doc__,
             '5. Validate and show a currently existing packet':craft.existingPkt.__doc__,
             '6. Remove an existing packet':craft.removePkt.__doc__,
             'Caveats':'1. As the app must accomodate both user crafted packets and pcap files, the maximum ID that can be assigned to a packet is 99.\n' \
                       'This means that there can only exist 99 crafted packets, at the same time.\n' \
                       '2. During packet crafting you are allowed to add any header you might like, as many of them, in any order.\n' \
                       'However, due to Scapy\'s validation, some of these fields might be removed, or, turned to payload as Raw data.\n' \
                       '3. When entering field values during packet crafting, no error checking is performed. Only at the end (after the payload size is specified)\n' \
                       'the whole packet is validated and an error is raised if it is the case.'}

        for k, v in d.items():
            print(k + '\n' + v + '\n')
    
    def packetSendingManual(self):
        clearConsole(self.os)
        print(titleFormatter('MANUAL >> Packet Sending Manual', level=3))

        d = {'1. Display the traffic available to send':tSend.showAvailablePackets.__doc__,
             '2. Send traffic using Scapy':tSend.startScapyThread.__doc__,
             '3. Send traffic using TCPReplay':tSend.startTCPReplayThread.__doc__,
             '4. Show and control the sending threads':tSend.threadControl.__doc__,
             'Caveats':'1. When choosing sending options (count, loop, etc.) you are presented with the type of the value required (float, int, str),\n' \
                       'or [yes|no] if boolean. You can either provide one of the required values, or, enter nothing, for default values.\n' \
                       '2. Scapy/TCPReplay limitations are applicable. This goes for what option has priority over which (loop vs count, mbps vs pps),\n' \
                       'how packet/capture sending behaves when using multiple options (loop + count + capture) etc. \n' \
                       '3. Due to Python\'s limitations, you can\'t actually restart a thread. What happens is that the thread is stopped if executing,\n' \
                       'removed, and another thread with the same exact options will be created. The "restarted" (old) thread\'s data is lost.\n' \
                       '4. Due to compatibility reasons, a crafted packet has to be written in a capture to be sent using TCPReplay.\n' \
                       'These captures are called "tcpreplay_thid<id>_sp.pcap". There is no removal mechanism in place for these captures because \n' \
                       'a thread ID is unique, and when a thread is created, if the pcap already exists, its content is overwritten. Therefore, there can not be\n' \
                       'two threads using the same capture at the same time, and there can not be residual content in a pcap that would affect subsequent threads.\n' \
                       '5. Sending traffic using Scapy uses, at its base, sendp(). This function requires you to specify a layer 2 header for the packets that will be sent,\n' \
                       'otherwise errors may be raised by sendp() or malformed traffic will be sent'}
        
        for k, v in d.items():
            print(k + '\n' + v + '\n')

    def captureTrafficManual(self):
        clearConsole(self.os)
        print(titleFormatter('MANUAL >> Capture Traffic Manual', level=3))

        d = {'1. Capture traffic using Scapy':tSniff.startScapySniff.__doc__,
             '2. Capture traffic using TCPDump':tSniff.startTCPDumpSniff.__doc__,
             '3. Show and control the traffic capturing threads':tSniff.threadControl.__doc__,
             '4. Display the contents of a packet capture (pcap file)':tSniff.readpcap.__doc__,
             'Caveats':'1. When choosing sniffing options (count, filter, etc.) you are presented with the type of the value required (float, int, str),\n' \
                       'or [yes|no] if boolean. You can either provide one of the required values, or, enter nothing, for default values.\n' \
                       '2. Scapy/TCPDump limitations are applicable. This goes for what option has priority over which (timeout vs count).\n' \
                       '3. Capturing traffic using both TCPReplay and Scapy, is bound to miss traffic even at relatively low speeds.\n' \
                       'Don\'t count on them to sniff everything.'}
        
        for k, v in d.items():
            print(k + '\n' + v + '\n')

    def exitModule(self):
        self.exitMenu = True
    
    def menuOptions(self):

        optionDict = {'1' : [self.packetCraftingManual, 'Packet Crafting Manual'],
                      '2' : [self.packetSendingManual, 'Packet Sending Manual'],
                      '3' : [self.captureTrafficManual, 'Capture Traffic Manual'],
                      '9' : [self.exitModule, 'Return to Main Menu']}
        
        while not self.exitMenu:
            
            userChoice = menuOptValidator(text = 'Enter a menu option: ',
                                             menu = optionDict, 
                                             showMenu = 2,
                                             allowEmpty = False,
                                             clearUI = self.os,
                                             title = ('MANUAL - Module Menu', 2))

            optionDict[userChoice][0]()
            input('Press ENTER to continue...')

    def launch(self):
        try:
            self.exitMenu = False
            self.menuOptions()
            self.resourceLoader()
            return('manual', None)
        except KeyboardInterrupt:
            raise
        except Exception as err:
            logging.critical(f'Module exiting... Error: {err}')
            raise