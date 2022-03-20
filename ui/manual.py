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
                       'However, due to Scapy\'s validation, some of these fields might be removed, or, turned to payload as Raw data'}

        for k, v in d.items():
            print(k + '\n' + v + '\n')

    def exitModule(self):
        self.exitMenu = True
    
    def menuOptions(self):

        optionDict = {'1' : [self.packetCraftingManual, 'Packet Crafting Manual'],
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