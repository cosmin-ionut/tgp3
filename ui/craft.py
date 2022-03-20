from collections import OrderedDict
from core.bootstrap import bootstrap
from scapy.all import *
from utils.menuOptValidator import menuOptValidator
from utils.uiUtils import clearConsole, titleFormatter
import logging

class craft(object):
    
    _instance = None
    hasUI = True
    showUIMenu = "Packet Crafting"
    
    def __new__(cls): # singleton. Make sure there can be only one craft object and use that
        if cls._instance is None:
            cls._instance = super(craft, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.pkt = ''
        self.pktList = {}
    
    def resourceLoader(self):
        if 'environment' not in bootstrap.resources:
            raise Exception('The OS type is not available.')
        self.os = bootstrap.resources['environment']['os']
    
    def showPacketDetails(self):
        '''- Displays the specifics of a header, which is the fields that can be modified.\n''' \
        '''- It is case sensitive.\n''' \
        '''- The header has to be typed exactly as returned by options 1 or 3 of Packet Crafting module.\n''' \
        '''- It has the same functionality as scapy's ls(Header) function'''

        uiError = ''
        while True:
            clearConsole(self.os)
            print(titleFormatter('PACKET CRAFTING >> Display the details about a specific packet type', level=3))
            print(uiError)
            packet = input("What kind of packet you need info about? (empty to exit): ")
            if packet == '':
                return
            elif hasattr(scapy.all, packet):
                ls(getattr(scapy.all, packet))
                return
            else:
                uiError = f"Invalid input '{packet}'! Please try again!"
                continue

    def searchPacket(self):
        '''- Allows you to search for a specific header.\n''' \
        '''- Takes your input and displays all matching headers.\n''' \
        '''- Not case sensitive.\n''' \
        '''- It has the same functionality as scapy's ls("Header") function'''

        uiError = ''
        while True:
            clearConsole(self.os)
            print(titleFormatter('PACKET CRAFTING >> Search for a packet type', level=3))
            print(uiError)
            keyword = input("Search keyword: (empty to exit): ")
            if keyword == '':
                return
            else:
                try:
                    ls(keyword)
                    input('Press ENTER to continue')
                except:
                    continue

    def addHeader(self):
        clearConsole(self.os)
        print(titleFormatter('PACKET CRAFTING >> Craft a packet that you can send >> Add Header', level=3))
        print(self.craftOutput)
        userHeader = input('Type what header you want to add to the packet (empty to quit): ')
        if hasattr(scapy.all, userHeader):
            if self.pkt == "":
                header = userHeader + "("
            else:
                header = "/" + userHeader + "("
            fields = (eval('%s()' % userHeader).show(dump = True)).split('\n')
            fields = [field[0:field.find('=')].strip().replace('\\', '') for field in fields if "#" not in field and field != '']
            for field in fields:
                userValueForField = input("Enter a value for %s's '%s' field (empty for default): " % (userHeader, field))
                if userValueForField != '':
                    try:
                        userValueForField = int(userValueForField)
                        header = header + "%s=%s" % (field, userValueForField)
                    except:
                        header = header + "%s='%s'" % (field, userValueForField)
                    header = header + ','
            if header[-1] == ",":
                header = header[0:-1] + ')'
            else:
                header = header + ')'
            self.pkt = self.pkt + header
            self.craftOutput = 'Header added succesfully!'
            return False
        elif userHeader == "": #True booleans stop the creation of the packet. So if the user enters nothing when asked about a header, the packet creation process stops
            return True
        else:
            self.craftOutput = f"The header '{userHeader}' is incorrect. Headers are case-sensitive. Try again"
            return False

    def setIndex(self):
        i = 1
        while str(i) in self.pktList:
            i += 1
        return str(i)
    
    def addRawLoad(self):
        uiError = ''
        while True:
            clearConsole(self.os)
            print(titleFormatter('PACKET CRAFTING >> Craft a packet that you can send >> Specify Payload Size', level=3))
            print(uiError)
            userBytesNumber = input('Payload size in bytes? ')
            try:   
                payloadHeader = "/Raw(load=RandBin({}))".format(int(userBytesNumber))
                break
            except:
                uiError = 'Invalid input! Please try again!'
        self.pkt = self.pkt + payloadHeader
        print(f'The payload of {userBytesNumber} bytes has been added to the packet.')

    def craft(self):
        '''- Starts the packet building process.\n''' \
        '''- Asks you what headers should be added to the packet, and asks for values for the specific fields.\n''' \
        '''- The headers are case-sensitive\n''' \
        '''- When you are done adding heades to the packet, you will be asked to specify the payload size in bytes.\n''' \
        '''- When the whole process is done, the built packet will be validated.'''

        self.craftOutput = ''
        try:
            self.pkt = ''
            while not self.addHeader():
                pass
            if self.pkt != '':
                self.addRawLoad()
                self.pkt = eval(self.pkt)
                self.pkt.show2()
                index = self.setIndex()
                if int(index) >= 100:
                    logging.error('There are too many crafted packets. You must remove some of them before creating others')
                    return
                self.pktList[index] = self.pkt
                print(f'Packet number {index} has been created')   
            return
        except Exception as err:
            logging.error(f'Failed to craft the packet. Error: {err}')
            return

    def existingPkt(self):
        '''- Displays a summary of all the already crafted packets.\n''' \
        '''- Allows you to see the details for each packet.\n''' \
        '''- Checking the details of the packet, will also validate its content.\n''' \
        '''- The validation checks the details of each header, and, to some degree, the compatibility of each header with one another.'''

        clearConsole(self.os)
        print(titleFormatter('PACKET CRAFTING >> Validate and show a currently existing packet', level=3))
        if len(self.pktList) != 0:
            try:
                for k,v in self.pktList.items():
                    if int(k) >= 100:
                        continue
                    print(f'Packet ID {k} : {v.summary()}')
                ui = menuOptValidator(text = 'Choose a packet ID (empty to exit): ', menu = self.pktList)
                if not ui:
                    return
                self.pktList[ui].show2()
            except Exception as err:
                logging.error(f'Invalid packet! Error: {err}')
        else:
            print ("\n Currently, there is no crafted packet \n")

    def removePkt(self):
        '''- Displays a summary of all the already crafted packets and allows you to remove any of them.\n'''

        clearConsole(self.os)
        print(titleFormatter('PACKET CRAFTING >> Remove an existing packet', level=3))
        if len(self.pktList) != 0:
            try:
                for k,v in self.pktList.items():
                    if int(k) >= 100:
                        continue
                    print(f'Packet ID {k} : {v.summary()}')
                ui = menuOptValidator(text = 'Choose a packet ID (empty to exit): ', menu = self.pktList)
                if not ui:
                    return
                self.pktList.pop(ui)
            except Exception as err:
                logging.error(f'Removal failed! Error: {err}')
        else:
            print ("\n Currently, there is no crafted packet \n")


    def exitModule(self):
        self.exitMenu = True
    
    def menuOptions(self):
        
        optionDict = OrderedDict()

        optionDict = {'1' : [ls, 'Display all packet types that you can craft'],
                      '2' : [self.showPacketDetails, 'Display the details about a specific packet type'],
                      '3' : [self.searchPacket, 'Search for a packet type'],
                      '4' : [self.craft, 'Craft a packet that you can send'],
                      '5' : [self.existingPkt, 'Validate and show a currently existing packet'],
                      '6' : [self.removePkt, 'Remove an existing packet'],
                      '9' : [self.exitModule, 'Return to Main Menu']}
        
        while not self.exitMenu:
            
            userChoice = menuOptValidator(text = 'Enter a menu option: ',
                                             menu = optionDict, 
                                             showMenu = 2,
                                             allowEmpty = False,
                                             clearUI = self.os,
                                             title = ('PACKET CRAFTING - Module Menu', 2))

            optionDict[userChoice][0]()
            input('Press ENTER to continue...')

    def launch(self):
        try:
            self.exitMenu = False
            self.resourceLoader()
            self.menuOptions()
            return('packets', self.pktList)
        except KeyboardInterrupt:
            raise
        except Exception as err:
            logging.critical(f'Module exiting... Error: {err}')
            raise