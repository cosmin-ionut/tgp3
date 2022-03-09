from collections import OrderedDict
from core.bootstrap import bootstrap
from scapy.all import *
from utils.menuOptValidator import menuOptValidator
from utils.uiUtils import clearConsole, titleFormatter
import logging

class craft(object):
    
    _instance = None
    
    def __new__(cls): # singleton. Make sure there can be only one craft object and use that
        if cls._instance is None:
            cls._instance = super(craft, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.pkt = ''
        self.pktList = {}
        #self.exitMenu = False

    hasUI = True
    showUIMenu = "Packet Crafting"
    
    def resourceLoader(self):
        if 'environment' not in bootstrap.resources:
            raise Exception('The OS type is not available.')
        self.os = bootstrap.resources['environment']['os']
    
    def showPacketDetails(self):
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

    def addLayer(self):
        clearConsole(self.os)
        print(titleFormatter('PACKET CRAFTING >> Craft a packet that you can send >> Add Layer', level=3))
        print(self.craftOutput)
        userLayer = input('Type what layer you want to add to the packet (empty to quit): ')  # takes the user's input regarding a layer to add to the packet (Ether, IP, etc.)
        if hasattr(scapy.all, userLayer):    #verifies that the layer exists in scapy and if it does, starts building the layer (populating the fields)
            if self.pkt == "":
                layer = userLayer + "("
            else:
                layer = "/" + userLayer + "("
            fields = (eval('%s()' % userLayer).show(dump = True)).split('\n')
            fields = [field[0:field.find('=')].strip().replace('\\', '') for field in fields if "#" not in field and field != '']
            for field in fields:
                userValueForField = input("Enter a value for %s's '%s' field (empty for default): " % (userLayer, field))
                if userValueForField != '':
                    layer = layer + "%s='%s'" % (field, userValueForField)
                    layer = layer + ','
            if layer[-1] == ",":
                layer = layer[0:-1] + ')'
            else:
                layer = layer + ')'
            self.pkt = self.pkt + layer
            self.craftOutput = 'Layer added succesfully!'
            return False
        elif userLayer == "": #True booleans stop the creation of the packet. So if the user enters nothing when asked about a layer, the packet creation process stops
            return True
        else:
            self.craftOutput = f"The layer '{userLayer}' is incorrect. Layers are case-sensitive. Try again"
            #print (f"The layer {userLayer} is either incorrect or not yet available. Try again")
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
                payloadLayer = "/Raw(load=RandBin({}))".format(int(userBytesNumber))
                break
            except:
                uiError = 'Invalid input! Please try again!'
        self.pkt = self.pkt + payloadLayer
        print(f'The payload of {userBytesNumber} bytes has been added to the packet.')

    def craft(self):
        self.craftOutput = ''
        try:
            self.pkt = ''
            while not self.addLayer():
                pass
            if self.pkt != '':
                self.addRawLoad()
                self.pkt = eval(self.pkt)
                self.pkt.show2()
                index = self.setIndex()
                self.pktList[index] = self.pkt
                print(f'Packet number {index} has been created')   
            return
        except Exception as err:
            logging.error(f'Failed to craft the packet. Error: {err}')
            return

    def existingPkt(self):
        clearConsole(self.os)
        print(titleFormatter('PACKET CRAFTING >> Validate and show a currently existing packet', level=3))
        if len(self.pktList) != 0:
            try:
                for k,v in self.pktList.items():
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
        clearConsole(self.os)
        print(titleFormatter('PACKET CRAFTING >> Remove an existing packet', level=3))
        if len(self.pktList) != 0:
            try:
                for k,v in self.pktList.items():
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