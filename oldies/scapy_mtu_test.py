#from scapy.all import *
from threading import Thread

class trafficThread(Thread):

    def __init__(self, iface, frame, mtuList):
        Thread.__init__(self)
        self.mtuList = mtuList
        self.iface = iface
        self.frame = frame

    def sendTraffic(self):
        print "Now sending traffic on iface %s with MTU size %i" % (self.iface, self.mtu)
        sendp(self.frame/Raw(load=RandBin(self.mtu)), self.iface, count = 1200)

    def run(self):
        for mtu in self.mtuList:
            self.mtu = mtu
            self.sendTraffic()

class generateTraffic(object):

    def __init__(self, ifaces, frame, mtuList = [1500]):
        self.mtuList = mtuList
        self.ifaces = ifaces
        self.frame = frame
        self.threads = {}

    def start(self):
        i = 0
        for iface in self.ifaces:
            self.threads[i] = trafficThread(iface, frame = self.frame, mtuList = self.mtuList)
            print "Thread id: %i opened for interface %s" % (i, iface)
            self.threads[i].start()
            i += 1

class inputValidator(object):

    #def __init__(self, inputToValidate):
    #    self.inputToValidate = inputToValidate

    def isItAnInteger(self, input, minValue, maxValue):
        try:
            numericInput = int(input)
            if not (minValue <= numericInput <= maxValue):
              raise Exception("Invalid number '%i'. You must enter a number between %i and %i" % (numericInput, minValue, maxValue))
            return numericInput
        except ValueError, error:
            return "Invalid input '%s': Not a number" % input
        except Exception, error:
            return error


    def checkInterface(self):
        pass
    
class userDialog(object):

    def __init__(self):
        self.interfaces = []
        self.moreInterfaces = True

    def selectFirstInterface(self):
        userInput = raw_input("Enter the interface you want to send traffic on: ")
        if userInput != "":
            self.interfaces.append(userInput)
        else:
            exit()

    def selectInterface(self):
        userInput = raw_input("Add more interfaces if needed. If not, enter EMPTY answer: ")
        if userInput != "":
            self.interfaces.append(userInput)
        else:
            self.moreInterfaces = False

    def selectmtusizes(self):
        userInput = raw_input("Add all the MTU sizes, separated by comma: ")
        mtuList = userInput.split(',')
        for mtu in mtuList:
            mtuList[mtuList.index(mtu)] = mtu.replace(" ",'')
        self.mtuList = mtuList


    def validate(self):
        validator = inputValidator(self)



    def startDialog(self):
        while self.moreInterfaces:
            if len(self.interfaces) != 0:
                self.selectInterface()
            else:
                self.selectFirstInterface()


class showHelp(object):

    def __init__(self, validator):
        self.validator = validator
        #self.option = None

    def showMTUhelp(self):

        #self.option = 1

        print """MTU - Maximum Transmission Unit is the maximum amount of data
              that a Layer 2 frame can carry as its payload. It includes the 
              Layer 3 header plus data payload.
              For example if a simple Ethernet II frame (with no additional header fields
              such as 802.1Q) is 1518 bytes, then the MTU is 1500 bytes since the Ethernet II
              header plus FCS is 18 bytes"""

    def showHelpOptions(self):

        print """1. What is MTU?
        8. Show this help again
        9. Exit help menu and return
        """

    def helpOptions(self):
        
        self.optionDict = {1 : self.showMTUhelp,
                           2 : self.showHelpOptions,
                           9 : exit}
                           
        self.userHelpChoice = self.validator.isItAnInteger(raw_input("Enter a help option: "), 1, 9)

        if isinstance(self.userHelpChoice, int) == True:
            self.optionDict[self.userHelpChoice]()
            self.helpOptions()
        else:
            print self.userHelpChoice
            self.helpOptions()
            
a = showHelp(inputValidator())
a.helpOptions()

        




#userInput = userDialog()
#userInput.startDialog()

#mcastFrame = Ether(dst="01:00:5E:00:00:01", src="00:0a:cd:34:ef:70", type=4660)

#generator = generateTraffic(mtuList=[512,1500], ifaces = userInput.interfaces, frame = mcastFrame)
#generator.start()

