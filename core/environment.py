import logging
from platform import system
from re import findall
from sys import version_info
from importlib import util
from subprocess import Popen, check_output

class environment(object):

    def __init__(self):
        self.operatingSystem = system()
        self.ifaces = {}

    def getInterfaceList(self):
        if self.operatingSystem == 'Windows':
            self.rawInterfaceString = check_output(['ipconfig','/all'], encoding='utf8')
        elif self.operatingSystem == 'Linux':
            self.rawInterfaceString = check_output('ip link', shell=True, encoding='utf8')
        else:
            raise Exception(f"ERROR: Unsupported operating system: {self.operatingSystem} for this application") 
        return

    def parseInterfaceList(self):
        i = 1
        if self.operatingSystem == 'Windows':
            interfaces = findall('\Description[^\n]*', self.rawInterfaceString)
            for iface in interfaces:
                self.ifaces[str(i)] = iface[iface.find(":") + 2:]
                i += 1
        elif self.operatingSystem == 'Linux':
            interfaces = findall(':.*<', self.rawInterfaceString)
            for iface in interfaces:
                self.ifaces[str(i)] = iface[2:-3]
                i += 1
        else:
            raise Exception(f"ERROR: Unsupported operating system: {self.operatingSystem} for this application") 
    
    def checkPythonVersion(self):
        if int(version_info.major) < 3 and int(version_info.minor) < 8:
            raise Exception('Python version 3.8 or newer required to run this application')
    
    def checkScapy(self):
        hasScapy = util.find_spec('scapy')
        if not hasScapy:
            raise Exception('Scapy version 2.4.3 or newer required to run this application')
    
    def checkTCPDump(self):
        try:
            Popen(['tcpdump', '--h'])
            return True
        except:
            return False
            
    def checkTCPReplay(self):
        try:
            Popen(['tcpreplay', '-V'])
            return True
        except:
            return False 

    def launch(self):
        try:
            self.checkPythonVersion()
            self.checkScapy()
            tcpdump = self.checkTCPDump()
            tcpreplay = self.checkTCPReplay()
            self.getInterfaceList()
            self.parseInterfaceList()
            return ("environment", {'ifaces': self.ifaces, 'os':self.operatingSystem, 'tcpdump':tcpdump, 'tcpreplay':tcpreplay})
        except Exception as err:
            logging.error(err)
