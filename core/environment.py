import re
import subprocess
import platform

class environment(object):

    def __init__(self):
        self.operatingSystem = platform.system()
        self.ifaces = {}

    def getInterfaceList(self):
        try:
            if self.operatingSystem == 'Windows':
                self.rawInterfaceString = subprocess.check_output(['ipconfig','/all'], encoding='utf8')
            elif self.operatingSystem == 'Linux':
                self.rawInterfaceString = subprocess.check_output('ip link', shell=True, encoding='utf8')
            else:
                raise Exception("ERROR: Unsupported operating system: '%s' for this application" % self.operatingSystem) 
            return
        except Exception as e:
            print (f"[FATAL] [Environment]: {e}")
            exit(1)

    def parseInterfaceList(self):
        try:
            i = 1
            if self.operatingSystem == 'Windows':
                interfaces =  re.findall('\Description[^\n]*', self.rawInterfaceString)
                for iface in interfaces:
                    self.ifaces[str(i)] = iface[iface.find(":") + 2:]
                    i += 1
            elif self.operatingSystem == 'Linux':
                interfaces =  re.findall(':.*<', self.rawInterfaceString)
                for iface in interfaces:
                    self.ifaces[str(i)] = iface[2:-3]
                    i += 1
            else:
                raise Exception("ERROR: Unsupported operating system: {} for this application".format(self.operatingSystem))
        except Exception as e:
            print (f"[FATAL] [Environment]: {e}")
            exit(1)

    def launch(self):
        self.getInterfaceList()
        self.parseInterfaceList()
        return ("environment", {'ifaces': self.ifaces, 'os':self.operatingSystem})
