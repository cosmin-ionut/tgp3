from datetime import *
from hacpy.utils.telnet import telnet
from hacpy.utils.ssh import SSH
from time import sleep
from re import compile, findall
from threading import Thread
from hacpy.utils.hacexpect import EOF, TIMEOUT

class resourceShow(Thread):
#class resourceShow(object):


    def __init__(self, connType, timeLimit, ip, resource, port="23", username="admin", password="private"):
        #super(resourceShow, self).__init__()
        Thread.__init__(self)
        self.connType = connType #pexpect connection. v24, telnet, ssh
        self.timeLimit = timeLimit
        self.error = False #the error which occured during script execution
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.resource = resource
        self.connection = False

        #connType -- telnet - for telnet connections use connType = telnet, and DUT's ip and port
        #                   - for v24 serial connections user connType = telnet and ip = localhost and ser2net port
        #timeLimit -- is the number of seconds for which the script will retrieve data from the DUT. Must be integer
        # self.error = False |- the error message which occured during the script execution
        #              Error | - this is a general attribute of the class. It is not method-specific.
        # self.ip - the DUT's network data. If serial then use localhost and ser2net port
        # self.port | - not to be specified for ssh connections because it does nothing
        #           | - only to be specified for ser2net connections
        # self.username | -> ssh and telnet login credentials
        # self.password |
        # self.resource - the resource which will be retrieved - if string then the resource will be retrieved from the
        #                                                         output of "show system resources"
        #                                                         Example: resource = "Free RAM" or resource = "CPU"
        #                                                     - if name of a function then the function will be executed
        #                                                       in serviceshell mode and the result will be parsed



    def initConnection(self):
        """ - spawns a connection using the telnet utility.
            - The atribute 'self.connection' contains the connection.
            - self.connection is a hacexpect object and methods such as expect and sendline can be used directly through it
        """
        if self.connType == "telnet":
            self.telConn = telnet(ip=self.ip, port=self.port, username=self.username, password = self.password)
            if not self.telConn.telnet_login():
                self.error = "[ resourceShow ] The telnet connection couldn't be established"
                return False
            self.connection = self.telConn.conn
        elif self.connType == "ssh":
            self.sshConn = SSH(host=self.ip, username=self.username, password=self.password, version="2")
            if not self.sshConn.ssh_login():
                self.error = "[ resourceShow ] The ssh connection couldn't be established"
                return False
            self.connection = self.sshConn.conn
        else:
            self.error = "[ resourceShow ] Unknown connection type %s" % self.connType
            return False
        return True

    def cliResourceParse(self):
        initTime = datetime.now()
        elapsedTime = (datetime.now() - initTime).total_seconds()
        works = False
        while elapsedTime < self.timeLimit:
            elapsedTime = (datetime.now() - initTime).total_seconds()
            self.connection.sendline('show system resources\r')
            result = self.connection.expect(['Error', '#', '>', EOF, TIMEOUT])
            if result != 1 and result != 2:
                self.error = "[ resourceShow ] The system resources couldn't be displayed. Expect result value: %i" % result
                return False
            parsedResource = self.connection.before[self.connection.before.find(self.resource):]
            parsedResource = parsedResource[:parsedResource.find('\n')]
            print parsedResource
            if works == False:
                if parsedResource == None or parsedResource == '':
                    self.error = "[ resourceShow ] The parsing of the resource failed. Please recheck the 'resource' argument"
                    return False
                else: works = True
            sleep(0.5)
        print "[ resourceShow ] Time limit reached. Starting exit process"
        self.connection.close()
        return True

    def showRAM(self):
        """
        - runs for a set number of seconds (__init__ timeLimit)
        - uses the connection spawned by initConnection
        - enters the DUT's serviceshell and executes memShow()
        - parses the free RAM bytes (using re) and prints them
        - when the time expires, automatically exits the DUT's serviceshell and closes the connection to the DUT
        """
        initTime = datetime.now()
        self.connection.sendline('enable\r')
        self.connection.expect('#')
        self.connection.sendline("serviceshell start\r")
        ready = self.connection.expect('WARNING!')
        if not ready == 0:
            self.error = "[ resourceShow ] Failed to enter ServiceShell. Closing connection..."
            print self.error
            self.connection.close()
            return False
        pattern = compile("[0-9]{1,}")
        while True:
            elapsedTime = (datetime.now() - initTime).total_seconds()
            self.connection.sendline("memShow()\r")
            if not self.connection.expect('status') == 0:
                self.error = "[ resourceShow ] memShow() execution failed. Trying to exit ServiceShell"
                self.connection.sendline("exit\r")
                self.connection.close()
                return False
            print pattern.findall(self.connection.before)[0:1]
            if elapsedTime > self.timeLimit:
                print "[ resourceShow ] Time limit reached. Starting exit process"
                self.connection.sendline("exit\r")
                sleep(2)
                exited = self.connection.expect(['Au revoir', '#', EOF, TIMEOUT])
                if exited != 0 and exited != 1:
                    self.error = "[ resourceShow ]Failed to exit ServiceShell. Code %i" % exited
                    return False
                else:
                    print "[ resourceShow ] Successfully exited ServiceShell mode. Closing connection now."
                self.connection.close()
                return True
            sleep(0.9)

    def run(self):
        self.initConnection()
        if not self.error:
            if self.resource.find('()') != -1:
                return self.showRAM()
            elif self.connType == 'ssh' or self.connType == "telnet":
                return self.cliResourceParse()
        else:
            print self.error
            return False
