import os

def getCaps():
    
    capDict = {}
    files = os.listdir('./captures')
    capList = [file for file in files if file.endswith('.pcap')]
    i = 100
    for file in capList:
        capDict[str(i)] = file
        i += 1
    return capDict