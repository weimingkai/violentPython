import optparse
import socket
from socket import *

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send("FishPython\r\n")
        result = connSkt.recv(100)
        print("[+]%d/tcp open" % tgtPort)
        print("[+] " + str(result))
        connSkt.close()
    except:
        print("[-]%d/tcp closed" % tgtPort)

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
        print(tgtHost)
        print(tgtIP)
    except:
        print("[-]Cannot resolve '%s': unkown host" % tgtHost)
        return
    try:
        tgtName = gethosrtbyaddr(tgtIP)
        print(tgtName)
        print("\n[+]Scan result for:" + tgtName[0])
    except:
        print("\n[+]Scan result for:" + tgtIP)
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        print("scanning port " + tgtPort)
        connScan(tgtHost, int(tgtPort))

def main():
    parser = optparse.OptionParser("usage %prog -H <target host> -P <target port>")
    parser.add_option("-H", dest="tgtHost", type="string",\
                      help="specify target host")
    parser.add_option("-P", dest="tgtPort", type="string",\
                      help="specify target port")
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(",")
    if(tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        print("You must specify target host and port[s].")
        exit(0)
    portScan(tgtHost, tgtPorts)

main()
    
    
        
