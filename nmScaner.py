import nmap
import optparse

def nmapScan(tgtHost, tgtPort):
    nmScan = nmap.PortScanner()
    result = nmScan.scan(tgtHost, tgtPort)
    state = result['nmap']['scanstats']
    print("[*]" + tgtHost + " /" + tgtPort + " state" + str(state))
    print(nmScan.csv())

def main():
    #快速解析用户主机名
    parser = optparse.OptionParser("usage %prog -H <target host> -P <target port>")
    parser.add_option("-H", dest="tgtHost", type="string",\
                      help="specify target host")
    parser.add_option("-P", dest="tgtPort", type="string",\
                      help="specify target port")
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(",")
    if(tgtHost == None) | (tgtPorts[0] == None):
        print("You must specify target host and port[s].")
        exit(0)
    for tgtPort in tgtPorts:
        nmapScan(tgtHost, tgtPort)


main()

