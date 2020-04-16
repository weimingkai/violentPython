import optparse
import socket
from socket import *

def connScan(tgtHost, tgtPort):  #尝试与指定目标主机建立连接
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send("FishPython\r\n") #发送垃圾数据
        result = connSkt.recv(100) #接受目标主机发回的Banner
        print("[+]%d/tcp open" % tgtPort)
        print("[+] " + str(result))
        connSkt.close()
    except:
        print("[-]%d/tcp closed" % tgtPort)

def portScan(tgtHost, tgtPorts): #基于指定主机扫描多个端口
    try:
        tgtIP = gethostbyname(tgtHost) #获取主机名
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
    for tgtPort in tgtPorts: #测试各个端口是否可用
        print("scanning port " + tgtPort)
        connScan(tgtHost, int(tgtPort))

def main():
    
    #快速解析目标主机
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
        
    #扫描端口
    portScan(tgtHost, tgtPorts)

main()
    
    
        
