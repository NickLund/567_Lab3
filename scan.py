from argparse import ArgumentParser
import socket
import argparse
import sys
import threading

#Get command line arguments
def get_args():
    parser = ArgumentParser(description="Get IP, TCP/UDP Protocol, and Port")
    parser.add_argument("-ip", nargs='+', required=True, help="IP address to scan")
    parser.add_argument("-layer", required=True, help="TCP or UDP")
    parser.add_argument("-port", nargs='*', required=False, help="Port number, default scans all well-known ports")
    args = parser.parse_args()
    return args

#Make TCP Connection, timeout 0.75 seconds, open port adds to output list
def TCP_connect(ip, port, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(0.75)
    try:
        TCPsock.connect((ip, port))
        output[port] = 'OPEN'
        TCPsock.close()
    except:
        output[port] = ''

#Make UDP Connection, timeout 0.75 seconds, open port adds to output list
def UDP_connect(ip, port, output):
    UDPsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    UDPsock.settimeout(0.75)
    try:
        UDPsock.connect((ip, port))
        output[port] = 'OPEN'
        UDPsock.close()
    except:
        output[port] = ''

#runs TCP/UDP scan with multiple threads
def scan(host_ip, host_layer, host_port):
    threads = []
    output = {}
    ports = []
    #Host Port not specified -> Scan well-known ports
    if host_port is None:
        for i in range (20,1023):
            ports.append(i)
    # Scan all ports listed
    else:
        for i in host_port:
            ports.append(i)

    #check TCP or UDP
    if (host_layer == 'TCP'):
        #Create threads for each port
        for i in ports:
            t = threading.Thread(target=TCP_connect, args=(host_ip, ports[i], output))
            threads.append(t)
    else:
        #Create threads for each port
        for i in ports:
            t = threading.Thread(target=UDP_connect, args=(host_ip, ports[i], output))
            threads.append(t)
    #Start the threads
    for i in threads:
        threads[i].start()
    #Lock main thread till these ones done
    for i in threads:
        threads[i].join()
    #Print open ports
    for i in threads:
        if output[i] == 'OPEN':
            print('Port ' + ports[i] + ': ' + output[i])

def main():
    args = get_args()
    for i in args.ip:
        scan(args.ip,args.layer,args.port)


if __name__ == '__main__':
    main()
