from argparse import ArgumentParser
import argparse
import os
import sys
import threading
import struct
import select
import time
from netaddr import *
import ipaddress
import socket
from prettytable import PrettyTable
from scapy.all import *

#Get command line arguments
def get_args():
    parser = ArgumentParser(description="IP (required either single/list, cidr block, range, or from file), TCP/UDP/ICMP Protocol (required), and Port (not required, single or list)")
    parser.add_argument("-ip", nargs='+', required=False, default=False, help="Single or list (no comma) of IP's address to scan (i.e. 192.168.1.1 OR 192.168.1.1 192.168.1.2 [etc])")
    parser.add_argument("-cidr", required=False, default=False, help="IP CIDR block address to scan (i.e. 192.168.1.0/24)")
    parser.add_argument("-range", nargs='+', required=False, default=False, help="IP range to scan (no comma, first last i.e. 192.168.1.1 192.168.1.255)")
    parser.add_argument("-file", required=False, default=False, help="IP address file input (single IP per line, no protocol nor ports")
    parser.add_argument("-layer", required=True, help="Required, specify TCP, UDP, ICMP, or traceroute")
    parser.add_argument("-port", nargs='*', type=int, required=False, help="Port number, default scans all well-known ports")
    parser.add_argument("-html", required=False, help="Select for outputting to HTML, otherwise prints in console")
    args = parser.parse_args()
    return args

#Make TCP Connection, timeout 0.75 seconds, open port adds to output list
def TCP_connect(ip, port, output, printIP):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(0.75)
    try:
        TCPsock.connect((ip, port))
        output.append(port)
        TCPsock.close()
        printIP.append('worked')
    except:
       return

#Make UDP Connection, timeout 0.75 seconds, open port adds to output list
def UDP_connect(ip, port, output, printIP):
    UDPsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    UDPsock.settimeout(0.75)
    try:
        UDPsock.connect((ip, port))
        output.append(port)
        UDPsock.close()
        printIP.append('worked')
    except:
        return

#runs TCP/UDP scan with multiple threads
def scan(host_ip, host_layer, host_port, sendToFile):
    threads = []
    output = []
    ports = []
    printIP = []
    #Host Port not specified -> Scan well-known ports
    if host_port is None:
        for i in range (0,1024):
            ports.append(i)
    # Scan all ports listed
    else:
        for i in host_port:
            ports.append(i)

    #check TCP or UDP
    if (host_layer == 'TCP'):
        #Create threads for each port
        for i in ports:
            t = threading.Thread(target=TCP_connect, args=(host_ip, i, output, printIP))
            threads.append(t)
    elif (host_layer == 'UDP'):
        #Create threads for each port
        for i in ports:
            t = threading.Thread(target=UDP_connect, args=(host_ip, i, output, printIP))
            threads.append(t)
    #check if ICMP, then stop rest of scan
    elif (host_layer == 'ICMP'):
        sendToFile.append('%s is up!' % host_ip)
        #print('%s is up!') % host_ip
        return
    else:
        print('You had a typo at the -layer argument')
        return
    #Start the threads
    for i in threads:
        i.start()
    #Lock main thread till these ones done
    for i in threads:
        i.join()
    #Print open ports
    if (len(printIP)>0):
        sendToFile.append('Open ports on %s: ' % host_ip)
        #print('Open ports on %s: ') % host_ip
        for i in range(len(output)):
            sendToFile.append('Port %d: OPEN' % output[i])
            #print('Port %d: OPEN') % output[i]

    else:
        sendToFile.append('Ports not open on %s ' % host_ip)
        #print('Ports not open on %s ') % host_ip

def outToFile(printOrFile, sendToFile):
    if printOrFile:
        for i in sendToFile:
            print(i)
    else:
        outFile = open("output.html", "w+")
        outFile.write(sendToFile.get_html_string(attributes={"border":"1"}))


#Ping host with ICMP packet
def nick_icmp(host_ip):
    resp = sr1(IP(dst=str(host_ip))/ICMP(),verbose=0, timeout=0.5)
    if resp == None:
        return False
    return True

#Traceroute
def nick_traceroute(host_ip, sendToFile):
    for i in range(1, 28):
        pkt = IP(dst=host_ip, ttl=i) / UDP(dport=33434)
        reply = sr1(pkt, verbose=0)
        if reply is None:
            break
        elif reply.type == 3:
            sendToFile(reply.srce)
            #print(reply.src)
            break
        else:
            sendToFile("%d : "% i, reply.src)
            #print("%d : ")% i, reply.src

def main():
    args = get_args()
    sendToFile = []
    #Does a check to only do one IP check at a time
    if (((args.ip != False) and (args.cidr == False) and (args.range == False) and args.file == False) or (args.ip == False and args.cidr != False and args.range == False and args.file == False) or (args.ip == False and args.cidr == False or args.range != False and args.file == False) or (args.ip == False and args.cidr == False or args.range == False and args.file != False)):
        ip_addresses = []
        #Single or listed IP's
        if (args.ip != False):
            for i in args.ip:
                ip_addresses.append(i)
        #CIDR IP blcok
        elif (args.cidr != False):
            for ip in IPNetwork(args.cidr):
                ip_addresses.append('%s' % ip)
        #IP range
        elif (args.range != False):
            for ip in IPRange(args.range[0], args.range[1]):
                ip_addresses.append('%s' % ip)
        #Read IP's from file
        elif (args.file != False):
            with open(args.file) as fp:
                for line in fp:
                    ip_addresses.append(line.rstrip())
        #Start scanning
        for i in ip_addresses:
            #if traceroute
            if (args.layer == 'traceroute'):
                sendToFile.append('Starting traceroute for %s' % i)
                #print('Starting traceroute for %s') % i
                nick_traceroute(i, sendToFile)
                break
            #if host is pingable, then continue
            if nick_icmp(i):
                scan(i,args.layer,args.port,sendToFile)
        
    else:
        print ("Incorrect number of IP paramaters. Use one (and only one) of the IP flags (-ip, -cidr, -range, -file)")

if __name__ == '__main__':
    main()

