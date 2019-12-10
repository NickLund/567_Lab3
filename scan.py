from argparse import ArgumentParser
import argparse
import os
import sys
import threading
from netaddr import *
import ipaddress
import socket
from prettytable import prettytable

#Get command line arguments
def get_args():
    parser = ArgumentParser(description="IP (required either single/list, cidr block, range, or from file), TCP/UDP/ICMP Protocol (required), and Port (not required, single or list)")
    parser.add_argument("-ip", nargs='+', required=False, default=False, help="Single or list of IP's address to scan (i.e. 192.168.1.1 OR 192.168.1.1, 192.168.1.2, [etc])")
    parser.add_argument("-cidr", required=False, default=False, help="IP CIDR block address to scan (i.e. 192.168.1.0/24)")
    parser.add_argument("-range", nargs='+', required=False, default=False, help="IP range to scan (comma separated first, last i.e. 192.168.1.1, 192.168.1.255)")
    parser.add_argument("-file", required=False, default=False, help="IP address file input (single IP per line, no protocol nor ports")
    parser.add_argument("-layer", required=True, help="Required, specify TCP, UDP, or ICMP")
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
    if (((args.ip != False) and (args.cidr == False) and (args.range == False) and args.file == False) or (args.ip == False and args.cidr != False and args.range == False and args.file == False) or (args.ip == False and args.cidr == False or args.range != False and args.file == False) or (args.ip == False and args.cidr == False or args.range == False and args.file != False)):
        ip_addresses = []
        if (args.ip != False):
            for i in args.ip:
                ip_addresses.append(args.ip[i])
        elif (args.cidr != False):
            #ips = IPNetwork(args.cidr)
            #ip_addresses = range(int(ipaddress.IPv4Address(ips[0])),int(ipaddress.IPv4Address(ips[-1]))+1)
            for ip in IPNetwork(args.cidr):
                ip_addresses.append('%s' % ip)
        elif (args.range != False):
            #ip_addresses = range(int(ipaddress.IPv4Address(args.range[0])),int(ipaddress.IPv4Address(args.range[1]))+1)
            #>>> r1 = IPRange('192.0.2.1', '192.0.2.15')
            #>>> r1
            #IPRange('192.0.2.1', '192.0.2.15')
            for ip in IPRange(args.range[0], args.range[1]):
                ip_addresses.append('%s' % ip)
        elif (args.file != False):
            #initial = open(args.file, "r")
            #file_ip = initial.readlines()
            #for x in file_ip:
            #    ip_addresses.append(int(ipaddress.IPv4Address(x.rstrip())))
            with open(args.file) as fp:
                line = fp.readline()
                while line:
                    ip_addresses.append(line)
                    line = fp.readline()
        for i in ip_addresses:
            scan(ip_addresses[i],args.layer,args.port)
    else:
        print ("Incorrect number of IP paramaters. Use one (and only one) of the IP flags (-ip, -cidr, -range, -file)")

if __name__ == '__main__':
    main()
