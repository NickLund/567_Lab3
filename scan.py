from argparse import ArgumentParser
import socket
import argparse
import sys
import threading

#Get command line arguments
def get_args():
    parser = ArgumentParser(description="Get IP and Port")
    parser.add_argument("-ip", type=str, required=True, help="IP address to scan")
    parser.add_argument("-port", type=int, required=False, help="Port number, default scans all well-known ports")
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

#runs TCP scan with multiple threads
def scan(host_ip, host_port):
    threads = []
    output = {}

    #Host Port not specified -> Scan all well-known ports
    if host_port is None:
        #Create threads for each port
        for i in range (20,1023):
            t = threading.Thread(target=TCP_connect, args=(host_ip, i, output))
            threads.append(t)
        #Start the threads
        for i in range (20,1023):
            threads[i].start()
        #Lock main thread till these ones done
        for i in range (20,1023):
            threads[i].join()
        #Print open ports
        for i in range(20,1023):
            if output[i] == 'OPEN':
                print('Port ' + str(i) + ': ' + output[i])
    else:
        TCP_connect(host_ip,host_port,output)

def main():
    args = get_args()
    scan(args.ip,args.host)
    #print(f"host ip: '{args.ip}'")
    #print(f"host port: '{args.port}''")


if __name__ == '__main__':
    main()
