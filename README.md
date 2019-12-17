# 567_Lab3
Port Scanner

## Dependancies
If PIP is not installed:
`sudo apt install python-pip`
Install the 'netaddr' and 'fpdf2' libraries/packages.
`pip install netaddr`
`pip install fpdf2`

## Use
Use argument flags to scan. You'll need an IP input flag, and a transport layer flag. With optional flags, you can specify port(s) and if you want this saved to a PDF rather than printed to console.
For IP inputs:
  -ip     (Single or list (no comma) of IP's address to scan (i.e. 192.168.1.1 OR 192.168.1.1 192.168.1.2 [etc]))
  
  -cider  (IP CIDR block address to scan (i.e. 192.168.1.0/24))
  
  -range  (IP range to scan (no comma, first last i.e. 192.168.1.1 192.168.1.255))
  
  -file   (IP address file input (single IP per line, no protocol nor ports)
  
For Transport Layer specificity:
  -layer (Required, specify TCP, UDP, ICMP, tracert. Note this will not export to PDF)
Port number:
  -port  (Port number, default scans all well-known ports)\
Save to PDF:
  -pdf   (Select True for outputting to PDF, otherwise prints in console, saved as 'Results.PDF')

## Information
This will only output at the very end of the scan, so it may take a minute or two before the console displays information.

This is multithreaded. Sometimes there are multithread errors about too many pages, but I've only seen that occasionally in Ubuntu, never in Kali. Still functions tho after a bit of warnings and hang. 


## Notes / Sources:
https://stackoverflow.com/questions/42867192/python-check-udp-port-open
https://github.com/remzmike/python-kports-portscanner/blob/master/kports.py
https://nmap.org/book/scan-methods-udp-scan.html
https://stackoverflow.com/questions/5815675/what-is-sock-dgram-and-sock-stream
https://wiki.python.org/moin/UdpCommunication
https://docs.python.org/3/library/argparse.html

For IP and CIDR stuff
from netaddr import *
https://netaddr.readthedocs.io/en/latest/tutorial_01.html
