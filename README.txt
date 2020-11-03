
gpdump 0.3, Copyright (c) 2009 Grzegorz Pawelski <grzegorz.pawelski@nsn.com>


allows tracing messages (online or offline) on combi SGSN (SG6 at least) interfaces:
- mtp3b (Iu-PS over ATM)
- mtp3 (narrowband Gr)
- frame relay (Gb)

It takes internal message log entries and converts them into pcap format - readable by Wireshark.


allows online tracing using DPDUMPGX on 
- ATM or 
- ETH interfaces
 


===Installation===

Linux:
rpm -ihv gpdump-0.3.rpm

or upgrade (if you have previously installed version):

rpm -Uhv gpdump-0.3.rpm


Windows:
unzip gpdump-0.3.zip



===Wireshark configuration===

For Frame Relay (Gb) correct decoding:
Edit -> Preferences -> Protocols -> FR -> Encapsulation: GPRS Network Service



===Usage===

gpdump -h




===Example usage===

Offline tracing of mtp3b (Iu-PS over ATM):

1.
telnet 10.10.147.35
ZDDS:PAPU,3:;
ZOQI:E49E

2.
capture the output to capture.log file (eg. by copy-paste or logging from the telnet)  

3.
gpdump -mtp3b capture.log mtp3b.pcap

4.
open mtp3b.pcap file in Wireshark




Online tracing of mtp3b (Iu-PS over ATM):

1.
on the 1st term:
script -f capture.log
telnet 10.10.147.35
ZDDS:PAPU,3:;
ZOQI:E49E


2a.
Stop and Restart in Wireshark working with fast running output:

on the 2nd term:

mkfifo /tmp/pipe
gpdump -o -mtp3b capture.log /tmp/pipe &
wireshark -t a -k -i /tmp/pipe


2b.
Stop and Restart in Wireshark not working

gpdump -o -mtp3b capture.log | wireshark -t a -k -i -
or 
wireshark -t a -k -i <(gpdump -o -mtp3b capture.log)






Online tracing on ATM interface on IOCPEA interface AA4:

1.
on the 1st term:
script -f capture.log
telnet 10.10.147.35
ZDDS:PAPU,0
ZRS:20,40BE
20-MAN>ZLE:1,DPDUMPGX
20-MAN>Z1
20-TCPDUMP>X:::::AA4


2a.
Stop and Restart in Wireshark working with fast running output:

on the 2nd term:

mkfifo /tmp/pipe
gpdump -o -atm capture.log /tmp/pipe &
wireshark -t r -k -i /tmp/pipe


2b.
Stop and Restart in Wireshark not working

gpdump -o -atm capture.log | wireshark -t r -k -i -
or 
wireshark -t r -k -i <(gpdump -o -atm capture.log)

