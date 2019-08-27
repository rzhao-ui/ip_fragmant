pcap:main.c pcap.h
	gcc main.c -g -o pcap -lpcap -Wall
.PHONY:clean
clean:
	rm pcap
