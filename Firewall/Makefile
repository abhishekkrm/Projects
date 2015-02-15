CC = gcc
CCOPTS = -c -g -Wall
LINKOPTS = -ggdb -pthread 

all: firewall

firewall:	firewall.o firewall_api.o process_rule.o packet_handler.o intf_config.o arp.o tcp_handler.o icmp_handler.o udp_handler.o
	$(CC) $(LINKOPTS) -o $@ $^ -lpcap

firewall.o: firewall.c firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@ firewall.c

firewall_api.o: firewall_api.c firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@ firewall_api.c

process_rule.o: process_rule.c process_rule.h  firewall.h firewall_api.h 
	$(CC) $(CCOPTS) -o $@ process_rule.c

packet_handler.o:  packet_handler.c packet_handler.h firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@  packet_handler.c

intf_config.o: intf_config.c intf_config.h firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@  intf_config.c

arp.o: arp.c arp.h firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@  arp.c

tcp_handler.o: tcp_handler.c tcp_handler.h firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@  tcp_handler.c

icmp_handler.o: icmp_handler.c icmp_handler.h firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@  icmp_handler.c

udp_handler.o: udp_handler.c udp_handler.h firewall.h firewall_api.h
	$(CC) $(CCOPTS) -o $@  udp_handler.c



clean:
	rm -rf *.o *~ firewall
