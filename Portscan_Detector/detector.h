#include <stdio.h>
#include <pcap/pcap.h>
#include "typedefs.h"

/*
 * reporting functions that reside in main.c
 */
extern void report_total_packets(packet_stats_t stats);
extern void report_destination_stats(destination_stats_t stats);
extern void report_port_scan(port_scan_stats_t stats);

/*
 * detector entrypoint
 */
void run_detector(pcap_t* handle);

/*
 * place your function/data structure definitions here.
 */

/*
 * Define Macro's here 
 */
#define FALSE (0)
#define TRUE (1)
/* Portscan detection score 21 */
#define PORTSCAN_SCORE_THRESHOLD (21)
/* Portscan detection time 300ms */
#define PORTSCAN_TIME_THRESHOLD (300000)

/* Port with 1 and 3 Score */
#define BOUNDRY_PORT 1024

#define LESSER_BOUNDRY_PORT_SCORE 3
#define GREATER_BOUNDRY_PORT_SCORE 1

/* Score for Special Port */
#define SPECIAL_PORTS_SCORE  10
/* Port with 10 Score (Special Ports) */
#define SPECIAL_PORT1 11
#define SPECIAL_PORT2 12
#define SPECIAL_PORT3 13
#define SPECIAL_PORT4 2000

/*
 * Standard length
 */
#define IPV4_ADDRSTRLEN		(16)

/* 
 * Hash Table Macro
 */
#define HOST_BITS	(16) 
#define HASH_SIZE	(1<<HOST_BITS) 

/* 
 * Protocol Macro
 */
#define IPV4_PROTO   (0x0800)
#define IPTCP_PROTO    (0x06)
#define IPUDP_PROTO    (0x11)

/*
 * TCP FLAGS
 */
#define TCP_FLAG_FIN	(0x01)
#define TCP_FLAG_SYN	(0x02)
#define TCP_FLAG_RST	(0x04)
#define TCP_FLAG_PSH	(0x08)
#define TCP_FLAG_ACK	(0x10)
#define TCP_FLAG_URG	(0x20)
#define TCP_FLAG_ECE	(0x40)
#define TCP_FLAG_CWR	(0x80)


/* SYN Flag is marked but No (SYNACK RST and FIN) */
#define IS_NEW_CONNECTION_REQ(flags) ((flags & TCP_FLAG_SYN)  && \
				 !(flags & (TCP_FLAG_RST|TCP_FLAG_ACK|TCP_FLAG_FIN)))

#define IS_SYN_ACK_SEND(flags)  (flags & (TCP_FLAG_SYN|TCP_FLAG_ACK) &&\
				!(flags & (TCP_FLAG_RST|TCP_FLAG_FIN)))

#define IS_WAITING_FOR_ACK(flags)  ((flags & TCP_FLAG_ACK) &&\
				!(flags & (TCP_FLAG_RST|TCP_FLAG_FIN)))

#define IS_FIN_OR_RST(flags)	((flags & TCP_FLAG_RST) ||\
				 (flags & TCP_FLAG_FIN))

#define IS_SYN_RECEIVE(con) 	(con->connection_state == e_tcp_state_syn_receive)
#define IS_HALF_OPEN(con)	 (con->connection_state == e_tcp_state_synack_send)
#define IS_OPEN(con) 		(con->connection_state == e_tcp_state_synack_receive)
#define IS_CLOSED(con) 		(con->connection_state == e_tcp_state_closed)


/*
 * Ether header
 * BYTE Structure
 */
typedef struct {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint8_t ethertype[2];
	uint8_t data[0];
} ethernet_hdr_t;

/*
 * IPv4 header
 * BYTE Structure
 */
typedef struct {
	uint8_t version_ihl;
	uint8_t dscp_ecn;
	uint8_t total_len[2];
	uint8_t identification[2];
	uint8_t flags_fragmentoffset[2];
	uint8_t ttl;
	uint8_t protocol;
	uint8_t checksum[2];
	uint8_t src_ip[4];
	uint8_t dst_ip[4];
	uint8_t options_and_data[0];
} ip_hdr_t;
/*
 * TCP header
 * BYTE Structure
 */
typedef struct {
	uint8_t src_port[2];
	uint8_t dst_port[2];
	uint8_t seq_no[4];
	uint8_t ack_no[4];
	uint8_t offset_reservd;
	uint8_t flags;
	uint8_t window[2];
	uint8_t checksum[2];
	uint8_t urgent_pointer[2];
	uint8_t options_and_data[0];
} tcp_hdr_t;

/* Simplified TCP State Machine for 
 * Destination IP.
 * TCP State 
 */
enum tcp_state {
e_tcp_state_listen = 0,		/* Initial State */
e_tcp_state_syn_receive,      	/* State after SYN */
e_tcp_state_synack_send,    	/* State after sending SYNACK (HALF OPEN) */
e_tcp_state_synack_receive,  	/* State after receiving ACK  (FULL OPEN) */
e_tcp_state_closed,  	  	/* State after (Closed) */
e_tcp_state_count    		/* Total Number of connection state */ 
};

/* TCP Events */
enum tcp_event {
e_tcp_flag_syn = 0,		/* SYN Packets */
e_tcp_flag_synack,		/* SYNACK Packets  */
e_tcp_flag_ack,			/* Ack Packets */
e_tcp_flag_psh,			/* PUSH Packets  */
e_tcp_flag_rst,			/* RST Packets */
e_tcp_flag_fin,			/* FINI Packets */
e_tcp_flag_count          
};

/* 
 * Connection information for computing 
 * TCP connection stats.
 * Vertical List of Connections from same host
 */
typedef struct connections {
	struct connections *v_list;
	uint32_t src_addr; /* src ip correspnding to all dest       */
	uint32_t dst_addr;  /* lets keep dest for future (redundant) */
	uint32_t seqno;
	uint32_t ackno;
	uint16_t src_port;
	uint16_t dst_port;
	enum tcp_state connection_state;
} connections_t;

/* 
 * Structure to keep info for Host connection 
 *
 * Host structure contains horizontal list for all host
 * which are added in case of hash collision   
 * 
 * Vertical list of connections will keep track of all
 * the connection for a specific host.
 */
typedef struct host {
 	struct host *h_list;		
	/* Currently Host is Destination IP Address */	
	uint32_t host_addr;
	destination_stats_t dest_stats;	
	connections_t *v_list;
} host_t;
/* 
 * List to store PORTSCAN_THRESHOLD score enteries 
 * 
 * Vertical list of Connections from same source 
 */
typedef struct  score {
	struct timeval scantime;
	uint32_t score;
	struct score *v_list;
} score_t;

/* 
 * Structure to keep info of all sources scanning the port.
 *
 * Source host structure contains horizontal list for all 
 * source which are added in case of hash collision   
 *
 * Vertical list of Connections from same source 
 */
typedef struct srchost {
	/* List of srcinfo in cash of hash collision */
 	struct srchost *h_list;
	/* Source Address */
	uint32_t src_addr;
	uint8_t detected;
	port_scan_stats_t portscan_stats;
	/* List of score with timestamp */
	score_t *v_list;
} srchost_t;
/* 
 * Hash table for 
 * For DestIP keep track of TCP state machine
 * For SrcIP keep track of port scan detection 
 */
typedef struct hashtable {
	/* Keep separate for lesser memory constrain */
	union {
		srchost_t *src_hash[HASH_SIZE];
		host_t *host_hash[HASH_SIZE];
	} addr;
	/* Number of hash collision for IPV4 addr
         * Used to compute better hash algo
	 */
	uint32_t collision_count;
} hashtable_t;
