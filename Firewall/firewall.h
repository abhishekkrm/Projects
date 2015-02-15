#ifndef FIREWALL_H_
#define FIREWALL_H_
#include <stdint.h>
#include <pcap/pcap.h>

/* FIXME REMOVE HARD CODED INFO */
//---------------------------------------
#define EXT_INTF "wlan0"
#define INT_INTF "ep1s"
#define INTERNAL_INTF_EP_MAC "22:94:f5:83:f9:68"
#define GATEWAY_MAC "28:c6:8e:91:ba:52"
#define WLAN_IP "192.168.1.6"
#define EP1_IP "10.0.0.1"
//---------------------------------------
/* Default 60 Min timeout */
#define DEFAULT_CONN_TIMEOUT 60

#define ETH_ALEN        6
#define IP_ALEN         4
#define IP_CHECKSUM_LENGTH 2
/*
 * Hash Table Macro
 */
#define HOST_BITS	(16)
#define HASH_SIZE	(1<<HOST_BITS)

#define MAX_CLEAN_CONN 20
//#time in (sec) (1 Hours)
#define DELETE_OLD_CONNECTION_TIME (3600)

/*
 * Protocol Macro
 */
#define IPV4_PROTO   (0x0800)
#define ARP_PROTO    (0x0806)
#define IPTCP_PROTO    (0x06)
#define IPUDP_PROTO    (0x11)
#define IPICMP_PROTO    (0x1)
#define DEFAULT_RULES_FILE 		"rules.txt"
#define DEFAULT_OUTPUT_PCAP		"output.pcap"
#define MAX_DEVICE_LEN			(32)

/* Firewall Proto */
enum fw_proto {
	PROTO_ANY = 0, PROTO_TCP = 1, PROTO_UDP = 2, PROTO_ICMP = 3, PROTO_ARP = 4
};

/* Simplified TCP State Machine for
 * Destination IP.
 * TCP State
 */
enum tcp_state {
e_tcp_state_listen = 0,		/* Initial State */
e_tcp_state_syn_receive,      	/* State after SYN */
e_tcp_state_synack_send,    	/* State after sending SYNACK (HALF OPEN) */
e_tcp_state_establised,  	/* State after receiving ACK  (FULL OPEN) */
e_tcp_state_closed,  	  	/* State after (Closed) */
e_tcp_state_count    		/* Total Number of connection state */
};

/*
 * Ether header
 * BYTE Structure
 */
typedef struct {
	uint8_t dst_mac[ETH_ALEN];
	uint8_t src_mac[ETH_ALEN];
	uint8_t ethertype[2];
	uint8_t data[0];
} ethernet_hdr_t;

/* IPv4 header
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
	uint8_t src_ip[IP_ALEN];
	uint8_t dst_ip[IP_ALEN];
	uint8_t options_and_data[0];
} ip_hdr_t;

typedef struct firewall_config {
	pcap_t *in_handler;
	pcap_dumper_t *out_handler;
	int  pcap_mode;  // 1 if operating in pcap Mode else 0 //
	uint32_t nat_ip; // IP address used for nat*/
	uint8_t src_mac_used[ETH_ALEN];  /* Source MAC  USED (dest mac mimic)*/
	uint8_t src_mac[ETH_ALEN];       /* SOURCE MAC */
	uint8_t dst_mac_used[ETH_ALEN];  /* Dest MAC of Switch or ep1 */
	pcap_t* src;     // Handler for interface
	pcap_t* dst;	// Handler for interface
	char dev_name[MAX_DEVICE_LEN]; /* Source DevName */
	int is_internal;  /*1 if src interface is internal*/
} firewall_config_t;
#define firewall_config_s (sizeof(firewall_config_t))


/*
 * Connection information for computing
 * TCP connection stats.
 * Vertical List of Connections from same host
 */
typedef struct connections {
	struct connections *v_list;
	struct connections *prev_vlist;
	int  action;
	uint32_t src_addr; /* src ip correspnding to all dest       */
	uint32_t dst_addr;  /* lets keep dest for future (redundant) */
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t proto;
	uint16_t connection_state;
	struct timeval timeout;
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
	connections_t *v_list;
	struct host  *prev_hlist;
} host_t;

/*
 * Hash table for
 * For DestIP keep track of TCP state machine
 * For SrcIP keep track of port scan detection
 */
typedef struct hashtable {
	/* Host Dest */
	host_t *host_hash[HASH_SIZE];
	/* Number of hash collision for IPV4 addr
         * Used to compute better hash algo
	 */
	uint32_t collision_count;
} hashtable_t;

pthread_mutex_t hash_mutex_operate[HASH_SIZE];

#if 0
 #define FREE_V_LIST(type_v,list_v)\
do {\
	while (list_v) {\
		type_v *temp_v = list_v;\
		list_v = list_v->v_list;\
		free(temp_v);\
	}\
}while(0);

#define FREE_H_V_LIST(type_v,list_v,type_h,list_h)\
do {\
	while(list_h) {\
		type_h *temp_h = list_h;\
		FREE_V_LIST(type_v,list_v)\
		list_h = list_h->h_list;\
		free(temp_h);\
	}\
}while(0);
#endif


extern void _HASH_LOCK_OPERATE( int32_t dst_ip,int32_t src_ip);
extern void _HASH_UNLOCK_OPERATE(int32_t dst_ip,int32_t src_ip);

extern int find_flow_rule(enum fw_proto proto, int32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
extern int udp_pkt_handler(const u_char * packet, firewall_config_t *fw_conf, int header_len, struct timeval time);
extern int tcp_pkt_handler(const u_char * packet, firewall_config_t *fw_conf, int header_len, struct timeval time);
extern connections_t *create_and_get_connection( uint16_t proto , uint32_t dst_ip, uint32_t src_ip,
 			uint16_t dst_port, uint16_t src_port);
extern int32_t  __thread_safe_tcp_state_machine_processing (struct timeval time, uint8_t flags, int32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port);
extern void __thread_safe_insert_action(int32_t action, int32_t proto, int32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port);
extern void *flow_timeout_cleaner(void *args);
extern int icmp_pkt_handler(const u_char * packet, firewall_config_t *fw_config, int header_len, struct timeval time);
extern int arp_pkt_handler(const u_char * packet, firewall_config_t *fw_config, int header_len);
extern int parse_fw_rules(const char *filename);
extern int initialize_pcap_handler(const char *input_pcap, const char *output_pcap);
extern int initialize_interface_handler();
extern void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif /* FIREWALL_H_ */
