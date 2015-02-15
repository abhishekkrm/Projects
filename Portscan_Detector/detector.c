#include <string.h>
#include "detector.h"
#include "typedefs.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/time.h>
/*GCC optimization needs to be turned on */
#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

//#define DEBUG_ENABLE

/* 
 * For debugging 
 */
#ifdef DEBUG_ENABLE
/* Dumps detector logs */
#define DEBUG_LVL1 (0x1)
/* Dumps TCP Info */ 
#define DEBUG_LVL2 (0x2)
/* Dumps ether,ip and tcp header */
#define DEBUG_LVL3 (0x4)
/* Mark to enable specfic LVL log dump default is LVL1 */
uint8_t debug_level = (DEBUG_LVL1 /*| DEBUG_LVL2 | DEBUG_LVL3*/);

#define DEBUG_MSG(msg) do {\
	if (debug_level & DEBUG_LVL1)\
		printf("\n[%s:%d]: %s", __func__, __LINE__, msg);\
} while (0);

#define PRINT_ETHER_HDR(ethernet_hdr) do{\
	if (debug_level & DEBUG_LVL3)\
		printf("\nETH: Dmac[%02x:%02x:%02x:%02x:%02x:%02x] Smac[%02x:%02x:%02x:%02x:%02x:%02x] etype 0x%04x",\
			ether_hdr->dst_mac[0], ether_hdr->dst_mac[1],\
			ether_hdr->dst_mac[2], ether_hdr->dst_mac[3],\
			ether_hdr->dst_mac[4], ether_hdr->dst_mac[5],\
			ether_hdr->src_mac[0], ether_hdr->src_mac[1],\
			ether_hdr->src_mac[2], ether_hdr->src_mac[3],\
			ether_hdr->src_mac[4], ether_hdr->src_mac[5],\
			unpack_uint16(ether_hdr->ethertype));\
} while(0);

/* 
 * Convert U32int to IP 
 */
static inline void uint32_2_ip(char *addr, uint32_t ip) {
	char first = (ip)     & 0xff;
	char second = (ip>>8)  & 0xff;
	char third  = (ip>>16) & 0xff;
	char fourth = (ip>>24) & 0xff;
	sprintf(addr,"%d.%d.%d.%d", fourth, third, second, first);
}
#define PRINT_IP_HDR(ip_hdr) do{\
	if (debug_level & DEBUG_LVL3) {\
		char daddr[IPV4_ADDRSTRLEN];\
		char saddr[IPV4_ADDRSTRLEN];\
		unpack_uint32(ip_hdr->src_ip),\
		unpack_uint32(ip_hdr->dst_ip),\
		uint32_2_ip(daddr, unpack_uint32(ip_hdr->dst_ip)),\
		uint32_2_ip(saddr, unpack_uint32(ip_hdr->src_ip)),\
		printf("\nIP : Sip[%s] Dip[%s] proto 0x%02x",\
			saddr, daddr, ip_hdr->protocol);\
	}\
} while(0);

#define PRINT_TCP_HDR(tcp_hdr) do{\
	if (debug_level & DEBUG_LVL2)\
		printf("\nTCP: Sport[%hu] Dport[%hu] seqno[%u] ackno[%u] flags 0x%02x",\
			unpack_uint16(tcp_hdr->src_port),\
			unpack_uint16(tcp_hdr->dst_port),\
			unpack_uint32(tcp_hdr->seq_no),\
			unpack_uint32(tcp_hdr->ack_no),\
			tcp_hdr->flags);\
} while(0);
#else /* End of debugging */
#define DEBUG_MSG(msg) 
#define PRINT_ETHER_HDR(ethernet_hdr)
#define PRINT_IP_HDR(ip_hdr)
#define PRINT_TCP_HDR(tcp)
#endif
/*
 * Define Global Variable here
 */
hashtable_t table, table_s;

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


/*
 * Write 2 byte value at buffer in network byte order.
 */
static inline void pack_uint16(uint16_t val, uint8_t* buf) {
	val = htons(val); 
	memcpy(buf, &val, sizeof(uint16_t));
}
/*
 * Read 2 byte value from buffer in host byte order.
 */
static inline uint16_t unpack_uint16(const uint8_t* buf) {
	uint16_t val;
	memcpy(&val, buf, sizeof(uint16_t));
	return ntohs(val);
}
/*
 * Write 4 byte value at buffer in network byte order.
 */
static inline void pack_uint32(uint32_t val, uint8_t* buf) {
	val = htonl(val); 
	memcpy(buf, &val, sizeof(uint32_t));
}
/*
 * Read 4 byte value from buffer in host byte order.
 */
static inline uint32_t unpack_uint32(const uint8_t* buf) {
	uint32_t val;
	memcpy(&val, buf, sizeof(uint32_t));
	return ntohl(val);
}
/*
 * Calculate hash using IPv4 address.
 */
static inline uint32_t hash_ipv4_addr(uint32_t addr) {

	uint32_t hash = 0;
	 do {
	 hash ^=addr;
	 addr >>= HOST_BITS;
	} while (addr);
	
	return (hash & (HASH_SIZE -1));
}
#define IS_HAS_VALUE(stats)\
	((stats.complete_tcp_handshakes != 0) ||\
	(stats.half_open_connections != 0) ||\
	(stats.reset_connections != 0) ||\
	(stats.unexpected_fins != 0))
/*
 * Report Connection Info.
 * Also Report half open connection before freeing.
 */
static void report_connection_info() {
	host_t * host_l = NULL;
	int i;
	for  (i = 0; i < HASH_SIZE; i++) {
		host_l = table.addr.host_hash[i];
		while (host_l) {
			connections_t *conn = host_l->v_list;
			while (conn) {
				if (IS_HALF_OPEN(conn)) {
					host_l->dest_stats.half_open_connections++;
				}
				conn = conn->v_list;
			}
			if (IS_HAS_VALUE(host_l->dest_stats))
				report_destination_stats(host_l->dest_stats);
			host_l = host_l->h_list;
		}
	}
}

/*
 * Free eneries.
 */ 
static inline void free_allocated_memory(){
	host_t * host_l;
	srchost_t * srchost;
	int i;
	for  (i = 0; i < HASH_SIZE; i++) {
		host_l = table.addr.host_hash[i];
		srchost = table_s.addr.src_hash[i];
		
		FREE_H_V_LIST(score_t,srchost->v_list,srchost_t,srchost);
		FREE_H_V_LIST(connections_t,host_l->v_list,srchost_t,srchost);
	}
}
/* 
 *
 * Calculate Score using the rule
 */
static inline uint32_t calculate_score(uint16_t dst_port) {
	
	if ((SPECIAL_PORT1 == dst_port) ||
		(SPECIAL_PORT2 == dst_port) ||
		(SPECIAL_PORT3 == dst_port) ||
		(SPECIAL_PORT4 == dst_port))
		return SPECIAL_PORTS_SCORE;
	if (dst_port < BOUNDRY_PORT)
		return LESSER_BOUNDRY_PORT_SCORE;
	else 
		return GREATER_BOUNDRY_PORT_SCORE;
}
/* 
 * Compute score based on last 300ms syn attack
 */
static uint32_t compute_weighted_score(srchost_t *src) { 

	score_t *s_list = src->v_list;
	score_t *prev_list = NULL;
	struct timeval curtime = s_list->scantime;
	struct timeval result;
	uint32_t score = 0;

	timersub(&curtime, &s_list->scantime, &result);
	while ((result.tv_usec < PORTSCAN_TIME_THRESHOLD) && 
	    (result.tv_sec == 0)) {
		score += s_list->score;
		/* Store the list time packet */
		src->portscan_stats.detection_time  = s_list->scantime;
		prev_list = s_list;
		s_list = s_list->v_list;
		if(s_list == NULL)
			break;
		timersub(&curtime, &s_list->scantime, &result);
        }
	/* 
	 * Free score enteries which are older than Threshold
	 */
	/* logically prv_list should not be NULL */
	if ((NULL != s_list) && (NULL != prev_list))  {
		FREE_V_LIST(score_t, s_list);
		prev_list->v_list = NULL;	
	}		
	return score;
}
/* 
 * Create source host 
 */
static inline srchost_t *new_srchost(uint32_t src_ip) {
	
	srchost_t * srchost_new = (srchost_t *)malloc(sizeof(srchost_t));
	if (srchost_new) {
		/* For reporting purpose */
		pack_uint32(src_ip, srchost_new->portscan_stats.src_address);
		srchost_new->src_addr = src_ip;
		srchost_new->h_list = NULL;
		srchost_new->v_list = NULL;
		/* To Stop further detection */
		srchost_new->detected = FALSE;
	}
	return  srchost_new;
}
/* 
 * Create new score 
*/
static inline score_t *new_score(uint32_t score, struct timeval time) {
	
	score_t *score_new = (score_t *)malloc(sizeof(score_t));
	if(score_new) {
		score_new->score = score;
		score_new->v_list = NULL;
		score_new->scantime = time;
	}
	return  score_new;
}
/* 
 * Get source host
 * if not present insert source host in hash table.
 * Return NULL in case of memory failure else source host
 * (NOTE : no need of separte get/insert srchost )
 */
static srchost_t  *put_get_srchost(uint32_t src_ip) {
	
	srchost_t *srchost = NULL;
	uint32_t hash_value = 0;
	
	hash_value = hash_ipv4_addr(src_ip);
	srchost = table_s.addr.src_hash[hash_value];


	/* Host Not Present Insert */
	if (NULL == srchost ) {
		srchost_t * srchost_new = new_srchost(src_ip);
		if(srchost_new) {
			table_s.addr.src_hash[hash_value] = srchost_new;
			srchost = srchost_new;
		}
	} else {
		 /* Scan Horizontol list for exact source
		  * Use dowhile to avoid one check (srchost!=NULL)
		  */
		do {
			if (src_ip == srchost->src_addr)
				break;
			srchost = srchost->h_list;
		} while (srchost);
		/* 
		 * If not found collision in hash table
	  	 * insert src host at the begining 
		 */
		if (NULL == srchost) {
			srchost_t * srchost_new = new_srchost(src_ip);
			if(srchost_new) {
				/* Insert host */
				table_s.collision_count++;
				srchost_new->h_list = table_s.addr.src_hash[hash_value];
				table_s.addr.src_hash[hash_value] = srchost_new;
				srchost = srchost_new;
			}
		}
	}
	return srchost;
}
/*
 * Port Scan detection
 *
 */
static int32_t  detect_port_scan(uint32_t src_ip,uint16_t dst_port, struct timeval time) {

	uint32_t score = 0;

	/* Get Source Host from hash table if present
	 * else insert(put) source host and return src host 
	 */		
	srchost_t *srchost = put_get_srchost(src_ip);
	if (unlikely(NULL == srchost)) {
		DEBUG_MSG("Memory allocation failed");
		goto mem_alloc_failed;
	}

	/* Port already detected a scan skip */
	if (likely(!srchost->detected)) {
		score = calculate_score(dst_port);
		score_t *score_new = new_score(score, time);
		if (unlikely(NULL == score_new)) {
			DEBUG_MSG("Memory allocation failed");
			goto mem_alloc_failed;
		}
		/* Insert Score*/
		score_new->v_list = srchost->v_list;
		srchost->v_list = score_new;
		/* Compute Weight */
		score = compute_weighted_score(srchost);
			
		if (score > PORTSCAN_SCORE_THRESHOLD) {
			/* Port Scan detected */
			srchost->detected = TRUE;
			srchost->portscan_stats.detection_score = score;
			report_port_scan(srchost->portscan_stats);
		}
	}
	return 0;
mem_alloc_failed:
	return -1;
}
/* 
 * Put host in hash table
 */
static inline host_t * new_host(uint32_t host_ip) {

	host_t *host_new = (host_t *)calloc(1, sizeof(host_t));
	if (host_new) {
		pack_uint32(host_ip, host_new->dest_stats.dest_address);
		host_new->host_addr = host_ip;
		host_new->v_list = NULL;
		host_new->h_list = NULL;
	}
	return host_new;
}

/*
 * return host if present in hash table 
 */
static inline host_t *get_host(uint32_t host_ip) {

	host_t *host = NULL;
	host = table.addr.host_hash[hash_ipv4_addr(host_ip)];

	if (host) {
		while(host) {
			if (host_ip == host->host_addr)
				break;
			host = host->h_list;
		}
	}
	return host;
}

static inline connections_t *new_connection(uint32_t dst_ip, uint32_t src_ip,
			uint16_t dst_port, uint16_t src_port, 
			uint32_t seqno, uint32_t ackno) {

	connections_t *conn_new = (connections_t *)calloc(1, sizeof(connections_t));
	if (conn_new) {
		conn_new->src_addr = src_ip;
		conn_new->dst_addr = dst_ip;
		conn_new->src_port = src_port;
		conn_new->dst_port = dst_port;
		/* Used for later purpose */
		conn_new->seqno  = seqno;
		conn_new->ackno  = ackno;
		conn_new->connection_state = e_tcp_state_listen;
		conn_new->v_list = NULL;
	}
	return conn_new;
}
/*
 * get connection info corresponding to host
 */
static inline connections_t *get_connection(host_t * host, uint32_t dst_ip, uint32_t src_ip,
			uint16_t dst_port, uint16_t src_port) {


	connections_t *conn = host->v_list;

	while (conn) {
		if((src_ip == conn->src_addr) &&
		    (dst_ip == conn->dst_addr) &&
	  	    (src_port == conn->src_port) &&
		    (dst_port == conn->dst_port)) { 
			break;
		}
		conn = conn->v_list;
	}
	return conn;
}
/*
 * Return the connection info from hash table if already exits
 * else insert the connection info and return 
 */ 
static connections_t *create_and_get_connection(uint32_t dst_ip, uint32_t src_ip,
			uint16_t dst_port, uint16_t src_port,
			uint32_t seqno, uint32_t ackno) {
	connections_t *conn = NULL;
	host_t * host = NULL;
	int hash_value = 0;
	/* Get host from hash table */
	host = get_host(dst_ip);
	/* Insert host if not present */
	if (NULL == host) { 
		host = new_host(dst_ip);
		if (unlikely(NULL == host)) {
			DEBUG_MSG("Memory allocation failed");
			goto mem_alloc_failed;
		}
//		char addr[IPV4_ADDRSTRLEN];
//		uint32_2_ip(addr, dst_ip);
//		printf("\nIP : HASH table Entry added [%s]",addr);
		hash_value = hash_ipv4_addr(dst_ip);
		host->h_list = table.addr.host_hash[hash_value];
		table.addr.host_hash[hash_value] = host;
	}
	conn =  get_connection(host, dst_ip, src_ip, dst_port, src_port);
	
	if (NULL == conn) {
		conn = new_connection(dst_ip, src_ip, dst_port, src_port, seqno, ackno);
		if (unlikely(NULL == conn)) {
			DEBUG_MSG("Memory allocation failed");
			goto mem_alloc_failed;
		}
		conn->v_list = host->v_list;
		host->v_list = conn;
	}
	return conn;
mem_alloc_failed:
	return NULL;
}
/*
 * Process TCP packets.
 */
static int32_t tcp_packet_processing (ip_hdr_t *ip_hdr, struct timeval time) {

	/* TCP Header */
	tcp_hdr_t *tcp_hdr = (tcp_hdr_t *)(ip_hdr->options_and_data); 
        uint32_t dst_ip = unpack_uint32(ip_hdr->dst_ip);
        uint32_t src_ip = unpack_uint32(ip_hdr->src_ip);
	uint16_t src_port = unpack_uint16(tcp_hdr->src_port);
	uint16_t dst_port = unpack_uint16(tcp_hdr->dst_port);
	uint16_t seqno = unpack_uint32(tcp_hdr->seq_no);
	uint16_t ackno = unpack_uint32(tcp_hdr->ack_no);
	uint8_t flags = tcp_hdr->flags;
	host_t *host = NULL;
	connections_t *conn = NULL;
	
	PRINT_IP_HDR(ip_hdr);
	PRINT_TCP_HDR(tcp_hdr);	

	if ((flags & TCP_FLAG_SYN)) {
		/*Algorithm to detect port scan */
		if (-1 == detect_port_scan(src_ip, dst_port, time))
			goto mem_alloc_failed;
	}

	if (IS_NEW_CONNECTION_REQ(flags))  {
		
		/* get the connection info from hash table if already exits
		 * else insert the connection info and return 
		 */
		 conn = create_and_get_connection(dst_ip, src_ip, 
			dst_port, src_port, seqno, ackno);
		if (unlikely(NULL == conn)) {
			DEBUG_MSG("Memory allocation failed");
			goto mem_alloc_failed;
		}
		/* If in Listen State Transition to SYN receive State*/
		if (e_tcp_state_listen == conn->connection_state) {
			conn->connection_state = e_tcp_state_syn_receive;
		}
	} 
	else if (IS_SYN_ACK_SEND(flags)) {
		host = get_host(src_ip);
		if(host) {
			conn = get_connection(host, src_ip, dst_ip, src_port, dst_port);
			if (conn) {
				/* If in SYN State transition to SYNACK Send State */
				if (IS_SYN_RECEIVE(conn)) 
					conn->connection_state = e_tcp_state_synack_send;
			}
		}
	}

 	if (IS_WAITING_FOR_ACK(flags)) {
		host = get_host(dst_ip);
		if(host) {
			conn = get_connection(host, dst_ip, src_ip, dst_port, src_port);
			if (conn) {
				/* Waiting for connection to Open, Currently Half Open */
				if (IS_HALF_OPEN(conn)) {
					host->dest_stats.complete_tcp_handshakes++;
					conn->connection_state = e_tcp_state_synack_receive;
				}
			}
		}
	}

	if (IS_FIN_OR_RST(flags)) {	
		host = get_host(dst_ip);
		if(host) {
			if (TCP_FLAG_RST & flags)
				host->dest_stats.reset_connections++;
			conn = get_connection(host, dst_ip, src_ip, dst_port, src_port);
			if (conn) {

					
				if (IS_HALF_OPEN(conn)) {
					/* Half Open Connection Closed (No Reuse) */
					conn->connection_state = e_tcp_state_listen;
					host->dest_stats.half_open_connections++;
					if (TCP_FLAG_FIN & flags) {
						host->dest_stats.unexpected_fins++;
					}
				}
				else if (IS_OPEN(conn)) {
					/* Open Connection Closed */
					conn->connection_state = e_tcp_state_listen;
				}
				else if (IS_CLOSED(conn)) {
					/* No Reuse as the problem stated */
				} 
				else if (IS_SYN_RECEIVE(conn)) {
					/* Open Connection Closed */
					conn->connection_state = e_tcp_state_listen;
					if (TCP_FLAG_FIN & flags) {
						host->dest_stats.unexpected_fins++;
					}

				}
			}
		} else {
			/* Check the Reset from Dest to Source */
			host = get_host(src_ip);
			if(host) {
				conn = get_connection(host, src_ip, dst_ip, src_port, dst_port);
				if (conn) {
					if (TCP_FLAG_RST & flags)
						host->dest_stats.reset_connections++;
				} else {
		 			conn = create_and_get_connection(dst_ip, src_ip, 
							dst_port, src_port, seqno, ackno);
					host = get_host(dst_ip);
					if (host) {
						if (TCP_FLAG_RST & flags)
							host->dest_stats.reset_connections++;
						if (TCP_FLAG_FIN & flags) {
							host->dest_stats.unexpected_fins++;
						}
					}
				}
			}
		}
	}
	return 0;
mem_alloc_failed:
	return -1;
}
/*
 * Entrypoint for the detector
 * 
 */
void run_detector(pcap_t* handle) {

	const uint8_t* packet = NULL;
	struct pcap_pkthdr* header = NULL;
	int32_t result;
	int32_t pkts_seen = 0;
	ip_hdr_t* ip_hdr = NULL;
	ethernet_hdr_t* ether_hdr = NULL;
	static packet_stats_t packet_info;
	struct timeval time;
	while(1) {
		result = pcap_next_ex(handle, &header, &packet);
		if (result == -2)
			break;
		time = header->ts;
	
		/* Ether Header */
		ether_hdr = (ethernet_hdr_t *)(packet);
	
                if (IPV4_PROTO  == unpack_uint16(ether_hdr->ethertype)) {
			
			/* IP header */
			ip_hdr = (ip_hdr_t *)(ether_hdr->data);			
			/* Protocol is 1 bytes */
			switch(ip_hdr->protocol) {
                        case IPTCP_PROTO:
				packet_info.tcp_packets++;
				/* TCP packet handler */
				tcp_packet_processing(ip_hdr, time);
				break;    
			case IPUDP_PROTO:
				/* UDP pcket handler */
 			        packet_info.udp_packets++;
				break;
			default :
                                ;
                                /*TODO*/
                        }
           	} 
		++pkts_seen;
	}

        /* Report Total TCP/UDP packets */
	report_total_packets(packet_info);
	
	/* Report TCP Connection Stats */
	report_connection_info();
	
	/* Free allocated memory */
	free_allocated_memory();
	/*
	 * Should be closed in main.c but to avoid 
	 * memory leaks closing in here 
	 */
//	pcap_close(handle);
	//return ret;
}

