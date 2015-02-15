#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "packet_handler.h"
#include "firewall_api.h"
#include "firewall.h"
#include "tcp_handler.h"


//GLOBAL VARIABLE----------------------
hashtable_t table;
struct timeval global_cur_time = (struct timeval){ 0 };;
pthread_mutex_t time_val;

/*
 * Write 2 byte value at buffer in network byte order.
 */
void pack_uint16(uint16_t val, uint8_t* buf) {
	val = htons(val);
	memcpy(buf, &val, sizeof(uint16_t));
}
/*
 * Read 2 byte value from buffer in host byte order.
 */
uint16_t unpack_uint16(const uint8_t* buf) {
	uint16_t val;
	memcpy(&val, buf, sizeof(uint16_t));
	return (ntohs(val));
}
/*
 * Write 4 byte value at buffer in network byte order.
 */
void pack_uint32(uint32_t val, uint8_t* buf) {
	val = htonl(val);
	memcpy(buf, &val, sizeof(uint32_t));
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

/*
 * Read 4 byte value from buffer in host byte order.
 */
uint32_t unpack_uint32(const uint8_t* buf) {
	uint32_t val;
	memcpy(&val, buf, sizeof(uint32_t));
	return (ntohl(val));
}

/*
 * Put host in hash table
 */
static inline host_t * new_host(uint32_t host_ip) {

	host_t *host_new = (host_t *)calloc(1, sizeof(host_t));
	if (host_new) {;
		host_new->host_addr = host_ip;
		host_new->v_list = NULL;
		host_new->h_list = NULL;
		host_new->prev_hlist =NULL;
	}
	return (host_new);
}

/*
 * return host if present in hash table
 */
static inline host_t *get_host(uint32_t host_ip) {

	host_t *host = NULL;
	host = table.host_hash[hash_ipv4_addr(host_ip)];
	if (host) {
		while(host) {
			if (host_ip == host->host_addr)
				break;
			host = host->h_list;
		}
	}
	return (host);
}
void  rm_host(host_t * host) {
	/* Remove host only if vlist is empty */
	if (NULL == host->v_list) {
		if (host->prev_hlist)
			(host->prev_hlist)->h_list = host->h_list;
		if (host->h_list)
			(host->h_list->prev_hlist) = host->prev_hlist;
		free(host);
	}
}


void  rm_connection(connections_t * conn) {
	if (conn->prev_vlist)
		(conn->prev_vlist)->v_list = conn->v_list;
    if (conn->v_list)
    	(conn->v_list->prev_vlist) = conn->prev_vlist;
	free(conn);
}

static inline connections_t *new_connection( uint16_t proto, uint32_t dst_ip, uint32_t src_ip,
			uint16_t dst_port, uint16_t src_port) {

	connections_t *conn_new = (connections_t *)calloc(1, sizeof(connections_t));
	if (conn_new) {
		conn_new->src_addr = src_ip;
		conn_new->dst_addr = dst_ip;
		conn_new->src_port = src_port;
		conn_new->dst_port = dst_port;
		conn_new->proto = proto;
		conn_new->action = NO_VALUE;
		conn_new->connection_state = e_tcp_state_listen;
		conn_new->v_list = NULL;
		conn_new->prev_vlist = NULL;
	}
	return (conn_new);
}
/*
 * get connection info corresponding to host
 */
static inline connections_t *get_connection(host_t * host,  uint16_t proto ,uint32_t dst_ip, uint32_t src_ip,
			uint16_t dst_port, uint16_t src_port) {
	connections_t *conn = host->v_list;

	while (conn) {
		if( (proto == conn->proto) &&
			(src_ip == conn->src_addr) &&
		    (dst_ip == conn->dst_addr) &&
	  	    (src_port == conn->src_port) &&
		    (dst_port == conn->dst_port)) {
			break;
		}
		conn = conn->v_list;
	}
	return (conn);
}
connections_t *create_and_get_connection(uint16_t proto, uint32_t dst_ip, uint32_t src_ip,
 			uint16_t dst_port, uint16_t src_port) {
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
 		hash_value = hash_ipv4_addr(dst_ip);
		host->h_list = table.host_hash[hash_value];
		if (host->h_list)
				host->h_list->prev_hlist = host->h_list;
			table.host_hash[hash_value] = host;
 	}
 	conn =  get_connection(host, proto, dst_ip, src_ip, dst_port, src_port);

 	if (NULL == conn) {
 		conn = new_connection(proto, dst_ip, src_ip, dst_port, src_port);
 		if (unlikely(NULL == conn)) {
 			DEBUG_MSG("Memory allocation failed");
 			goto mem_alloc_failed;
 		}
			if (host->v_list)
				host->v_list->prev_vlist = conn;
			conn->v_list = host->v_list;
			host->v_list = conn;
 	}
 	return (conn);
 mem_alloc_failed:
 	return NULL;
 }



// __grab_hash_insert_lock_
// prevent deadlock take lock on src_hash dest_hash in specfic  order avoid cycle)*/
void _HASH_LOCK_OPERATE( int32_t dst_ip,int32_t src_ip) {

	uint32_t index_small = hash_ipv4_addr(dst_ip);
	uint32_t index_big = hash_ipv4_addr(src_ip);
	if (index_big < index_small) {
		uint32_t temp = index_big;
		index_big = index_small;
		index_small = temp;
	}
	/* Lock dest and ip Index */
	pthread_mutex_lock(&hash_mutex_operate[index_small]);
	if (index_big != index_small) {
		pthread_mutex_lock(&hash_mutex_operate[index_big]);
	}
}

void  _HASH_UNLOCK_OPERATE(int32_t dst_ip,int32_t src_ip) {
	uint32_t index_small = hash_ipv4_addr(dst_ip);
	uint32_t index_big = hash_ipv4_addr(src_ip);
	if (index_big < index_small) {
		uint32_t temp = index_big;
		index_big = index_small;
		index_small = temp;
	}
	/* UNLock dest and ip Index */
	pthread_mutex_unlock(&hash_mutex_operate[index_small]);
	if (index_big != index_small) {
		pthread_mutex_unlock(&hash_mutex_operate[index_big]);
	}
}

void __thread_safe_insert_action(int32_t action, int32_t proto, int32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port) {
	host_t *host = NULL;
	connections_t *conn = NULL;
	_HASH_LOCK_OPERATE(dst_ip, src_ip);
	 host = get_host(dst_ip);
			if(host) {
				conn = get_connection(host, proto, src_ip, dst_ip, src_port, dst_port);
				if(conn)
					conn->action = action;
			}
	_HASH_UNLOCK_OPERATE(dst_ip, src_ip);
}


/*
 * Process TCP packets.
 */
int32_t __thread_safe_tcp_state_machine_processing (struct timeval time, uint8_t flags, int32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port) {

	host_t *host = NULL;
	connections_t *conn = NULL;
	connections_t *rev_conn =NULL;
	_HASH_LOCK_OPERATE(dst_ip, src_ip);
	int32_t action = NO_VALUE;
	if (IS_NEW_CONNECTION_REQ(flags))  {
		/* get the connection info from hash table if already exits
		 * else insert the connection info and return
		 */
		 conn = create_and_get_connection(PROTO_TCP, dst_ip, src_ip,
			dst_port, src_port);
		if (unlikely(NULL == conn)) {
			DEBUG_MSG("Memory allocation failed");
			goto mem_alloc_failed;
		}
				conn->connection_state = e_tcp_state_syn_receive;
	}
	else if (IS_SYN_ACK_SEND(flags)) {
		host = get_host(src_ip);
		if(host) {
			rev_conn = get_connection(host, PROTO_TCP, src_ip, dst_ip, src_port, dst_port);
			if (rev_conn) {
				/* If in SYN State transition to SYNACK Send State */
				if (IS_SYN_RECEIVE(conn))
					rev_conn->connection_state = e_tcp_state_synack_send;
			}
		}
	}
 	if (IS_WAITING_FOR_ACK(flags)) {
		host = get_host(dst_ip);
		if(host) {
			conn = get_connection(host,PROTO_TCP, dst_ip, src_ip, dst_port, src_port);
			if (conn) {
				/* Waiting for connection to Open, Currently Half Open */
				if (IS_HALF_OPEN(conn)) {
					/*Open Connection */
					conn->connection_state = e_tcp_state_establised;
					/* Open Reverse Connection and add in hash Table*/
					rev_conn = create_and_get_connection(PROTO_TCP, src_ip, dst_ip,
					 			src_port, dst_port);
					if (unlikely(NULL == rev_conn)) {
					 			DEBUG_MSG("Memory allocation failed");
					 			goto mem_alloc_failed;
					}
					rev_conn->connection_state = e_tcp_state_establised;
				}
			}
		}
	}

  if (IS_FIN_OR_RST(flags)) {
		host = get_host(dst_ip);
		if(host) {
			conn = get_connection(host,PROTO_TCP, dst_ip, src_ip, dst_port, src_port);
			if (conn) {
				/* Closed Connection */
				conn->connection_state = e_tcp_state_listen;
				rm_connection(conn);
				/* Close Reverse Connection  if exits*/
				rev_conn = get_connection(host, PROTO_TCP, src_ip, dst_ip, src_port, dst_port);
				if (rev_conn) {
					rev_conn->connection_state = e_tcp_state_listen;
					rm_connection(rev_conn);
				}
			}
		}
  }
  if(conn) {
	  conn->timeout = time;
	  action = conn->action;
  }
  _HASH_UNLOCK_OPERATE(dst_ip, src_ip);
   return (action);
mem_alloc_failed:
	return (-1);
}

void _thread_safe_set_global_time(struct timeval time) {
	pthread_mutex_lock(&time_val);
	global_cur_time = time;
	pthread_mutex_unlock(&time_val);

}
struct timeval _thread_safe_get_global_time() {
	struct timeval time;
	pthread_mutex_lock(&time_val);
	time = global_cur_time;
	pthread_mutex_unlock(&time_val);
	return (time);
}


uint32_t time_greater_than_insec(struct timeval *curtime, struct timeval *con_timeout){

	if (curtime->tv_sec > con_timeout->tv_sec) {
		return  (curtime->tv_sec - con_timeout->tv_sec);
	}else {
		return (0);
	}
}

void *flow_timeout_cleaner(void *args) {
	uint32_t offset = 0;
	uint32_t max_cleanup =	MAX_CLEAN_CONN;
	connections_t *conn_l =NULL;
	host_t * host_l = NULL;
	struct timeval curtime = _thread_safe_get_global_time();

	while (1) {
		sleep(600);
		curtime = _thread_safe_get_global_time();
		max_cleanup = MAX_CLEAN_CONN;
		while (max_cleanup-- >0) {
			host_l = table.host_hash[offset];
			pthread_mutex_lock(&hash_mutex_operate[offset]);
			while(host_l) {
				conn_l = host_l->v_list;
				while (conn_l) {
					if (time_greater_than_insec(&curtime, &conn_l->timeout) > DELETE_OLD_CONNECTION_TIME) {
							/* Remove port from Port Table */
							/*  Analyze Check Deadlock*/
							/* Check Source Port */
							__thread_safe_free_port_nat(conn_l->src_port);
							rm_connection(conn_l);
					}
					conn_l = conn_l->v_list;
				}
				if (NULL == host_l->v_list) {
					rm_host(host_l);
				}
					host_l = host_l->h_list;
			}
			pthread_mutex_unlock(&hash_mutex_operate[offset]);
			offset = (offset + 1) % HASH_SIZE;
		}
	}
}

static inline int process_packet(firewall_config_t *fw_conf,
		const struct pcap_pkthdr *header, const u_char *packet) {
	int action = BLOCKED ;
	ip_hdr_t* ip_hdr = NULL;
	ethernet_hdr_t* ether_hdr = NULL;

	/* Ether Header */
	ether_hdr = (ethernet_hdr_t *)(packet);

	if (IPV4_PROTO  == unpack_uint16(ether_hdr->ethertype)) {

		/*
		 *  Avoid Inject Loop by checking the MAC
		 *  Return if packet is not targeted to our MAC
		 */
		 if (0 != memcmp(ether_hdr->dst_mac, fw_conf->src_mac, ETH_ALEN)) {
			//DEBUG_MSG("Drop... Unwanted dest mac packet")
			return BLOCKED;
		 }

		 _thread_safe_set_global_time(header->ts);

		/* IP header */
		ip_hdr = (ip_hdr_t *)(ether_hdr->data);
		/* Protocol is 1 bytes */
		switch(ip_hdr->protocol) {
		case IPTCP_PROTO:
			/* TCP packet handler */
			action = tcp_pkt_handler(packet,fw_conf,header->len, header->ts);
			break;
		case IPUDP_PROTO:
			/* UDP packet handler */
			action = udp_pkt_handler(packet,fw_conf,header->len ,header->ts);
			break;
		case IPICMP_PROTO:
			/* ICMP packet handler */
			DEBUG_MSG("ICMP Packet received on %s",fw_conf->dev_name);
			action = icmp_pkt_handler(packet,fw_conf,header->len,header->ts);
			break;
		default :
             ;
         /*Todo check filter*/
		}
	} else if (ARP_PROTO  == unpack_uint16(ether_hdr->ethertype)) {
			//DEBUG_MSG("ARP Packet received on %s",fw_conf->dev_name);
			if (fw_conf->is_internal) {
				action = arp_pkt_handler(packet,fw_conf,header->len);
			}
	} else {
		// TODO default
		action = BLOCKED;
	}
return (action);
}

//Callback function called by libpcap for every incoming packet
void packet_handler(u_char *args,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	firewall_config_t *fw_conf = (firewall_config_t *) args;
	int forward = BLOCKED;

	forward = process_packet(fw_conf, header, pkt_data);

	//save the packet on the dump file
	if (forward == PASS) {
		/* Pcap Mode */
		if (fw_conf->pcap_mode) {
				pcap_dump((u_char *)fw_conf->out_handler,header,pkt_data);
		} else {
			DEBUG_MSG("packet enjected")
			if (pcap_inject(fw_conf->dst, pkt_data, header->len)< 0) {
				DEBUG_ERR("%s unable to inject packet",fw_conf->dev_name);
			}
		}
	}
}

int initialize_pcap_handler(const char* input_pcap, const char * output_pcap){

	char errbuf[PCAP_ERRBUF_SIZE];

	firewall_config_t *fw_conf = (firewall_config_t *)malloc(firewall_config_s);
	memset(&fw_conf,0,firewall_config_s);

	fw_conf->in_handler = pcap_open_offline(input_pcap, errbuf);

	if (fw_conf->in_handler == NULL) {
		DEBUG_ERR("Unable to open pcap file :%s", input_pcap);
		return (0);
	}

	fw_conf->out_handler = pcap_dump_open(fw_conf->in_handler, output_pcap);

	if(fw_conf->out_handler == NULL){
			DEBUG_ERR("Unable to create pcap file :%s", output_pcap);
			return (0);
	}

	fw_conf->pcap_mode = 1;
	pcap_loop(fw_conf->in_handler, 0, packet_handler, (unsigned char *)fw_conf);

	pcap_close(fw_conf->in_handler);
	pcap_dump_close(fw_conf->out_handler);

	DEBUG_INFO("Firewall Existed....")
	return (1);
}

