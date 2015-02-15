#ifndef FIREWALL_API_H_
#define FIREWALL_API_H_
#include <stdint.h>
#include <stdio.h>

#define DEBUG_ENABLE

/*
 * Define Macro's here
 */
#define FALSE (0)
#define TRUE (1)

#define BLOCKED  (0)
#define PASS    (1)
#define NO_VALUE (-1)

/*GCC optimization needs to be turned on */
#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

#define MAX_PORT (65535)
#define START_NAT_PORT (55535)


#define MAX_NETMASK (32)
#define IPV4_ADDRSTRLEN 16

#define DEBUG_ERR(msg, args...) do {   							\
		printf("\nERR [%s:%d] "msg, __func__, __LINE__, ##args);\
		fflush(stdout);\
	}while(0);

#define DEBUG_INFO(msg, args...) do {	\
		printf("\n"msg, ##args);		\
		fflush(stdout);\
	}while(0);

#ifdef DEBUG_ENABLE

#define DEBUG_MSG(msg, args...) do {   						\
		printf("\n[%s:%d] "msg, __func__, __LINE__, ##args);\
		fflush(stdout);\
	}while(0);

#define PRINT_ETHER_HDR(ethernet_hdr) do{\
		printf("\nETH: Dmac[%02x:%02x:%02x:%02x:%02x:%02x] Smac[%02x:%02x:%02x:%02x:%02x:%02x] etype 0x%04x",\
			ether_hdr->dst_mac[0], ether_hdr->dst_mac[1],\
			ether_hdr->dst_mac[2], ether_hdr->dst_mac[3],\
			ether_hdr->dst_mac[4], ether_hdr->dst_mac[5],\
			ether_hdr->src_mac[0], ether_hdr->src_mac[1],\
			ether_hdr->src_mac[2], ether_hdr->src_mac[3],\
			ether_hdr->src_mac[4], ether_hdr->src_mac[5],\
			unpack_uint16(ether_hdr->ethertype));\
} while(0);

#define PRINT_IP_HDR(ip_hdr) do{\
		char daddr[IPV4_ADDRSTRLEN];\
		char saddr[IPV4_ADDRSTRLEN];\
		unpack_uint32(ip_hdr->src_ip),\
		unpack_uint32(ip_hdr->dst_ip),\
		uint32_2_ip(daddr, unpack_uint32(ip_hdr->dst_ip)),\
		uint32_2_ip(saddr, unpack_uint32(ip_hdr->src_ip)),\
		printf("\nIP : Sip[%s] Dip[%s] proto 0x%02x",\
			saddr, daddr, ip_hdr->protocol);\
} while(0);

#define PRINT_TCP_HDR(tcp_hdr) do{\
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



typedef struct nat_atributes {
	uint32_t total_port;
	uint16_t last_port;
	int fd_port_list[MAX_PORT-START_NAT_PORT];
}nat_atributes_t;

typedef struct hash_table{
	uint16_t port;
} hash_table_t;



/* Fixme Change index range later */
hash_table_t external_nat_map[MAX_PORT], internal_nat_map[MAX_PORT];
pthread_mutex_t natport_table;

extern uint16_t __thread_safe_get_free_port_nat(uint16_t port);
extern int __thread_safe_free_port_nat(uint16_t port);
extern uint16_t __thread_safe_get_internal_nat_map(uint16_t port);
extern uint16_t __thread_safe_get_external_nat_map(uint16_t port);
extern uint16_t ip_checksum(const void *,size_t length);
extern uint16_t tcp_checksum(const void *buff, size_t len, uint32_t src_addr, uint32_t dest_addr);
extern void setmac_from_str(char *macstr, uint8_t *mac);
extern void uint32_2_ip(char *addr, uint32_t ip);
extern void fill_mac_address(char *dev, uint8_t *mac);
extern void pack_uint16(uint16_t val, uint8_t* buf);
extern uint16_t unpack_uint16(const uint8_t* buf);
extern void pack_uint32(uint32_t val, uint8_t* buf);
extern uint32_t unpack_uint32(const uint8_t* buf);

#endif /* FIREWALL_API_H_ */
