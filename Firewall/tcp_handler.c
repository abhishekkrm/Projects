#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "tcp_handler.h"
#include "firewall.h"
#include "firewall_api.h"

/*The TCP pseudo header */
 typedef struct tcp_pseudo
 {
	   uint8_t src_addr[IP_ALEN];
	   uint8_t dst_addr[IP_ALEN];
	   uint8_t zero;
	   uint8_t proto;
	   uint8_t length[2];
 } pseudo_t;


 static inline int32_t  find_flow_rule_tcp(struct timeval time, uint8_t flags, uint32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port) {
 	int32_t action = NO_VALUE;
 	action = __thread_safe_tcp_state_machine_processing(time, flags, dst_ip, src_ip, dst_port, src_port);
 	/* No Entry in State full fire wall*/
 	if (NO_VALUE == action) {
 		action = find_flow_rule(PROTO_TCP, dst_ip, src_ip, dst_port, src_port);
 		__thread_safe_insert_action(action, PROTO_TCP,dst_ip, src_ip, dst_port, src_port);
 	}
 	return (action);
 }
 uint16_t _checksum(void* vdata,size_t length) {
     // Cast the data pointer to one that can be indexed.
     char* data=(char*)vdata;

     // Initialise the accumulator.
     uint64_t acc=0xffff;

     // Handle any partial block at the start of the data.
     unsigned int offset=((uintptr_t)data)&3;
     if (offset) {
         size_t count=4-offset;
         if (count>length) count=length;
         uint32_t word=0;
         memcpy(offset+(char*)&word,data,count);
         acc+=ntohl(word);
         data+=count;
         length-=count;
     }

     // Handle any complete 32-bit blocks.
     char* data_end=data+(length&~3);
     while (data!=data_end) {
         uint32_t word;
         memcpy(&word,data,4);
         acc+=ntohl(word);
         data+=4;
     }
     length&=3;

     // Handle any partial block at the end of the data.
     if (length) {
         uint32_t word=0;
         memcpy(&word,data,length);
         acc+=ntohl(word);
     }

     // Handle deferred carries.
     acc=(acc&0xffffffff)+(acc>>32);
     while (acc>>16) {
         acc=(acc&0xffff)+(acc>>16);
     }

     // If the data began at an odd byte address
     // then reverse the byte order to compensate.
     if (offset&1) {
         acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
     }

     // Return the checksum in network byte order.
     return (htons(~acc));
 }

int32_t tcp_pkt_handler(const u_char * packet, firewall_config_t *fw_conf, int len_header,struct timeval time) {
		ethernet_hdr_t* ether_hdr =(ethernet_hdr_t *)(packet);
		ip_hdr_t* ip_hdr =  (ip_hdr_t *)(ether_hdr->data);
		tcp_hdr_t * tcp_hdr = (tcp_hdr_t *)(ip_hdr->options_and_data);
		int action = BLOCKED;
		uint16_t chksum=0, alloc_port=0;
		action =PASS;
		uint16_t src_port = unpack_uint16(tcp_hdr->src_port);
		uint16_t dst_port = unpack_uint16(tcp_hdr->dst_port);
		uint8_t flags = tcp_hdr->flags;
		uint32_t dst_ip = unpack_uint32(ip_hdr->dst_ip);
		uint32_t src_ip = unpack_uint32(ip_hdr->src_ip);

		/* On Internal Network Apply rule before NATing */
		if (fw_conf->is_internal) {
				action = find_flow_rule_tcp(time, flags, dst_ip, src_ip, dst_port, src_port);
				if(BLOCKED == action) {
					DEBUG_MSG("Tcp PACKET DROPPING");
					return (BLOCKED);
				}
				src_port = __thread_safe_get_internal_nat_map(src_port);
				if(!src_port) {
					alloc_port = __thread_safe_get_free_port_nat(src_port);
					if (0 == alloc_port) {
						DEBUG_ERR("Unable to allocate port");
						return BLOCKED;
					}
				}
				pack_uint16(src_port, tcp_hdr->src_port);
				src_ip = fw_conf->nat_ip;
		} else {
				dst_port = __thread_safe_get_external_nat_map(dst_port);
				if (dst_port) {
					pack_uint16(dst_port, tcp_hdr->dst_port);
				} else {
				//	DEBUG_MSG("Connection Started from Outside Blocking No Mapping...");
					return BLOCKED;
				}
				dst_ip = fw_conf->nat_ip;
				action = find_flow_rule_tcp(time, flags, dst_ip, src_ip, dst_port, src_port);
				if(BLOCKED == action) {
					DEBUG_MSG("TCP PACKET DROP...");
					return (BLOCKED);
				}
		}
		 /* NAT Code */
		{
			/*                      NAT operation
			 *       EXT--------------------------------------------INT
			 *      (natip)dst_ip=ep1_ip:nat_ip         (nat_ip)src_ip=wlan_ip:nat_ip
			 *      src_mac=ep1s_mac:src_mac_used       src_mac=wlan_mac:src_mac_used
			 *		dst_mac=ep1_mac:dst_mac_used        dst_mac=gw_mac:dst_mac_used
			 */
			memcpy(ether_hdr->dst_mac, fw_conf->dst_mac_used, ETH_ALEN);
			memcpy(ether_hdr->src_mac, fw_conf->src_mac_used, ETH_ALEN);
			if (fw_conf->is_internal) {
				pack_uint32(fw_conf->nat_ip, ip_hdr->src_ip);
			} else {
				pack_uint32(fw_conf->nat_ip, ip_hdr->dst_ip);
			}
		}

		/* Update IP Checksum */
		memset(ip_hdr->checksum, 0,IP_CHECKSUM_LENGTH);
		chksum = ip_checksum(ip_hdr, sizeof(ip_hdr_t));
		memcpy(ip_hdr->checksum, &chksum, IP_CHECKSUM_LENGTH);
		PRINT_TCP_HDR(tcp_hdr);
		PRINT_IP_HDR(ip_hdr);
		/* Update TCP Checksum */

		pseudo_t tcp_pseudo;
		/* tcp pseudo header */
		memset(tcp_hdr->checksum, 0,TCP_CHECKSUM_LENGTH);
		memset(&tcp_pseudo, 0, sizeof(struct tcp_pseudo));
		memcpy(&tcp_pseudo.src_addr,ip_hdr->src_ip, IP_ALEN);
		memcpy(&tcp_pseudo.dst_addr,ip_hdr->dst_ip, IP_ALEN);
		tcp_pseudo.zero = 0;
		tcp_pseudo.proto = 6;
		int tcp_len = unpack_uint16(ip_hdr->total_len) - ((ip_hdr->version_ihl & 0xF)* IP_ALEN);
		pack_uint16(tcp_len, tcp_pseudo.length);

		uint8_t tcpcsumblock[sizeof(pseudo_t) + tcp_len];
		memcpy(tcpcsumblock, &tcp_pseudo, sizeof(pseudo_t));
		memcpy(tcpcsumblock + sizeof(pseudo_t), tcp_hdr, tcp_len);
		uint16_t checksum = _checksum((unsigned short *)tcpcsumblock, sizeof(tcpcsumblock));
		memcpy(tcp_hdr->checksum, &checksum, TCP_CHECKSUM_LENGTH);
	//	PRINT_TCP_HDR(tcp_hdr);
	//	PRINT_IP_HDR(ip_hdr);
	return (action);
}
