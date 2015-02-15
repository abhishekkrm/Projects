#include <stdio.h>
#include <string.h>
#include "icmp_handler.h"
#include "firewall.h"
#include "firewall_api.h"


static inline int32_t  __thread_safe_icmp_packet_processing (struct timeval time, int32_t dst_ip, uint32_t src_ip) {
	_HASH_LOCK_OPERATE(dst_ip, src_ip);
 	connections_t *conn = NULL;
 	int32_t action = NO_VALUE;
	conn = create_and_get_connection(PROTO_ICMP, dst_ip, src_ip, 0, 0);
	if (unlikely(NULL == conn)) {
	 		DEBUG_MSG("Memory allocation failed");
	 		return (NO_VALUE);
	}
	/* Update time out on every flow */
	if (conn) {
		conn->timeout = time;
		action = conn->action;
	} else {
		action = NO_VALUE;
	}
	_HASH_UNLOCK_OPERATE(dst_ip, src_ip);
	return (action);
}

static inline int  find_flow_rule_icmp(struct timeval time, uint32_t dst_ip, uint32_t src_ip) {
	int32_t action = NO_VALUE;
	action = __thread_safe_icmp_packet_processing(time, dst_ip, src_ip);
	if(action == NO_VALUE){
		action = find_flow_rule(PROTO_ICMP, dst_ip, src_ip, 0, 0);
		__thread_safe_insert_action(action, PROTO_ICMP, dst_ip, src_ip, 0, 0);
	}
	return (action);
}

int icmp_pkt_handler(const u_char * packet, firewall_config_t *fw_conf, int header_len, struct timeval time) {
	ethernet_hdr_t* ether_hdr = (ethernet_hdr_t *)(packet);
	ip_hdr_t* ip_hdr = (ip_hdr_t *)(ether_hdr->data);
	int action = BLOCKED;
	uint32_t dst_ip = unpack_uint32(ip_hdr->dst_ip);
	uint32_t src_ip = unpack_uint32(ip_hdr->src_ip);
	uint16_t chksum=0;
	/* On Internal Network Apply rule before NATing */
		if (fw_conf->is_internal) {
			PRINT_IP_HDR(ip_hdr);
			action = find_flow_rule_icmp(time, dst_ip, src_ip);
			if(BLOCKED == action) {
				DEBUG_MSG("ICMP PACKET DROPPING");
				return (BLOCKED);
			}
			src_ip = fw_conf->nat_ip;
		}else {
			dst_ip = fw_conf->nat_ip;
			/* Revere Matching of rule */
			PRINT_IP_HDR(ip_hdr);
			action = find_flow_rule_icmp(time, src_ip, dst_ip);
			if(BLOCKED == action) {
				DEBUG_MSG("ICMP PACKET DROPPING ...");
				return (BLOCKED);
			}
		}

		/*                      NAT operation
		 *       EXT--------------------------------------------INT
		 *      (natip)dst_ip=ep1_ip:nat_ip         (nat_ip)src_ip=wlan_ip:nat_ip
		 *      src_mac=ep1s_mac:src_mac_used       src_mac=wlan_mac:src_mac_used
		 *		dst_mac=ep1_mac:dst_mac_used        dst_mac=gw_mac:dst_mac_used
		 */
		memcpy(ether_hdr->dst_mac, fw_conf->dst_mac_used, ETH_ALEN);
		memcpy(ether_hdr->src_mac, fw_conf->src_mac_used, ETH_ALEN);
		if (fw_conf->is_internal) {
			pack_uint32(src_ip, ip_hdr->src_ip);
		} else {
			pack_uint32(dst_ip, ip_hdr->dst_ip);
		}
		/* Update Checksum */
		memset(ip_hdr->checksum, 0,IP_CHECKSUM_LENGTH);
		chksum = ip_checksum(ip_hdr, sizeof(ip_hdr_t));
		memcpy(ip_hdr->checksum, &chksum, IP_CHECKSUM_LENGTH);
		DEBUG_MSG("action %d",action)
	return (action);
}
