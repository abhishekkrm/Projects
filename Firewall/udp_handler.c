#include <stdio.h>
#include <string.h>
#include "udp_handler.h"
#include "firewall.h"
#include "firewall_api.h"

static inline int32_t __thread_safe_udp_packet_processing (struct timeval time, int32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port) {
	_HASH_LOCK_OPERATE(dst_ip, src_ip);
 	connections_t *conn = NULL;
 	int32_t action = NO_VALUE;
	conn = create_and_get_connection(PROTO_UDP, dst_ip, src_ip, dst_port, src_port);
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

static inline int32_t  find_flow_rule_udp(struct timeval time, uint32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port) {
	connections_t *conn = NULL;
	int32_t action = NO_VALUE;
	action = __thread_safe_udp_packet_processing(time, dst_ip, src_ip, dst_port, src_port);
	if(action == NO_VALUE){
		action = find_flow_rule(PROTO_UDP, dst_ip, src_ip, dst_port, src_port);
		__thread_safe_insert_action(action, PROTO_UDP, dst_ip, src_ip, dst_port, src_port);
	}
	return (action);
}

int32_t udp_pkt_handler(const u_char * packet, firewall_config_t *fw_conf, int header_len, struct timeval time) {
	ethernet_hdr_t* ether_hdr = (ethernet_hdr_t *)(packet);
	ip_hdr_t* ip_hdr = (ip_hdr_t *)(ether_hdr->data);
	udp_hdr_t * udp_hdr = (udp_hdr_t *)(ip_hdr->options_and_data);
	int32_t action = BLOCKED;
	uint16_t chksum=0, alloc_port = 0 ;

	uint32_t dst_ip = unpack_uint32(ip_hdr->dst_ip);
	uint32_t src_ip = unpack_uint32(ip_hdr->src_ip);
	uint16_t src_port = unpack_uint16(udp_hdr->source);
	uint16_t dst_port = unpack_uint16(udp_hdr->dest);

	/* On Internal Network Apply rule before NATing */
	if (fw_conf->is_internal) {
		action = find_flow_rule_udp(time, dst_ip, src_ip, dst_port, src_port);
			if(BLOCKED == action) {
				DEBUG_MSG("UDP PACKET DROPPING");
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
			pack_uint16(src_port, udp_hdr->source);
			src_ip = fw_conf->nat_ip;
	} else {
			dst_port = __thread_safe_get_external_nat_map(dst_port);
			if (dst_port) {
				pack_uint16(dst_port, udp_hdr->dest);
			} else {
			//	DEBUG_MSG("Connection Started from Outside Blocking No Mapping...");
				return BLOCKED;
			}
			dst_ip = fw_conf->nat_ip;
			action = find_flow_rule_udp(time, dst_ip, src_ip, dst_port, src_port);
			if(BLOCKED == action) {
				DEBUG_MSG("UDP PACKET DROP...");
				return (BLOCKED);
			}
	}
		    /* NAT Code */
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
			/* Update IP Checksum */
			memset(ip_hdr->checksum, 0, IP_CHECKSUM_LENGTH);
			chksum = ip_checksum(ip_hdr, sizeof(ip_hdr_t));
			memcpy(ip_hdr->checksum, &chksum, IP_CHECKSUM_LENGTH);

			/* Update UDP Checksum */
			memset(udp_hdr->check, 0, UDP_CHECKSUM_LENGTH);

	return (action);
}
