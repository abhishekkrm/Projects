#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <string.h>
#include "firewall.h"
#include "firewall_api.h"
#include "arp.h"

#ifdef DEBUG_ENABLE
#define  DUMP_APR_PACKET(arphdr) do{ \
	char src_ip[INET_ADDRSTRLEN];\
	char dst_ip[INET_ADDRSTRLEN];\
	uint32_2_ip(src_ip, unpack_uint32(arphdr->ar_sip));\
	uint32_2_ip(dst_ip, unpack_uint32(arphdr->ar_tip));\
	DEBUG_MSG("Arp: hard %x prot %x hlen %u plen  %u oper %u"\
			   " smac %02x:%02x:%02x:%02x:%02x:%02x sip  %s "\
			   " dmac %02x:%02x:%02x:%02x:%02x:%02x dip %s",\
		unpack_uint16(arphdr->arh_hardware),\
		unpack_uint16(arphdr->arh_proto),\
		arphdr->arh_hlen, arphdr->arh_plen,\
		unpack_uint16(arphdr->arh_operation),\
		arphdr->ar_sha[0],arphdr->ar_sha[1],arphdr->ar_sha[2],\
		arphdr->ar_sha[3],arphdr->ar_sha[4],arphdr->ar_sha[5],\
		src_ip,\
		arphdr->ar_tha[0],arphdr->ar_tha[1],arphdr->ar_tha[2],\
		arphdr->ar_tha[3],arphdr->ar_tha[4],arphdr->ar_tha[5],\
		dst_ip);\
}while(0);
#else
#define  DUMP_APR_PACKET(arphdr)
#endif
void swap_bytes(char * s1, char *s2, int size){
	uint8_t tmp[size];
	memcpy(tmp, s1, size);
	memcpy(s1, s2, size);
	memcpy(s2,tmp, size);
}

int arp_pkt_handler(const u_char * packet, firewall_config_t *fw_config, int len) {

	ethernet_hdr_t* ether_hdr = NULL;

	/* Ether Header */
	ether_hdr = (ethernet_hdr_t *)(packet);

	if(ARP_PROTO  == unpack_uint16(ether_hdr->ethertype)) {

		 /* BroadCast Request */
		if(ether_hdr->dst_mac[0] == 0xff && ether_hdr->dst_mac[1] == 0xff &&
		   ether_hdr->dst_mac[2] == 0xff && ether_hdr->dst_mac[3] == 0xff &&
		   ether_hdr->dst_mac[4] == 0xff && ether_hdr->dst_mac[5] == 0xff) {

			//	if (memcmp(ether_hdr->dst_mac,"ETH_ALEN)
			arphdr_t *arphdr =(arphdr_t *)ether_hdr->data;

			/* If Request For response and inject reply */
			if (ARP_REQUEST == unpack_uint16(arphdr->arh_operation)) {

				//DUMP_APR_PACKET(arphdr);
					/* ARP Contents */
				{
					/*Form Arp Reply */
					pack_uint16(ARP_REPLY, arphdr->arh_operation);

					/* Reverse Contents */
					swap_bytes((char *)arphdr->ar_sip,(char *)arphdr->ar_tip, IP_ALEN);

					/* Copy MAC */
					memcpy((char*)arphdr->ar_tha, (char *)arphdr->ar_sha, ETH_ALEN);

					/* Set ep1s Mac as response */
					memcpy((char*)arphdr->ar_sha, fw_config->src_mac, ETH_ALEN);
				}
				/* ETHER Packet */
				/* Set dst mac as src mac received*/
				memcpy(ether_hdr->dst_mac,ether_hdr->src_mac, ETH_ALEN);
				/* Set ep1s Mac as Source*/
				memcpy(ether_hdr->src_mac, fw_config->src_mac, ETH_ALEN);

				/* Inject Packet to ep1s */
				if(pcap_inject(fw_config->src, packet, len) < 0) {
					DEBUG_ERR("Unable to inject Arp Packet")
				}
				//PRINT_ETHER_HDR(ether_hdr);
				// DUMP_APR_PACKET(arphdr);
			}
		}
	}

return (BLOCKED);
}
