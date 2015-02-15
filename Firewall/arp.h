#ifndef ARP_H_
#define ARP_H_

#define ARP_REQUEST (1)
#define ARP_REPLY (2)
typedef struct arp_hdr {
	uint8_t arh_hardware[2];	 /* format of hardware address	*/
	uint8_t arh_proto[2];		 /* format of protocol address	*/
	uint8_t arh_hlen;			/* length of hardware address	*/
	uint8_t arh_plen;			/* length of protocol address	*/
	uint8_t arh_operation[2];	/* ARP opcode (command) */
	uint8_t	ar_sha[ETH_ALEN];	/* sender hardware address	*/
	uint8_t	ar_sip[IP_ALEN];			/* sender IP address		*/
	uint8_t	ar_tha[ETH_ALEN];	/* target hardware address	*/
	uint8_t	ar_tip[IP_ALEN];			/* target IP address		*/
} arphdr_t;

#endif /* ARP_H_ */
