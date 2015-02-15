#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "firewall_api.h"
#include "firewall.h"
#include "intf_config.h"


void *intf_packet_handler(void * args) {

	firewall_config_t * fw_conf = (firewall_config_t *)args;
	DEBUG_MSG("Starting Firewall on %s",fw_conf->dev_name);
	pcap_loop(fw_conf->src, -1, packet_handler, (unsigned char *)fw_conf);
	pcap_close(fw_conf->src);
	return (0);
}

pcap_t *set_intf_handler(char *dev) {
		char errbuf[PCAP_ERRBUF_SIZE];
	    struct bpf_program fp;
		pcap_t * handle;
	    /* Open device for reading this time lets set it in promiscuous
	     * mode so we can monitor traffic to another machine
	     */

	     handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	     if (handle == NULL) {
	    	 DEBUG_ERR("Failed %s pcap_open_live(): %s",dev,errbuf);
	    	 exit(EXIT_FAILURE);
	     }

	     /* Lets try and compile the program.. non-optimized */
	     if (pcap_compile(handle, &fp,FILTER_PACKETS, 0,PCAP_NETMASK_UNKNOWN) == -1) {
	    	 DEBUG_ERR("Error calling pcap_compile %s", dev);
	    	// exit(EXIT_FAILURE);
	     }

	     /* set the compiled program as the filter */
	     if (pcap_setfilter(handle, &fp) == -1) {
	    	 DEBUG_ERR("Error setting filter %s", dev);
	    	 exit(EXIT_FAILURE);
	     }

	     return (handle);
}

int initialize_interface_handler() {

		pthread_t intf_handler[FW_MAX_INTF];
		int intf_handler_count=0;
		int i;
		struct sockaddr_in ip_ext;
		struct sockaddr_in ip_int;

		firewall_config_t *fw_conf_int = (firewall_config_t *)malloc(firewall_config_s);
		firewall_config_t *fw_conf_ext = (firewall_config_t *)malloc(firewall_config_s);
		memset(fw_conf_int, 0,firewall_config_s);
		memset(fw_conf_ext, 0,firewall_config_s);


		//  Fill following MACs for _int and _ext threads
		/*
		 * GW   		    EXT-----------------INT                  Network
		 * Gw 		        wlan0               ep1s                    ep1
		 *   	    	    ext:src_mac       int:src_mac
		 *      	      int:src_mac_used   ext:src_mac_used
		 * int:dst_mac_used                                      ext:dst_mac_used
		 */

		/* Internal Network */
		fw_conf_int->src = set_intf_handler(INT_INTF);
		strncpy(fw_conf_int->dev_name,INT_INTF,MAX_DEVICE_LEN-1);
		fw_conf_ext->dst = fw_conf_int->src;
		fw_conf_int->is_internal = 1;
		fw_conf_int->pcap_mode =0;
		fill_mac_address(INT_INTF,fw_conf_int->src_mac);
		fill_mac_address(EXT_INTF,fw_conf_int->src_mac_used);
		setmac_from_str(GATEWAY_MAC, fw_conf_int->dst_mac_used);
		inet_pton(AF_INET, WLAN_IP, &(ip_int.sin_addr));
		fw_conf_int->nat_ip = ntohl(ip_int.sin_addr.s_addr);

		/* External Network */
		fw_conf_int->dst = set_intf_handler(EXT_INTF);
		strncpy(fw_conf_ext->dev_name,EXT_INTF,MAX_DEVICE_LEN-1);
		fw_conf_ext->src = fw_conf_int->dst;
		fw_conf_ext->pcap_mode =0;
		fill_mac_address(EXT_INTF,fw_conf_ext->src_mac);
		fill_mac_address(INT_INTF,fw_conf_ext->src_mac_used);
		setmac_from_str(INTERNAL_INTF_EP_MAC,fw_conf_ext->dst_mac_used);
		inet_pton(AF_INET, EP1_IP, &(ip_ext.sin_addr));
		fw_conf_ext->nat_ip = ntohl(ip_ext.sin_addr.s_addr);

		//intf_packet_handler((void*)fw_conf_int);
		/*                      NAT operation
		 *       EXT--------------------------------------------INT
		 *      (natip)dst_ip=ep1_ip:nat_ip         (nat_ip)src_ip=wlan_ip:nat_ip
		 *      src_mac=ep1s_mac:src_mac_used       src_mac=wlan_mac:src_mac_used
		 *		dst_mac=ep1_mac:dst_mac_used        dst_mac=gw_mac:dst_mac_used
		 */
		/* Create Second Thread for External network */

		pthread_create(&intf_handler[intf_handler_count++], NULL, intf_packet_handler, (void*)fw_conf_ext);
		intf_handler_count++;

		/* Create Second Thread for internal network */
		pthread_create(&intf_handler[intf_handler_count++], NULL, intf_packet_handler, (void*)fw_conf_int);
		intf_handler_count++;

		pthread_create(&intf_handler[intf_handler_count++], NULL, flow_timeout_cleaner, (void*)NULL);
		intf_handler_count++;

		for(i=0; i< intf_handler_count;i++) {
			pthread_join(intf_handler[i],NULL);
		}

	DEBUG_INFO("Firewall Existed....")
	return (1);
}







