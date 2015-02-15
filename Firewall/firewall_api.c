#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "firewall_api.h"
#include "firewall.h"

/* Set Mac Address */
void setmac_from_str(char *macstr, uint8_t *mac) {
unsigned int iMac[6];
int i;
sscanf(macstr,"%x:%x:%x:%x:%x:%x", &iMac[0], &iMac[1], &iMac[2], &iMac[3], &iMac[4], &iMac[5]);
for(i=0;i<6;i++)
    mac[i] = (uint8_t)iMac[i];
}

/*
 * Convert U32int to IP
 */
void uint32_2_ip(char *addr, uint32_t ip) {
	unsigned char first = (ip)     & 0xff;
	unsigned char second = (ip>>8)  & 0xff;
	unsigned char third  = (ip>>16) & 0xff;
	unsigned char fourth = (ip>>24) & 0xff;
	sprintf(addr,"%u.%u.%u.%u", fourth, third, second, first);
}

/* Fill Mac Address Given Name */
void fill_mac_address(char *dev, uint8_t *mac)
{
    int fd;
    struct ifreq ifr;
    char *iface = dev;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
#define ETH_ALEN        6
    memcpy(mac,(unsigned char *)ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#undef ETH_ALEN
}

 uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
        unsigned long sum = 0;
        const uint16_t *ip1;
        ip1 = buf;
        while (hdr_len > 1)
        {
               sum += *ip1++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                hdr_len -= 2;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return(~sum);
}

nat_atributes_t  nat;
#define INDEX(i) (i-START_NAT_PORT)

static inline uint16_t __thread_safe_get_netid_list(uint16_t index) {
	uint16_t id;
	pthread_mutex_lock(&natport_table);
	id = nat.fd_port_list[index];
	pthread_mutex_unlock(&natport_table);
	return (id);
}
uint16_t __thread_safe_get_internal_nat_map(uint16_t port) {
	uint16_t req_port;
	pthread_mutex_lock(&natport_table);
	req_port = internal_nat_map[port].port;
	pthread_mutex_unlock(&natport_table);
	return (req_port);
}

uint16_t __thread_safe_get_external_nat_map(uint16_t port) {
	uint16_t req_port;
	pthread_mutex_lock(&natport_table);
	req_port = external_nat_map[port].port;
	pthread_mutex_unlock(&natport_table);
	return (req_port);
}

uint16_t __thread_safe_get_free_port_nat(uint16_t src_port) {
	struct sockaddr_in addr;
	int sock_fd;
	uint16_t i;

	for (i = START_NAT_PORT; i < MAX_PORT;  i++) {

		/* Port is allocated for NAT  Search another one */
		/* Ok one thread can remove No need to grab entire session*/
		if (__thread_safe_get_netid_list(INDEX(i)))
			continue;

		/* Open up the TCP socket to listens on */
		if ((sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			DEBUG_ERR("Socket %d create error ", sock_fd);
			/* No Port Found */
			/* Running out of Process FD */
			DEBUG_MSG("Try increasing process FD limit")
			 return (0);
		}

		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
		/* Try Binding the ith Port */
		addr.sin_port = htons(i);
		addr.sin_addr.s_addr = INADDR_ANY;

		if (bind(sock_fd, (struct sockaddr *) &addr,
				sizeof(addr)) < 0) {
			/* If error then try on some other ports
			 * already connections is Bind
			 * */
			close(sock_fd);
			continue ;
		}

		if (0 == listen(sock_fd,10)) {
			/* Don't close Socket */
			goto free_port_found;
		}
		close(sock_fd);
	}
	/* No Port Found */
	DEBUG_ERR("No Free Port Found");
	return (1);
free_port_found:
		pthread_mutex_lock(&natport_table);
		nat.fd_port_list[INDEX(i)] = sock_fd;
		nat.total_port++;
		internal_nat_map[src_port].port = i;
		external_nat_map[i].port = src_port;
		pthread_mutex_unlock(&natport_table);
		DEBUG_MSG("ALLOCATED PORT %u", i)
	return (i);
}

int __thread_safe_free_port_nat(uint16_t port) {
	if ((INDEX(port)<0)) {
		DEBUG_MSG("Unused Port Free")
			return (-1);
	}
	pthread_mutex_lock(&natport_table);
	DEBUG_MSG("free port %d", port)
	if (nat.fd_port_list[INDEX(port)]) {
		/* Close Socket */
		close(nat.fd_port_list[INDEX(port)]);
		nat.fd_port_list[INDEX(port)] = 0;
		if (port < MAX_PORT &&  port > 0) {
			internal_nat_map[external_nat_map[port].port].port = 0;
			external_nat_map[port].port=0;
		}
		nat.total_port--;
	}
	pthread_mutex_unlock(&natport_table);
	return (0);
}



