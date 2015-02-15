#ifndef UDP_HANDLER_H_
#define UDP_HANDLER_H_
#include <stdint.h>

#define UDP_CHECKSUM_LENGTH 2
typedef struct udp_hdr {
  uint8_t	source[2];
  uint8_t	dest[2];
  uint8_t	len[2];
  uint8_t	check[2];
}udp_hdr_t ;

#endif /* UDP_HANDLER_H_ */
