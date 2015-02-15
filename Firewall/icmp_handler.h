#ifndef ICMP_HANDLER_H_
#define ICMP_HANDLER_H_
#include <stdint.h>
typedef struct icmp_hdr
{
  uint8_t type;		/* message type */
  uint8_t code;		/* type sub-code */
  uint8_t checksum[2];
  union
  {
    struct
    {
      uint8_t	id[2];
      uint8_t	sequence[2];
    } echo;			/* echo datagram */
    uint8_t	gateway[4];	/* gateway address */
    struct
    {
      uint8_t	__unused[2];
      uint8_t	mtu[2];
    } frag;			/* path mtu discovery */
  } un;
}icmp_hdr_t;

#endif /* ICMP_HANDLER_H_ */
