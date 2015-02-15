#ifndef TCP_HANDLER_H_
#define TCP_HANDLER_H_
#include <stdint.h>
#define TCP_CHECKSUM_LENGTH 2

/*
 * TCP FLAGS
 */
#define TCP_FLAG_FIN	(0x01)
#define TCP_FLAG_SYN	(0x02)
#define TCP_FLAG_RST	(0x04)
#define TCP_FLAG_PSH	(0x08)
#define TCP_FLAG_ACK	(0x10)
#define TCP_FLAG_URG	(0x20)
#define TCP_FLAG_ECE	(0x40)
#define TCP_FLAG_CWR	(0x80)

/* SYN Flag is marked but No (SYNACK RST and FIN) */
#define IS_NEW_CONNECTION_REQ(flags) ((flags & TCP_FLAG_SYN)  && \
				 !(flags & (TCP_FLAG_RST|TCP_FLAG_ACK|TCP_FLAG_FIN)))

#define IS_SYN_ACK_SEND(flags)  ((flags & (TCP_FLAG_SYN|TCP_FLAG_ACK)) &&\
				!(flags & (TCP_FLAG_RST|TCP_FLAG_FIN)))

#define IS_WAITING_FOR_ACK(flags)  ((flags & TCP_FLAG_ACK) &&\
				!(flags & (TCP_FLAG_RST|TCP_FLAG_FIN)))

#define IS_FIN_OR_RST(flags)	((flags & TCP_FLAG_RST) ||\
				 (flags & TCP_FLAG_FIN))

#define IS_SYN_RECEIVE(con) 	(con->connection_state == e_tcp_state_syn_receive)
#define IS_HALF_OPEN(con)	 (con->connection_state == e_tcp_state_synack_send)
#define IS_OPEN(con) 		(con->connection_state == e_tcp_state_synack_receive)
#define IS_CLOSED(con) 		(con->connection_state == e_tcp_state_closed)



/* TCP Events */
enum tcp_event {
e_tcp_flag_syn = 0,		/* SYN Packets */
e_tcp_flag_synack,		/* SYNACK Packets  */
e_tcp_flag_ack,			/* Ack Packets */
e_tcp_flag_psh,			/* PUSH Packets  */
e_tcp_flag_rst,			/* RST Packets */
e_tcp_flag_fin,			/* FINI Packets */
e_tcp_flag_count
};
/*
 * TCP header
 * BYTE Structure
 */
typedef struct {
	uint8_t src_port[2];
	uint8_t dst_port[2];
	uint8_t seq_no[4];
	uint8_t ack_no[4];
	uint8_t offset_reservd;
	uint8_t flags;
	uint8_t window[2];
	uint8_t checksum[2];
	uint8_t urgent_pointer[2];
	uint8_t options_and_data[0];
} tcp_hdr_t;



#endif /* TCP_HANDLER_H_ */
