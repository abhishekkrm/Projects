#ifndef PROCESS_RULE_H_
#define PROCESS_RULE_H_
#include "firewall.h"
#include <stdint.h>

#define FW_MIN_PRIORITY (0)
#define FW_MAX_PRIORITY (16)
#define DEFAULT_RULE_VALUE 0




/* Firewall Port  */
enum fw_port {
	PORT_SRC = 0, PORT_DEST = 1
};

/* Firewall Action  */
enum fw_action {
	ACTION_BLOCKED = 0, ACTION_PASS = 1
};


typedef struct portrange {
	uint16_t start;
	uint16_t end;
} portrange_t;

typedef struct firewall_rule {
	struct firewall_rule *next;
	uint32_t index;
	uint32_t src_ip;
	portrange_t src_port;
	uint32_t dst_ip;
	portrange_t dst_port;
	enum fw_action action;
	enum fw_proto proto;
	uint8_t src_mask;
	uint8_t dst_mask;
	uint8_t priority;
} firewall_rule_t;
#define firewall_rule_s sizeof(firewall_rule_t)



#endif /* PROCESS_RULE_H_ */
