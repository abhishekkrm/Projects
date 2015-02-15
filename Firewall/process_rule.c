#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "process_rule.h"
#include "firewall_api.h"
#include "firewall.h"

firewall_rule_t *rule_list[FW_MAX_PRIORITY];

#define NETMASK(ip,mask) ((mask == MAX_NETMASK)? ip: (ip & (~((1U<<(MAX_NETMASK-mask))-1))))

/*
 *
 * Find rule and return action
 * Default is to block all packets
 */
int find_flow_rule(enum fw_proto proto, int32_t dst_ip, uint32_t src_ip, uint16_t dst_port, uint16_t src_port) {
	int action = BLOCKED, i;
	for (i = FW_MAX_PRIORITY - 1; i >= FW_MIN_PRIORITY; i--) {
		firewall_rule_t *rules = rule_list[i];
		while (rules) {
			if (((proto == rules->proto) ||  (0 == rules->proto)) &&
				((NETMASK(src_ip, rules->src_mask) == NETMASK(rules->src_ip, rules->src_mask)) || (0 == rules->src_ip)) &&
				((NETMASK(dst_ip, rules->dst_mask) == NETMASK(rules->dst_ip, rules->dst_mask)) || (0 == rules->dst_ip)) &&
				(((src_port >= rules->src_port.start) && (src_port <= rules->src_port.end)) || (0 == src_port))  &&
				(((dst_port >= rules->dst_port.start) && (dst_port <= rules->dst_port.end)) || (0 == dst_port))) {
				action = rules->action;
				DEBUG_MSG("Rule Found Action %d",action)
				return (action);
			}
			rules=rules->next;
		}
	}
	return (action);
}

void dump_rule_list() {
	int i;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];


	DEBUG_INFO("%-8s %-8s %-5s %16s %32s ", "Priority", "Action", "Proto",
			"Source", "Destination");
	for (i = FW_MAX_PRIORITY - 1; i >= FW_MIN_PRIORITY; i--) {
		firewall_rule_t *rules_l = rule_list[i];
		while (rules_l) {

			uint32_2_ip(src_ip, rules_l->src_ip);
			uint32_2_ip(dst_ip, rules_l->dst_ip);

			DEBUG_INFO("%-8d %-8s %-5s %16s/%-2d[%-5u-%5u] %16s/%-2d[%-5u-%5u] ",
					rules_l->priority,
					(ACTION_PASS == rules_l->action) ? "PASS" : "BLOCK",
					((PROTO_TCP == rules_l->proto) ? "TCP" :
					((PROTO_UDP == rules_l->proto) ? "UDP" :
					((PROTO_ICMP == rules_l->proto) ? "ICMP" : "ANY"))),
					(src_ip), rules_l->src_mask, rules_l->src_port.start, rules_l->src_port.end,
					(dst_ip), rules_l->dst_mask, rules_l->dst_port.start, rules_l->dst_port.end);
			rules_l = rules_l->next;
		}
	}
}

static void insert_rule(firewall_rule_t * rule) {
	/* Insert Rule */
	if ((rule->priority >= FW_MIN_PRIORITY)
			&& (rule->priority < FW_MAX_PRIORITY)) {
		rule->next = rule_list[rule->priority];
		rule_list[rule->priority] = rule;
	} else {
		free(rule);
	}
}

firewall_rule_t * make_rule() {
	static int rule_idx = 1;
	firewall_rule_t * new_rule = (firewall_rule_t *) malloc(firewall_rule_s);
	if (new_rule) {
		new_rule->index = rule_idx++;
		new_rule->src_ip = DEFAULT_RULE_VALUE;
		new_rule->src_port.start = DEFAULT_RULE_VALUE;
		new_rule->src_port.end = MAX_PORT;
		new_rule->src_mask = MAX_NETMASK;
		new_rule->dst_ip = DEFAULT_RULE_VALUE;
		new_rule->dst_port.start = DEFAULT_RULE_VALUE;
		new_rule->dst_port.end = MAX_PORT;
		new_rule->dst_mask = MAX_NETMASK;
		new_rule->action = ACTION_BLOCKED;
		new_rule->proto = PROTO_ANY;
		new_rule->priority = DEFAULT_RULE_VALUE;
		new_rule->next = NULL;
	}
	return (new_rule);
}

int parse_fw_rules(const char *filename) {
	FILE *fp = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	char *token = NULL, *subtoken = NULL, *saveptr_t, *saveptr_st;
	struct sockaddr_in sa;
	enum fw_port next_port = PORT_SRC;

	fp = fopen(filename, "r");

	if (fp == NULL) {
		DEBUG_ERR("Unable to open rule file: %s", filename);
		exit(EXIT_FAILURE);
	}

	while ((read = getline(&line, &len, fp)) != -1) {

		token = strtok_r(line, " ", &saveptr_t);
		/* Skip if first character is # (Comments) */
		if (token && ('#' == *token)) {
			continue;
		}

		firewall_rule_t *rule = make_rule();
		next_port = PORT_SRC;
		while (token) {

			/* Rule first field is Action */
			if (0 == strcasecmp(token, "block")) {
				rule->action = ACTION_BLOCKED;
			} else if (0 == strcasecmp(token, "pass")) {
				rule->action = ACTION_PASS;
			}

			/* Rule field is Proto */
			if (0 == strcasecmp(token, "proto")) {
				token = strtok_r(NULL, " ", &saveptr_t);
				if (0 != strcasecmp(token, "any")) {
					if (0 == strcasecmp(token, "tcp")) {
						rule->proto = PROTO_TCP;
					} else if (0 == strcasecmp(token, "udp")) {
						rule->proto = PROTO_UDP;
					} else if (0 == strcasecmp(token, "icmp")) {
						rule->proto = PROTO_ICMP;
					}
				} else {
					rule->proto = PROTO_ANY;
				}
			}

			/* Rule field is from (Source) */
			if (0 == strcasecmp(token, "from")) {
				token = strtok_r(NULL, " ", &saveptr_t);
				subtoken = strtok_r(token, "/", &saveptr_st);
				if (0 != strcasecmp(subtoken, "any")) {
					inet_pton(AF_INET, subtoken, &(sa.sin_addr));
					rule->src_ip = ntohl(sa.sin_addr.s_addr);
					subtoken = strtok_r(NULL, "/", &saveptr_st);
					if (subtoken) {
						rule->src_mask = atoi(subtoken);
					}
				} else {
					rule->src_ip = DEFAULT_RULE_VALUE;
				}
			}

			/* Rule field is PORT (Source) */
			if (0 == strcasecmp(token, "port")) {
				token = strtok_r(NULL, " ", &saveptr_t);
				subtoken = strtok_r(token, "-", &saveptr_st);
				if (PORT_SRC == next_port) {
					if (0 != strcasecmp(subtoken, "any")) {
						rule->src_port.start = atoi(subtoken);
						rule->src_port.end = atoi(subtoken);
						subtoken = strtok_r(NULL, "-", &saveptr_st);
						if (subtoken) {
							rule->src_port.end = atoi(subtoken);
						}
					}
				} else {
					if (0 != strcasecmp(subtoken, "any")) {
						rule->dst_port.start = atoi(subtoken);
						rule->dst_port.end = atoi(subtoken);
						subtoken = strtok_r(NULL, "-", &saveptr_st);
						if (subtoken) {
							rule->dst_port.end = atoi(subtoken);
						}
					}
				}
			}
			/* Rule field is to (Destination) */
			if (0 == strcasecmp(token, "to")) {
				next_port = PORT_DEST;
				token = strtok_r(NULL, " ", &saveptr_t);
				subtoken = strtok_r(token, "/", &saveptr_st);
				if (0 != strcasecmp(subtoken, "any")) {
					inet_pton(AF_INET, subtoken, &(sa.sin_addr));
					rule->dst_ip = ntohl(sa.sin_addr.s_addr);
					subtoken = strtok_r(NULL, "/", &saveptr_st);
					if (subtoken) {
						rule->dst_mask = atoi(subtoken);
					}
				} else {
					rule->dst_ip = DEFAULT_RULE_VALUE;
				}
			}

			/* Rule field is Priority*/
			if (0 == strcasecmp(token, "priority")) {
				token = strtok_r(NULL, " ", &saveptr_t);
				if (0 != strcasecmp(token, "any")) {
					rule->priority = atoi(token);
				} else {
					rule->priority = DEFAULT_RULE_VALUE;
				}
			}
			token = strtok_r(NULL, " ", &saveptr_t);
		} /* One line read */
		insert_rule(rule);
	} /* End of file read Loop */
	dump_rule_list();
	free(line);
	fclose(fp);
	return (1);
}
