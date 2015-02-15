#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include "firewall.h"
#include "firewall_api.h"

/*
 * Usage for Firewall
 */
void usage(const char *program_name) {
	fprintf(stderr,
			"Usage: %s [-i] <input_pcap> [-o] <output_pcap> -r <rule_file>\n",
			program_name);
	exit(EXIT_FAILURE);
}

/*
 * Program execution begin here
 */
int main(int argc, char *argv[]) {

	int choice;
	const char *input_pcap = NULL, *output_pcap = DEFAULT_OUTPUT_PCAP;
	const char *rule_file = DEFAULT_RULES_FILE;
	const char *prg_name = argv[0];

	/*
	 * If argument is specified then parse input pcap file,
	 * apply firewall policy and dumps filtered packets in output pcap file
	 * else run in default mode i.e apply firewall rules between interfaces
	 */
	if (1 != argc) {
		while ((choice = getopt(argc, argv, "i:o:r")) != -1) {
			switch (choice) {
			case 'i':
				input_pcap = optarg;
				break;
			case 'o':
				output_pcap = optarg;
				break;
			case 'r':
				rule_file = optarg;
				break;
			default:
				usage(prg_name);
			}
		}
		if (input_pcap) {
			DEBUG_INFO("Firewall Started ......");
			DEBUG_MSG("Input Pcap :%s Output Pcap :%s ", input_pcap,
					output_pcap);
			parse_fw_rules(rule_file);
			initialize_pcap_handler(input_pcap, output_pcap);
		} else {
			usage(prg_name);
		}

	} else {
		DEBUG_INFO("Firewall Started ......");
		parse_fw_rules(rule_file);
		initialize_interface_handler();
	}

	return (EXIT_SUCCESS);
}
