/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <getopt.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

/* Number of packets to attempt to read from queue */
#define PKT_READ_SIZE  ((uint16_t)32)

/* define common names for structures shared between ovs_dpdk and client */
#define MP_CLIENT_RXQ_NAME "MProc_Client_%u_RX"
#define MP_CLIENT_TXQ_NAME "MProc_Client_%u_TX"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define BASE_10 10
#define BASE_16 16

typedef enum {IP_ADDRESS_DEST, IP_ADDRESS_SRC} ip_address_t;

void mangle_ip_addresses(struct rte_mbuf *pkts[], unsigned num_pkts);

/* our client id number - tells us which rx queue to read, and tx 
 * queue to write to. */
static uint8_t client_id = 0;
static uint32_t src_ip   = 0;
static uint32_t dest_ip  = 0;

/*
 * Given the rx queue name template above, get the queue name
 */
static inline const char *
get_rx_queue_name(unsigned id)
{
	/* buffer for return value. Size calculated by %u being replaced
	 * by maximum 3 digits (plus an extra byte for safety) */
	static char buffer[sizeof(MP_CLIENT_RXQ_NAME) + 2];

	rte_snprintf(buffer, sizeof(buffer) - 1, MP_CLIENT_RXQ_NAME, id);
	return buffer;
}

/*
 * Given the tx queue name template above, get the queue name
 */
static inline const char *
get_tx_queue_name(unsigned id)
{
	/* buffer for return value. Size calculated by %u being replaced
	 * by maximum 3 digits (plus an extra byte for safety) */
	static char buffer[sizeof(MP_CLIENT_TXQ_NAME) + 2];

	rte_snprintf(buffer, sizeof(buffer) - 1, MP_CLIENT_TXQ_NAME, id);
	return buffer;
}

/*
 * print a usage message
 */
static void
usage(const char *progname)
{
	printf("\nUsage: %s [EAL args] -- -n <client_id> -s <src_ip> -d <dest_ip>\n"
	       "\t\t ** or ** \t\t\n"
	       "Usage: %s [EAL args] -- -n <client_id> --src_ip <src_ip> --dest_ip <dest_ip>\n"
	       "IP addresses should be in hex format, e.g. 0x01010101 (1.1.1.1)\n\n", 
	       progname, progname);
}

/*
 * Convert the client id number from a string to an int.
 */
static int
parse_client_num(const char *client)
{
	char *end = NULL;
	unsigned long temp = 0;

	if (client == NULL || *client == '\0')
		return -1;

	temp = strtoul(client, &end, BASE_10);
	/* If valid string argument is provided, terminating '/0' character
	 * is stored in 'end' */
	if (end == NULL || *end != '\0')
		return -1;

	client_id = (uint8_t)temp;
	return 0;
}

static int 
parse_ip_addr(const char *ip_str, ip_address_t type)
{
	char *end = NULL;
	unsigned long ip_addr = 0;

	ip_addr = strtoul(ip_str, &end, BASE_16);
	/* If valid string argument is provided, terminating '/0' character
	 * is stored in 'end' */
	if (end == NULL || *end != '\0') {
		printf("Invalid address format supplied\n");
		return -1;
	}

	switch(type) {
	case IP_ADDRESS_DEST:
		dest_ip = (uint32_t)ip_addr;
		break;
	case IP_ADDRESS_SRC:
		src_ip = (uint32_t)ip_addr;
		break;
	default:
		printf("Invalid IP address type supplied\n");
		break;
	}

	return 0;	
}

/*
 * Parse the application arguments to the client app.
 */
static int
parse_app_args(int argc, char *argv[])
{
	int option_index = 0, opt = 0;
	char **argvopt = argv;
	const char *progname = NULL;
	static struct option lgopts[] = { 
		{"src_ip",  required_argument, 0, 's'},
		{"dest_ip", required_argument, 0, 'd'},
		{NULL, 0, 0, 0 }
	};
	progname = argv[0];

	while ((opt = getopt_long(argc, argvopt, "n:s:d:", lgopts,
		&option_index)) != EOF){
		switch (opt){
			case 'n':
				if (parse_client_num(optarg) != 0){
					usage(progname);
					return -1;
				}
				break;
			case 's':
				if (parse_ip_addr(optarg, IP_ADDRESS_SRC) != 0) {
					usage(progname);
					return -1;
				}
				break;
			case 'd':
				if (parse_ip_addr(optarg, IP_ADDRESS_DEST) != 0) {
					usage(progname);
					return -1;
				}
				break;
			default:
				usage(progname);
				return -1;
		}
	}

	/* If source or destination IP address command line parameters
	 * not suplpied, then exit. 
	 * */
	if (src_ip == 0 || dest_ip == 0) {
		usage(progname);
		return -1;
	}
	
	return 0;
}

/*
 * For 'num_pkts' in 'pkts', modify the source and destination IP addresses to
 * those specified by the command line parameters supplied to the application.
 */ 
void mangle_ip_addresses(struct rte_mbuf *pkts[], unsigned num_pkts)
{
	struct ipv4_hdr *ipv4_hdr = NULL;
	struct rte_mbuf *m = NULL;
	unsigned i = 0;

	for (i = 0; i < num_pkts; i++) {
		m = pkts[i];
		ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
					sizeof(struct ether_hdr));

		/* Update the source and destination IP address to the values 
		 * distilled from the command line arguments
		 */
		ipv4_hdr->src_addr = rte_cpu_to_be_32(src_ip);
		ipv4_hdr->dst_addr = rte_cpu_to_be_32(dest_ip);
	}

}

/*
 * Application main function - loops through
 * receiving and processing packets. Never returns
 */
int
main(int argc, char *argv[])
{
	struct rte_ring *rx_ring = NULL;
	struct rte_ring *tx_ring = NULL;
	int retval = 0;
	void *pkts[PKT_READ_SIZE];

	if ((retval = rte_eal_init(argc, argv)) < 0)
		return -1;

	argc -= retval;
	argv += retval;

	if (parse_app_args(argc, argv) < 0)
		rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

	rx_ring = rte_ring_lookup(get_rx_queue_name(client_id));
	if (rx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot get RX ring - is server process running?\n");

	tx_ring = rte_ring_lookup(get_tx_queue_name(client_id));
	if (tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot get TX ring - is server process running?\n");

	RTE_LOG(INFO, APP, "Finished Process Init.\n");

	printf("\nClient process %d handling packets\n", client_id);
	printf("[Press Ctrl-C to quit ...]\n");

	for (;;) {
		unsigned rx_pkts = PKT_READ_SIZE;

		/* try dequeuing max possible packets first, if that fails, get the
		 * most we can. Loop body should only execute once, maximum */
		while (rx_pkts > 0 &&
				unlikely(rte_ring_dequeue_bulk(rx_ring, pkts, rx_pkts) != 0))
			rx_pkts = (uint16_t)RTE_MIN(rte_ring_count(rx_ring), PKT_READ_SIZE);

		mangle_ip_addresses((struct rte_mbuf **)pkts, rx_pkts);

		rte_ring_enqueue_bulk(tx_ring, pkts, rx_pkts);
	}
}
