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

#include <rte_ethdev.h>
#include <rte_byteorder.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_fbk_hash.h>
#include <rte_string_fns.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cpuflags.h>
#include <rte_kni.h>
#include <rte_ip.h>

#include "kni.h"
#include "common.h"
#include "args.h"
#include "init.h"
#include "main.h"

/*
 * When reading/writing to/from rings/ports use this batch size
 */
#define PKT_BURST_SIZE      32
#define RX_RING_SIZE        128
#define TX_RING_SIZE        512
#define SOCKET0             0
#define PREFETCH_OFFSET     3
#define RING_SIZE           (PKT_BURST_SIZE * 8)
#define VLAN_ID_MASK        0xFFF
#define VLAN_PRIO_SHIFT     13
#define PORT0               0x10
#define PORT1               0x11
#define VSWITCHD            0x0
#define CLIENT1             0x1
#define CLIENT2             0x2
#define KNI0               0x20
#define KNI1               0x21
#define KNI2               0x22
#define NUM_BYTES_MAC_ADDR  6
#define MAC_ADDR_STR_INT_L  3
#define NEWLINE_CHAR_OFFSET 1
#define HASH_NAME           "hash1"
#define HASH_BUCKETS        4
#define BYTES_TO_PRINT      256
#define PORT_MASK           0x0F
#define KNI_MASK            0x1F
#define CLIENT_MASK         0xFF
#define IS_PORT_ACTION(action) ((action) > PORT_MASK && (action) <= KNI_MASK)
#define IS_KNI_ACTION(action)  ((action) > KNI_MASK)
#define KNI_MAX_PORTID    KNI0 + (MAX_KNI_PORTS - 1)

/* Parameters used for hash table in unit test functions. Name set later. */
static struct rte_hash_parameters ut_params = {
	.name               = HASH_NAME,
	.entries            = MAX_FLOWS,
	.bucket_entries     = HASH_BUCKETS,
	.key_len            = sizeof(struct flow_key), /* 13 */
	.hash_func          = rte_hash_crc,
	.hash_func_init_val = 0,
	.socket_id          = SOCKET0,
};
extern struct cfg_params *cfg_params;
/* One buffer per client rx queue - dynamically allocate array */
static struct rte_hash *handle = NULL;
static int switch_rx_drop = 0;
static int switch_tx_drop = 0;
/* When > 0, indicates that a ring's high water mark has been
 * reached or exceeded */
static int overruns = 0;
extern uint16_t nb_cfg_params;

static void send_to_client(uint8_t client, struct rte_mbuf *buf);
static void send_to_port(uint8_t vportid, struct rte_mbuf *buf);
static void receive_from_client(uint16_t client);
static void receive_from_port(unsigned vportid);
static void send_to_kni(uint8_t vportid, struct rte_mbuf *buf);
static void receive_from_kni(uint8_t vportid);
void send_to_vswitchd(struct rte_mbuf *mbuf);
static void receive_from_vswitchd(void);
static void flush_pkts(unsigned);

static void flow_init(void);
static void flow_action(int pos0, struct rte_mbuf *pkt);
static int flow_lookup(struct rte_mbuf *pkt, uint8_t in_port);
static int switch_packet(struct rte_mbuf *pkt, uint8_t in_port);
static void print_flow_key(volatile struct flow_key *key);
static void print_flow_table_info(int pos);
static void inline write_flow_table_info(int pos, struct flow_key key);
struct statistics *vport_stats;

void *ofpbuf_at(char *b, size_t offset, size_t size);

void *
ofpbuf_at(char *b, size_t offset, size_t size)
{
	return offset + size <= size ? (char *) b + offset : NULL;
}

/*
 * Returns MAC address for port in a string
 */
static const char *
get_printable_mac_addr(uint8_t port)
{
	static const char err_address[] = "00:00:00:00:00:00";
	static char addresses[RTE_MAX_ETHPORTS][sizeof(err_address)] = {0};
	struct ether_addr mac = {0};
	int ether_addr_len = sizeof(err_address) - NEWLINE_CHAR_OFFSET;
	int i = 0;
	int j = 0;

	if (unlikely(port >= RTE_MAX_ETHPORTS))
		return err_address;

	/* first time run for this port so we populate addresses */
	if (unlikely(addresses[port][0] == '\0')) {
		rte_eth_macaddr_get(port, &mac);
		while(j < NUM_BYTES_MAC_ADDR){
			rte_snprintf(&addresses[port][0] + i,
			             MAC_ADDR_STR_INT_L + NEWLINE_CHAR_OFFSET,
			             "%02x:",
			             mac.addr_bytes[j]);
			i += MAC_ADDR_STR_INT_L;
			j++;
		}
		/* Overwrite last ":" and null terminate the string */
		addresses[port][ether_addr_len] = '\0';
	}
	return addresses[port];
}

/*
 * This function displays the recorded statistics for each port
 * and for each client. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(void)
{
	unsigned i = 0;
	unsigned j = 0;
	/* ANSI escape sequences for terminal display.
	 * 27 = ESC, 2J = Clear screen */
	const char clr[] = {27, '[', '2', 'J', '\0'};
	/* H = Home position for cursor*/
	const char topLeft[] = {27, '[', '1', ';', '1', 'H','\0'};

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("Physical Ports\n");
	printf("-----\n");
	for (i = 0; i < ports->num_ports; i++)
		printf("Port %u: '%s'\t", ports->id[i],
				get_printable_mac_addr(ports->id[i]));
	printf("\n\n");

	printf("\nVport Statistics\n"
		     "============   ============  ============  ============  ============\n"
		     "Interface      rx_packets    rx_dropped    tx_packets    tx_dropped  \n"
		     "------------   ------------  ------------  ------------  ------------\n");
	for (i = 0; i < MAX_VPORTS; i++) {
		const volatile struct statistics vstats = vport_stats[i];
		if (i == 0) {
			printf("vswitchd   ");
		}
		else if (i <= PORT_MASK) {
			printf("Client   %2u", i);
		}
		else if (i <= KNI_MASK) {
			printf("Port     %2u", i & PORT_MASK);
		}
		else {
			printf("KNI Port %2u", i & KNI_MASK);
		}
		printf("%13llu %13llu %13"PRIu64" %13"PRIu64"\n",
					vstats.rx,
					vstats.rx_drop,
					vstats.tx,
					vstats.tx_drop);
	}
	printf("============   ============  ============  ============  ============\n");

	printf("\n Switch rx dropped %d\n", switch_rx_drop);
	printf("\n Switch tx dropped %d\n", switch_tx_drop);
	printf("\n Queue overruns   %d\n",  overruns);
	printf("\n Mempool count    %9llu\n", rte_mempool_count(pktmbuf_pool));
	printf("\n");
}

/*
 * Function to set all the client statistic values to zero.
 * Called at program startup.
 */
static void
clear_stats(void)
{
	unsigned i = 0;

	for (i = 0; i < MAX_VPORTS; i++) {
		vport_stats[i].rx = 0;
		vport_stats[i].rx_drop = 0;
		vport_stats[i].tx = 0;
		vport_stats[i].tx_drop = 0;
	}
}

/*
 * Enqueue a single packet to a client rx ring
 */
static void
send_to_client(uint8_t client, struct rte_mbuf *buf)
{
	struct client *cl = NULL;
	int rslt = 0;
	struct statistics *s = NULL;

	cl = &clients[client];
	s = &vport_stats[client];

	rslt = rte_ring_sp_enqueue(cl->rx_q, (void *)buf);
	if (rslt < 0) {
		if (rslt == -ENOBUFS) {
			rte_pktmbuf_free(buf);
			switch_tx_drop++;
			s->rx_drop++;
		}
		else {
			overruns++;
			s->rx++;
		}
	}
	else {
		s->rx++;
	}
}

/*
 * Enqueue single packet to a port
 */
static void
send_to_port(uint8_t vportid, struct rte_mbuf *buf)
{
	struct port_queue *pq = &port_queues[vportid & PORT_MASK];

	if (rte_ring_mp_enqueue(pq->tx_q, (void *)buf) < 0) {
		rte_pktmbuf_free(buf);
	}
}

static void
send_to_kni(uint8_t vportid, struct rte_mbuf *buf)
{
	int i = 0;
	int rslt = 0;
	struct kni_port *kp = NULL;
	struct statistics *s = NULL;

	s = &vport_stats[vportid];

	rslt = rte_kni_tx_burst(&rte_kni_list[vportid & KNI_MASK], &buf, 1);
	/* FIFO is full */
	if (rslt == 0) {
		rte_pktmbuf_free(buf);
		s->rx_drop++;
		switch_tx_drop++;
	}
	else {
		s->rx++;
	}
}

static void
receive_from_kni(uint8_t vportid)
{
	int i = 0;
	int rslt = 0;
	int pos0 = 0;
	struct rte_mbuf *buf[PKT_BURST_SIZE] = {0};
	struct statistics *s = NULL;

	s = &vport_stats[vportid];

	rslt = rte_kni_rx_burst(&rte_kni_list[vportid & KNI_MASK], buf, PKT_BURST_SIZE);

	if (rslt != 0) {
		s->tx += rslt;
		for (i = 0; i < rslt; i++) {
			pos0 = switch_packet(buf[i], vportid);
			if (pos0 < 0) {
				s->tx_drop++;
			}
		}
	}
}

/*
 * Receive burst of packets from client
 */
static void
receive_from_client(uint16_t client)
{
	int j = 0;
	int pos0 = 0;
	uint16_t dq_pkt = PKT_BURST_SIZE;
	struct client *cl = &clients[client];
	struct rte_mbuf *buf[PKT_BURST_SIZE] = {0};
	struct statistics *s = NULL;

	s = &vport_stats[client];

	/* Attempt to dequeue maximum available number of mbufs from ring */
	while (dq_pkt > 0 &&
			unlikely(rte_ring_sc_dequeue_bulk(
					cl->tx_q, (void **)buf, dq_pkt) != 0))
		dq_pkt = (uint16_t)RTE_MIN(
				rte_ring_count(cl->tx_q), PKT_BURST_SIZE);

	/* update number of packets transmitted by client */
	s->tx += dq_pkt;

	for (j = 0; j < dq_pkt; j++) {
		pos0 = switch_packet(buf[j], client);
		if (pos0 < 0) {
			s->tx_drop++;
		}
	}
}


/*
 * Receive burst of packets from physical port.
 */
static void
receive_from_port(unsigned vportid)
{
	int j = 0;
	uint16_t rx_count = 0;
	struct rte_mbuf *buf[PKT_BURST_SIZE] = {0};
	/* read a port */
	rx_count = rte_eth_rx_burst(vportid & PORT_MASK, 0, \
			buf, PKT_BURST_SIZE);
	/* Now process the NIC packets read */
	if (likely(rx_count > 0))
	{
		vport_stats[vportid].rx += rx_count;
		/* Prefetch first packets */
		for (j = 0; j < PREFETCH_OFFSET && j < rx_count; j++) {
			rte_prefetch0(rte_pktmbuf_mtod(buf[j], void *));
		}

		/* Prefetch and forward already prefetched packets */
		for (j = 0; j < (rx_count - PREFETCH_OFFSET); j++) {
			rte_prefetch0(rte_pktmbuf_mtod(buf[
						j + PREFETCH_OFFSET], void *));
			switch_packet(buf[j], vportid);
		}

		/* Forward remaining prefetched packets */
		for (; j < rx_count; j++) {
			switch_packet(buf[j], vportid);
		}
	}
}

void
send_to_vswitchd(struct rte_mbuf *mbuf)
{
	int rslt = 0;
	struct statistics *s = NULL;
	struct client *cl = NULL;

	cl = &clients[VSWITCHD];
	rte_pktmbuf_data_len(mbuf) = rte_pktmbuf_pkt_len(mbuf);

	s = &vport_stats[VSWITCHD];
	rslt = rte_ring_sp_enqueue(cl->rx_q, mbuf);
	if (rslt < 0) {
		if (rslt == -ENOBUFS) {
			rte_pktmbuf_free(mbuf);
			switch_tx_drop++;
			s->rx_drop++;
		}
		else {
			overruns++;
		}
	}
	s->tx++;
}

/* receive packet form vswitchd */
static void
receive_from_vswitchd(void)
{
	int j = 0;
	struct rte_mbuf *buf = NULL;
	struct client *cl = NULL;

	cl = &clients[VSWITCHD];

	/* Read packet(s) from ring share mem */
	if (!(rte_ring_sc_dequeue(cl->tx_q, (void**)&buf) < 0)) {
		rte_pktmbuf_dump(buf, BYTES_TO_PRINT);
		/* TODO send to vswitchd here */
	}
}

/*
 * Flush packets scheduled for transmit on ports
 */
static void
flush_pkts(unsigned action)
{
	unsigned i = 0;
	uint16_t deq_count = PKT_BURST_SIZE;
	struct rte_mbuf *pkts[PKT_BURST_SIZE] =  {0};
	struct port_queue *pq =  &port_queues[action & PORT_MASK];
	struct statistics *s = &vport_stats[action];

	if (unlikely(rte_ring_count(pq->tx_q) >= PKT_BURST_SIZE))
	{
		if (unlikely(rte_ring_dequeue_bulk(
			              pq->tx_q, (void **)pkts, PKT_BURST_SIZE) != 0))
			return;

		const uint16_t sent = rte_eth_tx_burst(
			                 action & PORT_MASK, 0, pkts, PKT_BURST_SIZE);
		if (unlikely(sent < PKT_BURST_SIZE))
		{
			for (i = sent; i < PKT_BURST_SIZE; i++)
				rte_pktmbuf_free(pkts[i]);
			s->tx_drop += (PKT_BURST_SIZE - sent);
		}
		else
		{
			s->tx += sent;
		}
	}
	else
	{
		return;
	}
}

/*
 * This function takes a packet and routes it as per the flow table.
 */
static int
switch_packet(struct rte_mbuf *pkt, uint8_t in_port)
{
	int pos0 = 0;

	pos0 = flow_lookup(pkt, in_port);
	if (pos0 < 0)
		rte_pktmbuf_free(pkt);
	else
		flow_action(pos0, pkt);

	return pos0;
}

/* Default flows initialize */
static void
flow_init(void)
{
	int pos = 0;
	struct flow_key key = {0};

	/* Check if hardware-accelerated hashing supported */
	if (ut_params.hash_func == rte_hash_crc &&
			!rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE4_2)) {
		RTE_LOG(WARNING, HASH, "CRC32 instruction requires SSE4.2, "
				               "which is not supported on this system. "
				               "Falling back to software hash.\n");
		ut_params.hash_func = rte_jhash;
	}

	handle = rte_hash_create(&ut_params);
	if (handle == NULL) {
		printf("Failed to create hash table\n");
		exit(EXIT_FAILURE);
	}

	/* Forward from Port 1 to Port 0 */
	key.in_port = PORT1;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(1,1,1,2);
	key.ip_dst = IPv4(1,1,1,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", PORT1, PORT0, pos);
		flow_table->dst_port[pos] = PORT0;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Port 0 to Port 1 */
	key.in_port = PORT0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(1,1,1,1);
	key.ip_dst = IPv4(1,1,1,2);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", PORT0, PORT1, pos);
		flow_table->dst_port[pos] = PORT1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Client 2 to Client 1 */
	key.in_port = CLIENT2;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(2,2,2,2);
	key.ip_dst = IPv4(2,2,2,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", CLIENT2, CLIENT1, pos);
		flow_table->dst_port[pos] = CLIENT1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Client 1 to Client 2 */
	key.in_port = CLIENT1;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(2,2,2,1);
	key.ip_dst = IPv4(2,2,2,2);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", CLIENT1, CLIENT2, pos);
		flow_table->dst_port[pos] = CLIENT2;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Port 0 to Client 1 */
	key.in_port = PORT0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(1,1,1,1);
	key.ip_dst = IPv4(2,2,2,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", PORT0, CLIENT1, pos);
		flow_table->dst_port[pos] = CLIENT1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Client 2 to Port 1*/
	key.in_port = CLIENT2;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(2,2,2,2);
	key.ip_dst = IPv4(1,1,1,2);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", CLIENT2, PORT1, pos);
		flow_table->dst_port[pos] = PORT1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Client 1 to Port 1*/
	key.in_port = CLIENT1;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(2,2,2,1);
	key.ip_dst = IPv4(1,1,1,2);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", CLIENT1, PORT1, pos);
		flow_table->dst_port[pos] = PORT1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Physical Port 0 to KNI Port 0 */
	key.in_port = PORT0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(1,1,1,1);
	key.ip_dst = IPv4(3,3,3,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", PORT0, KNI0, pos);
		flow_table->dst_port[pos] = KNI0;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from KNI Port 0 to Physical Port 0 */
	key.in_port = KNI0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(3,3,3,1);
	key.ip_dst = IPv4(1,1,1,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", KNI0, PORT0, pos);
		flow_table->dst_port[pos] = PORT0;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from KNI Port 0 to Physical Port 1 */
	key.in_port = KNI0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(3,3,3,1);
	key.ip_dst = IPv4(1,1,1,2);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", KNI0, PORT1, pos);
		flow_table->dst_port[pos] = PORT1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from Physical Port 0 to KNI Port 1 */
	key.in_port = PORT0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(1,1,1,1);
	key.ip_dst = IPv4(3,3,3,2);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", PORT0, KNI1, pos);
		flow_table->dst_port[pos] = KNI1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from KNI Port 1 to Physical Port 0 */
	key.in_port = KNI1;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(3,3,3,2);
	key.ip_dst = IPv4(1,1,1,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", KNI1, PORT0, pos);
		flow_table->dst_port[pos] = PORT0;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from KNI Port 0 to KNI Port 1 */
	key.in_port = KNI0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(3,3,3,1);
	key.ip_dst = IPv4(3,3,3,2);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", KNI0, KNI1, pos);
		flow_table->dst_port[pos] = KNI1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from KNI Port 1 to KNI Port 0 */
	key.in_port = KNI1;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(3,3,3,2);
	key.ip_dst = IPv4(3,3,3,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", KNI1, KNI0, pos);
		flow_table->dst_port[pos] = KNI0;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}

	/* Forward from KNI Port 0 to Client 1 */
	key.in_port = KNI0;
	memset(key.ether_dst.addr_bytes, 0, ETHER_ADDR_LEN);
	memset(key.ether_src.addr_bytes, 0, ETHER_ADDR_LEN);
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_src = IPv4(3,3,3,1);
	key.ip_dst = IPv4(2,2,2,1);
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	pos = rte_hash_add_key(handle, &key);
	if (pos >= 0) {
		printf("\nHash 0x%x to 0x%x is %d\n", KNI0, CLIENT1, pos);
		flow_table->dst_port[pos] = CLIENT1;
		write_flow_table_info(pos, key);
		print_flow_table_info(pos);
	}
}

/*
 * Send to client or port depending on action in flow table
 */
static void
flow_action(int pos0, struct rte_mbuf *pkt)
{
	uint8_t action = flow_table->dst_port[pos0];

	/* Physical port action*/
	if (IS_PORT_ACTION(action)) {
		send_to_port(action, pkt);
	}
	/* KNI FIFO action */
	else if (IS_KNI_ACTION(action)) {
		send_to_kni(action, pkt);
	}
	/* Client ring action*/
	else {
		send_to_client(action, pkt);
	}
}

/*
 * Extract 12 tuple from pkt as key, and look up flow table for position
 */
static int
flow_lookup(struct rte_mbuf *pkt, uint8_t in_port)
{
	int hash_pos = 0;
	struct flow_key key = {0};
	struct ipv4_hdr *ipv4_hdr = NULL;
	struct tcp_hdr *tcp = NULL;
	struct udp_hdr *udp = NULL;
	unsigned char *pkt_data = NULL;
	struct ether_hdr *ether_hdr = NULL;
	uint16_t next_proto = 0;
	struct vlan_hdr *vlan_hdr = NULL;
	uint16_t vlan_tci = 0;

	key.in_port = in_port;

	/* Assume ethernet packet and get packet data */
	pkt_data = rte_pktmbuf_mtod(pkt, unsigned char *);
	ether_hdr = (struct ether_hdr *) pkt_data;
	pkt_data += sizeof(struct ether_hdr);


	key.ether_dst = ether_hdr->d_addr;
	key.ether_src = ether_hdr->s_addr;
	key.ether_type = rte_be_to_cpu_16(ether_hdr->ether_type);

	next_proto = key.ether_type;
	if (next_proto == ETHER_TYPE_VLAN) {
		vlan_hdr = (struct vlan_hdr *)pkt_data;
		pkt_data += sizeof(struct vlan_hdr);

		vlan_tci = rte_be_to_cpu_16(vlan_hdr->vlan_tci);
		key.vlan_id = vlan_tci & VLAN_ID_MASK;
		key.vlan_prio = vlan_tci >> VLAN_PRIO_SHIFT;

		next_proto = rte_be_to_cpu_16(vlan_hdr->eth_proto);
	}

	if (next_proto == ETHER_TYPE_IPv4) {
		ipv4_hdr = (struct ipv4_hdr *)pkt_data;
		pkt_data += sizeof(struct ipv4_hdr);

		key.ip_dst = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		key.ip_src = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		key.ip_proto = ipv4_hdr->next_proto_id;
		key.ip_tos = ipv4_hdr->type_of_service;

		next_proto = ipv4_hdr->next_proto_id;
	}

	switch (next_proto) {
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *)pkt_data;
			pkt_data += sizeof(struct tcp_hdr);

			key.tran_dst_port = rte_be_to_cpu_16(tcp->dst_port);
			key.tran_src_port = rte_be_to_cpu_16(tcp->src_port);
			break;
		case IPPROTO_UDP:
			udp = (struct udp_hdr *)pkt_data;
			pkt_data += sizeof(struct udp_hdr);

			key.tran_dst_port = rte_be_to_cpu_16(udp->dst_port);
			key.tran_src_port = rte_be_to_cpu_16(udp->src_port);
			break;
		default:
			key.tran_dst_port = 0;
			key.tran_src_port = 0;
	}


	/* We parse out the fields in order to replicate the performance hit it
	 * takes to do so, but do not actually use the fields */
	//key.in_port = 0;
	memset(&key.ether_dst, 0, sizeof(key.ether_dst));
	memset(&key.ether_src, 0, sizeof(key.ether_dst));
	key.ether_type = 0;
	key.vlan_id = 0;
	key.vlan_prio = 0;
	key.ip_proto = 0;
	key.ip_tos = 0;
	key.tran_src_port = 0;
	key.tran_dst_port = 0;

	hash_pos = rte_hash_lookup(handle, &key);

	return hash_pos;
}

static void
print_flow_key(volatile struct flow_key *key)
{
	int i = 0;
	printf("key.in_port = %x\n", key->in_port);
	printf("key.ether_dst = ");
	for (i = 0; i < NUM_BYTES_MAC_ADDR; i++) {
		printf("%hhx", key->ether_dst.addr_bytes[i]);
	}
	printf("\n");
	printf("key.ether_src = ");
	for (i = 0; i < NUM_BYTES_MAC_ADDR; i++) {
		printf("%hhx", key->ether_src.addr_bytes[i]);
	}
	printf("\n");
	printf("key.ether_type = %hx\n", key->ether_type);
	printf("key.vlan_id = %hx\n", key->vlan_id);
	printf("key.vlan_prio = %hhx\n", key->vlan_prio);
	printf("key.ip_src = %x\n", key->ip_src);
	printf("key.ip_dst = %x\n", key->ip_dst);
	printf("key.ip_proto = %hhx\n", key->ip_proto);
	printf("key.ip_tos  = %hhx\n", key->ip_tos);
	printf("key.tran_src_port  = %hx\n", key->tran_src_port);
	printf("key.tran_dst_port  = %hx\n", key->tran_dst_port);
}

/* print flow table key at position pos*/
static void
print_flow_table_info(int pos)
{
	printf("APP: flow_table->key[%d]\n", pos);
	print_flow_key(&flow_table->key[pos]);
}

/* assigning key to flow table*/
static void inline
write_flow_table_info(int pos, struct flow_key key)
{
	flow_table->key[pos] = key;
}

/* Main function used by the processing threads.
 * Prints out some configuration details for the thread and then begins
 * performing packet RX and TX.
 */
static int
lcore_main(void *arg __rte_unused)
{
	unsigned i = 0;
	unsigned j = 0;
	unsigned vportid = 0;
	unsigned client = CLIENT1;
	unsigned kni_vportid = KNI0;
	const unsigned id = rte_lcore_id();

	/* vswitchd core is used for print_stat and receive_from_vswitchd */
	if (id == vswitchd_core) {
		RTE_LOG(INFO, APP, "Print stat core is %d.\n", id);
		while (sleep(stats) <= stats) {
			if (stats > 0)
				do_stats_display();

			/* handle any packets from vswitchd */
			receive_from_vswitchd();
		}
	}
	/* client_switching_core is used process packets from client rings
	 * or fifos
	 */
	if (id == client_switching_core) {
		RTE_LOG(INFO, APP, "Client switching core is %d.\n", id);
		for (;;) {
			receive_from_client(client);
			/* move to next client and dont handle client 0*/
			if (++client == num_clients){
				client = 1;
			}
			receive_from_kni(kni_vportid);
			/* move to next kni port */
			if (++kni_vportid == KNI0 + num_kni) {
				kni_vportid = KNI0;
			}
		}
	}
	for (i = 0; i < nb_cfg_params; i++) {
		if (id == cfg_params[i].lcore_id) {
			RTE_LOG(INFO, APP, "Port core is %d.\n", id);
			vportid = cfg_params[i].port_id;
			for (;;) {
				receive_from_port(vportid);
				flush_pkts(vportid);
			}
		}
	}

	return 0;
}

int
MAIN(int argc, char *argv[])
{
	unsigned i = 0;

	if (init(argc, argv) < 0 ) {
		RTE_LOG(INFO, APP, "Process init failed.\n");
		return -1;
	}
	RTE_LOG(INFO, APP, "Finished Process Init.\n");

	clear_stats();
	flow_init();

	for (i = 0; i < nb_cfg_params; i++) {
		RTE_LOG(INFO, APP, "config = %d,%d,%d\n",
		                cfg_params[i].port_id,
		                cfg_params[i].queue_id,
		                cfg_params[i].lcore_id);
	}
	RTE_LOG(INFO, APP, "nb_cfg_params = %d\n", nb_cfg_params);


	rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}
	return 0;
}
