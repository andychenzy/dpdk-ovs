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

#include <string.h>
#include <rte_string_fns.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include "kni.h"
#include <exec-env/rte_kni_common.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include "common.h"
#include "init_drivers.h"
#include "args.h"
#include "init.h"
#include "main.h"

#define MBUFS_PER_CLIENT  3072
#define MBUFS_PER_PORT    3072
#define MBUFS_PER_KNI     3072
#define MBUF_CACHE_SIZE   32
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define RX_MBUF_DATA_SIZE 2048
#define MBUF_SIZE (RX_MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define RTE_MP_RX_DESC_DEFAULT 512
#define RTE_MP_TX_DESC_DEFAULT 512
#define CLIENT_QUEUE_RINGSIZE  256

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
/* Default configuration for rx and tx thresholds etc. */
/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define MP_DEFAULT_PTHRESH 36
#define MP_DEFAULT_RX_HTHRESH 8
#define MP_DEFAULT_TX_HTHRESH 0
#define MP_DEFAULT_WTHRESH 0
#define VPORT_STATS_SIZE sizeof(struct statistics) * MAX_VPORTS

static const struct rte_eth_rxconf rx_conf_default = {
		.rx_thresh = {
				.pthresh = MP_DEFAULT_PTHRESH,
				.hthresh = MP_DEFAULT_RX_HTHRESH,
				.wthresh = MP_DEFAULT_WTHRESH,
		},
};

static const struct rte_eth_txconf tx_conf_default = {
		.tx_thresh = {
				.pthresh = MP_DEFAULT_PTHRESH,
				.hthresh = MP_DEFAULT_TX_HTHRESH,
				.wthresh = MP_DEFAULT_WTHRESH,
		},
		.tx_free_thresh = 0, /* Use PMD default values */
		.tx_rs_thresh = 0, /* Use PMD default values */
};

/* The mbuf pool for packet rx */
struct rte_mempool *pktmbuf_pool;

/* array of info/queues for clients */
struct client *clients = NULL;
struct port_queue *port_queues = NULL;

/* the port details */
struct port_info *ports;

/* the flow table details */
struct flow_table *flow_table;


/**
 * Initialise the mbuf pool for packet reception for the NIC, and any other
 * buffer pools needed by the app - currently none.
 */
static int
init_mbuf_pools(void)
{
	const unsigned num_mbufs = (num_clients * MBUFS_PER_CLIENT) \
			+ (ports->num_ports * MBUFS_PER_PORT) \
			+ (num_kni * MBUFS_PER_KNI);

	/* don't pass single-producer/single-consumer flags to mbuf create as it
	 * seems faster to use a cache instead */
	printf("Creating mbuf pool '%s' [%u mbufs] ...\n",
			PKTMBUF_POOL_NAME, num_mbufs);
	pktmbuf_pool = rte_mempool_create(PKTMBUF_POOL_NAME, num_mbufs,
			MBUF_SIZE, MBUF_CACHE_SIZE,
			sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init,
			NULL, rte_pktmbuf_init, NULL, SOCKET0, NO_FLAGS );

	return (pktmbuf_pool == NULL); /* 0  on success */

}

/**
 * Initialise an individual port:
 * - configure number of rx and tx rings
 * - set up each rx ring, to pull from the main mbuf pool
 * - set up each tx ring
 * - start the port and report its status to stdout
 */
static int
init_port(uint8_t port_num)
{
	/* for port configuration all features are off by default */
	const struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_RSS
		}
	};
	const uint16_t rx_rings = 1, tx_rings = num_clients;
	const uint16_t rx_ring_size = RTE_MP_RX_DESC_DEFAULT;
	const uint16_t tx_ring_size = RTE_MP_TX_DESC_DEFAULT;

	struct rte_eth_link link;
	uint16_t q;
	int retval;

	printf("Port %u init ... ", (unsigned)port_num);
	fflush(stdout);

	/* Standard DPDK port initialisation - config port, then set up
	 * rx and tx rings */
	if ((retval = rte_eth_dev_configure(port_num, rx_rings, tx_rings,
		&port_conf)) != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port_num, q, rx_ring_size,
				SOCKET0, &rx_conf_default, pktmbuf_pool);
		if (retval < 0) return retval;
	}

	for ( q = 0; q < tx_rings; q ++ ) {
		retval = rte_eth_tx_queue_setup(port_num, q, tx_ring_size,
				SOCKET0, &tx_conf_default);
		if (retval < 0) return retval;
	}

	rte_eth_promiscuous_enable(port_num);

	retval  = rte_eth_dev_start(port_num);
	if (retval < 0) return retval;

	printf( "done: ");

	/* get link status */
	rte_eth_link_get(port_num, &link);
	if (link.link_status) {
		printf(" Link Up - speed %u Mbps - %s\n",
		       (uint32_t) link.link_speed,
		       (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
		       ("full-duplex") : ("half-duplex\n"));
	}
	else{
		printf(" Link Down\n");
	}
	return 0;
}

/**
 * Set up the DPDK rings which will be used to pass packets, via
 * pointers, between the multi-process server and client processes.
 * Each client needs one RX queue.
 */
static int
init_shm_rings(void)
{
	unsigned i;
	const unsigned ringsize = CLIENT_QUEUE_RINGSIZE;

	clients = rte_malloc("client details",
		sizeof(*clients) * num_clients, 0);
	if (clients == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate memory for client program details\n");

	port_queues = rte_malloc("port_txq details",
		sizeof(*port_queues) * ports->num_ports, 0);
	if (port_queues == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate memory for port tx_q details\n");

	for (i = 0; i < num_clients; i++) {
		/* Create an RX queue for each client */
		clients[i].rx_q = rte_ring_create(get_rx_queue_name(i),
				ringsize, SOCKET0,
				NO_FLAGS); /* multi producer multi consumer*/
		if (clients[i].rx_q == NULL)
			rte_exit(EXIT_FAILURE, "Cannot create rx ring queue for client %u\n", i);

		clients[i].tx_q = rte_ring_create(get_tx_queue_name(i),
				ringsize, SOCKET0,
				NO_FLAGS); /* multi producer multi consumer*/
		if (clients[i].tx_q == NULL)
			rte_exit(EXIT_FAILURE, "Cannot create tx ring queue for client %u\n", i);
	}

	for (i = 0; i < ports->num_ports; i++) {
		/* Create an RX queue for each ports */
		port_queues[i].tx_q = rte_ring_create(get_port_tx_queue_name(i),
				ringsize, SOCKET0,
				RING_F_SC_DEQ); /* multi producer single consumer*/
		if (port_queues[i].tx_q == NULL)
			rte_exit(EXIT_FAILURE, "Cannot create tx ring queue for port %u\n", i);
	}
	return 0;
}

/**
 * Main init function for the multi-process server app,
 * calls subfunctions to do each stage of the initialisation.
 */
int
init(int argc, char *argv[])
{
	int retval;
	const struct rte_memzone *mz;
	uint8_t i, total_ports;

	/* init EAL, parsing EAL args */
	retval = rte_eal_init(argc, argv);
	if (retval < 0)
		return -1;
	argc -= retval;
	argv += retval;
        if (rte_eal_pci_probe())
                rte_panic("Cannot probe PCI\n");


	/* initialise the nic drivers */
	retval = init_drivers();
	if (retval != 0)
		rte_exit(EXIT_FAILURE, "Cannot initialise drivers\n");

	/* get total number of ports */
	total_ports = rte_eth_dev_count();

	/* set up array for port data */
	mz = rte_memzone_reserve(MZ_PORT_INFO, sizeof(*ports),
				rte_socket_id(), NO_FLAGS);
	if (mz == NULL)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for port information\n");
	memset(mz->addr, 0, sizeof(*ports));
	ports = mz->addr;
	RTE_LOG(INFO, APP, "memzone address is %lx\n", mz->phys_addr);

	/* set up array for statistics */
	mz = rte_memzone_reserve(MZ_STATS_INFO, VPORT_STATS_SIZE, rte_socket_id(), NO_FLAGS);
	if (mz == NULL)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for statistics\n");
	memset(mz->addr, 0, VPORT_STATS_SIZE);
	vport_stats = mz->addr;

	/* set up array for flow table data */
	mz = rte_memzone_reserve(MZ_FLOW_TABLE, sizeof(*flow_table),
				rte_socket_id(), NO_FLAGS);
	if (mz == NULL)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for port information\n");
	memset(mz->addr, 0, sizeof(*flow_table));
	flow_table = mz->addr;

	/* parse additional, application arguments */
	retval = parse_app_args(total_ports, argc, argv);
	if (retval != 0)
		return -1;

	/* initialise mbuf pools */
	retval = init_mbuf_pools();
	if (retval != 0)
		rte_exit(EXIT_FAILURE, "Cannot create needed mbuf pools\n");


	/* now initialise the ports we will use */
	for (i = 0; i < ports->num_ports; i++) {
		retval = init_port(ports->id[i]);
		if (retval != 0)
			rte_exit(EXIT_FAILURE, "Cannot initialise port %u\n",
					(unsigned)i);
	}

	/* initialise the client queues/rings for inter process comms */
	init_shm_rings();

	/* initalise kni queues */
	init_kni();

	return 0;
}

