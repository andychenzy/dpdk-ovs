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
#include <netinet/in.h>
#include <linux/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#include <rte_memzone.h>
#include <rte_string_fns.h>
#include <rte_kni.h>
#include <exec-env/rte_kni_common.h>

#define KNI_FIFO_COUNT_MAX   1024
#define RTE_LOGTYPE_APP      RTE_LOGTYPE_USER1
#define PKTMBUF_POOL_NAME    "MProc_pktmbuf_pool"
#define BASE_10              10
#define BASE_16              16
#define QUEUE_NAME_SIZE      32
#define MBUF_OVERHEAD        (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define RX_MBUF_DATA_SIZE    2048
#define MBUF_SIZE            (RX_MBUF_DATA_SIZE + MBUF_OVERHEAD)

/* This must match the value defined in the ovs_dpdk app */
#define MAX_KNI_PORTS        16

/**
 * KNI context
 */
struct rte_kni {
	char name[IFNAMSIZ];                /**< KNI interface name */
	uint8_t port_id;                    /**< Port id KNI associate with */
	struct rte_mempool *pktmbuf_pool;   /**< pkt mbuf mempool */
	unsigned mbuf_size;                 /**< mbuf size */

	struct rte_kni_fifo *tx_q;          /**< TX queue */
	struct rte_kni_fifo *rx_q;          /**< RX queue */
	struct rte_kni_fifo *alloc_q;       /**< Allocated mbufs queue */
	struct rte_kni_fifo *free_q;        /**< To be freed mbufs queue */

	/* For request & response */
	struct rte_kni_fifo *req_q;         /**< Request queue */
	struct rte_kni_fifo *resp_q;        /**< Response queue */
	void * sync_addr;                   /**< Req/Resp Mem address */

	struct rte_kni_ops ops;             /**< operations for request */
	uint8_t port_in_use : 1;             /**< kni creation flag */
};

static struct rte_kni kni_list[MAX_KNI_PORTS];
/* Mask of enabled ports */
static uint32_t ports_mask = 0;
static volatile int kni_fd = -1;
static phys_addr_t host_hugepage_phys = 0;

/* Function Prototypes */
static int
create_kni_device(uint8_t port_id);
static const struct rte_memzone *
kni_memzone_lookup(const char *queue_string, uint8_t port_id);
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu);
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up);
static uint64_t
convert_host_phys_to_offset(phys_addr_t host_phys);

static struct rte_kni_ops kni_ops = {
	.change_mtu = kni_change_mtu,
	.config_network_if = kni_config_network_interface,
};


/* Called by the driver when the kernel calls the
 * ndo_set_mtu function for the driver.
 */
int
kni_change_mtu(uint8_t __attribute__((unused))port_id,
               unsigned __attribute__((unused))new_mtu)
{
	RTE_LOG(INFO, KNI, "Changing MTU is not supported\n");
	return -EINVAL;
}

/* Called by the driver when the kernel calls the
 * ndo_open function. We return success as we have
 * no real net device to configure.
 */
int
kni_config_network_interface(uint8_t __attribute__((unused))port_id,
                             uint8_t __attribute__((unused))if_up)
{
	return 0;
}

/*
 * print a usage message
 */
static void
usage(const char *progname)
{
	printf("\nUsage: %s [EAL args] -- -p <port_mask>\n", progname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint32_t
parse_unsigned(const char *portmask)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(portmask, &end, BASE_16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return (uint32_t)num;
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
		{NULL, 0, 0, 0 }
	};
	progname = argv[0];

	while ((opt = getopt_long(argc, argvopt, "p:", lgopts,
		&option_index)) != EOF){
		switch (opt){
			case 'p':
				ports_mask = parse_unsigned(optarg);
				break;
			default:
				usage(progname);
				return -1;
		}
	}

	return 0;
}

/* Take the memzone name and attach port_id to perform
 * a lookup.
 */
const struct rte_memzone *
kni_memzone_lookup(const char *queue_string, uint8_t port_id)
{

	const struct rte_memzone *mz = NULL;
	char q_name[QUEUE_NAME_SIZE];

	rte_snprintf(q_name, QUEUE_NAME_SIZE, queue_string, port_id);
	RTE_LOG(INFO, KNI, "Looking for memzone %s\n", q_name);
	mz = rte_memzone_lookup(q_name);
	if (mz == NULL) {
		rte_exit(EXIT_FAILURE, "Memzone lookup of %s failed\n", q_name);
	}
	printf("queue name: %s\n", q_name);
	printf("memzone %s - length: %"PRIu64", hugepage size: %"PRIu64"\n",
			mz->name, mz->len, mz->hugepage_sz);
	return mz;

}

/* Find the offset of the memzone from the start
 * of the hugepage
 */
uint64_t
convert_host_phys_to_offset(phys_addr_t host_phys)
{

	uint64_t offset = 0;

	/* Because we only use one hugepage, we can assume that
	 * the address of host_phys will be greater than the
	 * address of the hugepage
	 */
	offset = host_phys - host_hugepage_phys;
	RTE_LOG(INFO, KNI,
	        "%lx host_phys, %lx host_hugepage_phys\n", host_phys, host_hugepage_phys);
	RTE_LOG(INFO, KNI, "offset is %lu\n", offset);

	return(offset);

}


/* Fill the dev_info struct and call the ioctl so the
 * kni device is created
 */
int
create_kni_device(uint8_t port_id)
{
	const struct rte_memzone *mz = NULL;
	struct rte_kni_device_info dev_info;
	struct rte_mempool *mempool = NULL;
	char mz_name[QUEUE_NAME_SIZE];

	if (kni_list[port_id].port_in_use != 0) {
		RTE_LOG(ERR, KNI, "Port %d has been used\n", port_id);
		return -1;
	}
	/* Check FD and open once */
	if (kni_fd < 0) {
		kni_fd = open("/dev/" KNI_DEVICE, O_RDWR);
		if (kni_fd < 0) {
			RTE_LOG(ERR, KNI, "Can not open /dev/%s\n",
							KNI_DEVICE);
			return -1;
		}
	}

	dev_info.port_id   = port_id;

	rte_snprintf(dev_info.name, IFNAMSIZ, "vEth%u", port_id);

	/* We store the guest virtual address in our kni structure and
	 * write the physical address offset into the dev struct to
	 * be sent to the driver
	 */
	mz = kni_memzone_lookup("kni_port_%u_rx", port_id);
	kni_list[port_id].rx_q = mz->addr;
	dev_info.rx_phys = convert_host_phys_to_offset(mz->phys_addr);

	mz = kni_memzone_lookup("kni_port_%u_tx", port_id);
	kni_list[port_id].tx_q = mz->addr;
	dev_info.tx_phys = convert_host_phys_to_offset(mz->phys_addr);

	mz = kni_memzone_lookup("kni_port_%u_alloc", port_id);
	kni_list[port_id].alloc_q = mz->addr;
	dev_info.alloc_phys = convert_host_phys_to_offset(mz->phys_addr);

	mz = kni_memzone_lookup("kni_port_%u_free", port_id);
	kni_list[port_id].free_q = mz->addr;
	dev_info.free_phys = convert_host_phys_to_offset(mz->phys_addr);

	mz = kni_memzone_lookup("kni_port_%u_req", port_id);
	kni_list[port_id].req_q = mz->addr;
	dev_info.req_phys = convert_host_phys_to_offset(mz->phys_addr);

	mz = kni_memzone_lookup("kni_port_%u_resp", port_id);
	kni_list[port_id].resp_q = mz->addr;
	dev_info.resp_phys = convert_host_phys_to_offset(mz->phys_addr);

	mz = kni_memzone_lookup("kni_port_%u_sync", port_id);
	kni_list[port_id].sync_addr = mz->addr;
	dev_info.sync_va = mz->addr;
	dev_info.sync_phys = convert_host_phys_to_offset(mz->phys_addr);

	mempool = rte_mempool_lookup("MProc_pktmbuf_pool");
	rte_snprintf(mz_name, sizeof(mz_name), "MP_%s", mempool->name);
	mz = rte_memzone_lookup(mz_name);
	if (mz == NULL) {
		rte_exit(EXIT_FAILURE, "Memzone lookup of %s failed\n", mz_name);
	}
	dev_info.mbuf_va = mz->addr;
	dev_info.mbuf_phys = convert_host_phys_to_offset(mz->phys_addr);

	kni_list[port_id].mbuf_size = MBUF_SIZE;
	/* Configure the buffer size which will be checked in kernel module */
	dev_info.mbuf_size = kni_list[port_id].mbuf_size;

	memcpy(&kni_list[port_id].ops, &kni_ops, sizeof(struct rte_kni_ops));

	ioctl(kni_fd, RTE_KNI_IOCTL_CREATE, &dev_info);
	kni_list[port_id].port_in_use = 1;
	return 0;
}


/*
 * Application main function - loops through
 * receiving and processing packets. Never returns
 */
int
main(int argc, char *argv[])
{
	int retval = 0;
	uint8_t port = 0;
	const struct rte_memseg *layout = NULL;


	if ((retval = rte_eal_init(argc, argv)) < 0) {
		RTE_LOG(INFO, APP, "EAL init failed.\n");
		return -1;
	}

	layout = rte_eal_get_physmem_layout();
	/* We assume only one hugepage */
	host_hugepage_phys = (layout[0].phys_addr);
	RTE_LOG(INFO, KNI, "Host hugepage phys is %lx\n", host_hugepage_phys);

	argc -= retval;
	argv += retval;
	if (parse_app_args(argc, argv) < 0)
		rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

	memset(kni_list, 0, sizeof(struct rte_kni) * MAX_KNI_PORTS);

	/* Initialise the devices for each port*/
	for (port = 0; port < MAX_KNI_PORTS; port++) {
		/* Skip ports that are not enabled */
		if ((ports_mask & (1 << port)) == 0) {
			RTE_LOG(INFO, KNI, "skipping port %d\n", port);
			continue;
		}
		RTE_LOG(INFO, KNI, "Attaching queues for port %d\n", port);
		create_kni_device(port);
		RTE_LOG(INFO, APP, "Finished Process Init.\n");
		RTE_LOG(INFO, APP, "KNI queues ready.\n");
		printf("[Press Ctrl-C to quit ...]\n");
	}

	for (;;) {
		for (port = 0; port < MAX_KNI_PORTS; port++) {
			if ((ports_mask & (1 << port)) != 0) {
				/* Sleep to reduce processor load. As long as we respond
				 * before rtnetlink times out we will still be able to ifup
				 * and change mtu
				 */
				sleep(2);
				rte_kni_handle_request(&kni_list[port]);
			}
		}
	}

	return 0;
}

