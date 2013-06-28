#include <rte_string_fns.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "common.h"
#include "init_drivers.h"
#include "args.h"
#include "init.h"
#include "main.h"
#include "kni.h"

#define OBJNAMSIZ 32

static void
kni_fifo_init(struct rte_kni_fifo *fifo, unsigned size);
static int
create_kni_fifos(uint8_t kni_port_id);

/**
 * Create memzones and fifos for a KNI port.
 */
static int
create_kni_fifos(uint8_t kni_port_id)
{
	const struct rte_memzone *mz = NULL;
	char obj_name[OBJNAMSIZ];
	rte_kni_list[kni_port_id].pktmbuf_pool = pktmbuf_pool;

	if(kni_port_id >= MAX_KNI_PORTS) {
		RTE_LOG(ERR, APP, "Port id %u greater than MAX_KNI_PORTS %u",
		        kni_port_id, MAX_KNI_PORTS);
		return -EINVAL;
	}

	/* TX RING */
	rte_snprintf(obj_name, OBJNAMSIZ, "kni_port_%u_tx", kni_port_id);
	mz = rte_memzone_reserve(obj_name, KNI_FIFO_SIZE, SOCKET_ID_ANY, 0);
	FAIL_ON_MEMZONE_NULL(mz);
	rte_kni_list[kni_port_id].tx_q = mz->addr;
	kni_fifo_init(rte_kni_list[kni_port_id].tx_q, KNI_FIFO_COUNT_MAX);

	/* RX RING */
	rte_snprintf(obj_name, OBJNAMSIZ, "kni_port_%u_rx", kni_port_id);
	mz = rte_memzone_reserve(obj_name, KNI_FIFO_SIZE, SOCKET_ID_ANY, 0);
	FAIL_ON_MEMZONE_NULL(mz);
	rte_kni_list[kni_port_id].rx_q = mz->addr;
	kni_fifo_init(rte_kni_list[kni_port_id].rx_q, KNI_FIFO_COUNT_MAX);

	/* ALLOC RING */
	rte_snprintf(obj_name, OBJNAMSIZ, "kni_port_%u_alloc", kni_port_id);
	mz = rte_memzone_reserve(obj_name, KNI_FIFO_SIZE, SOCKET_ID_ANY, 0);
	FAIL_ON_MEMZONE_NULL(mz);
	rte_kni_list[kni_port_id].alloc_q = mz->addr;
	kni_fifo_init(rte_kni_list[kni_port_id].alloc_q, KNI_FIFO_COUNT_MAX);

	/* FREE RING */
	rte_snprintf(obj_name, OBJNAMSIZ, "kni_port_%u_free", kni_port_id);
	mz = rte_memzone_reserve(obj_name, KNI_FIFO_SIZE, SOCKET_ID_ANY, 0);
	FAIL_ON_MEMZONE_NULL(mz);
	rte_kni_list[kni_port_id].free_q = mz->addr;
	kni_fifo_init(rte_kni_list[kni_port_id].free_q, KNI_FIFO_COUNT_MAX);

	/* Request RING */
	rte_snprintf(obj_name, OBJNAMSIZ, "kni_port_%d_req", kni_port_id);
	mz = rte_memzone_reserve(obj_name, KNI_FIFO_SIZE, SOCKET_ID_ANY, 0);
	FAIL_ON_MEMZONE_NULL(mz);
	rte_kni_list[kni_port_id].req_q = mz->addr;
	kni_fifo_init(rte_kni_list[kni_port_id].req_q, KNI_FIFO_COUNT_MAX);

	/* Response RING */
	rte_snprintf(obj_name, OBJNAMSIZ, "kni_port_%d_resp", kni_port_id);
	mz = rte_memzone_reserve(obj_name, KNI_FIFO_SIZE, SOCKET_ID_ANY, 0);
	FAIL_ON_MEMZONE_NULL(mz);
	rte_kni_list[kni_port_id].resp_q = mz->addr;
	kni_fifo_init(rte_kni_list[kni_port_id].resp_q, KNI_FIFO_COUNT_MAX);

	/* Req/Resp sync mem area */
	rte_snprintf(obj_name, OBJNAMSIZ, "kni_port_%d_sync", kni_port_id);
	mz = rte_memzone_reserve(obj_name, KNI_FIFO_SIZE, SOCKET_ID_ANY, 0);
	FAIL_ON_MEMZONE_NULL(mz);
	rte_kni_list[kni_port_id].sync_addr= mz->addr;
	kni_fifo_init(rte_kni_list[kni_port_id].sync_addr, KNI_FIFO_COUNT_MAX);

	return 0;
}

/**
 * Initializes the kni fifo structure
 */
static void
kni_fifo_init(struct rte_kni_fifo *fifo, unsigned size)
{
	/* Ensure size is power of 2 */
	if (size & (size - 1))
		rte_panic("KNI fifo size must be power of 2\n");

	fifo->write = 0;
	fifo->read = 0;
	fifo->len = size;
	fifo->elem_size = sizeof(void *);
}


void
init_kni(void)
{
	uint8_t i = 0;
	const struct rte_memzone *mz = NULL;

	/* Create the rte_kni fifos for each KNI port */
	for (i = 0; i < MAX_KNI_PORTS; i++) {
		RTE_LOG(INFO, APP, "Initialising KNI %d\n", i);
		create_kni_fifos(i);
	}
}
