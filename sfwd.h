/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2021 Intel Corporation
 */

#ifndef __L3_FWD_H__
#define __L3_FWD_H__

#include <rte_ethdev.h>
#include <rte_vect.h>
#include <rte_acl.h>

#define DO_RFC_1812_CHECKS

#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1

#if !defined(NO_HASH_MULTI_LOOKUP) && defined(__ARM_NEON)
#define NO_HASH_MULTI_LOOKUP 1
#endif

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MEMPOOL_CACHE_SIZE 256
#define MAX_RX_QUEUE_PER_LCORE 16

#define VECTOR_SIZE_DEFAULT   MAX_PKT_BURST
#define VECTOR_TMO_NS_DEFAULT 1E6 /* 1ms */
/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define	MAX_TX_BURST	  (MAX_PKT_BURST / 2)

#define NB_SOCKETS        8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	  3

/* Used to mark destination port as 'invalid'. */
#define	BAD_PORT ((uint16_t)-1)

/* replace first 12B of the ethernet header. */
#define	MASK_ETH 0x3f

/* Hash parameters. */
#ifdef RTE_ARCH_64
/* default to 4 million hash entries (approx) */
#define L3FWD_HASH_ENTRIES		(1024*1024*4)
#else
/* 32-bit has less address-space for hugepage memory, limit to 1M entries */
#define L3FWD_HASH_ENTRIES		(1024*1024*1)
#endif

struct parm_cfg {
	const char *rule_ipv4_name;
	const char *rule_ipv6_name;
	enum rte_acl_classify_alg alg;
};

struct acl_algorithms {
	const char *name;
	enum rte_acl_classify_alg alg;
};

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
	uint16_t port_id;
	uint16_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

extern volatile bool force_quit;

/* RX and TX queue depths */
extern uint16_t nb_rxd;
extern uint16_t nb_txd;

/* ethernet addresses of ports */
extern uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
extern struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
extern uint32_t enabled_port_mask;

/* Used only in exact match mode. */
extern int ipv6; /**< ipv6 is false by default. */
extern uint32_t hash_entry_number;

extern xmm_t val_eth[RTE_MAX_ETHPORTS];

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

extern struct parm_cfg parm_config;

extern struct acl_algorithms acl_alg[];

extern uint32_t max_pkt_len;

/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf *qconf, uint16_t n, uint16_t port)
{
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int send_single_packet(struct lcore_conf *qconf,
		   struct rte_mbuf *m, uint16_t port)
{
	uint16_t len;

	len = qconf->tx_mbufs[port].len;
	qconf->tx_mbufs[port].m_table[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
		send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	qconf->tx_mbufs[port].len = len;
	return 0;
}

#ifdef DO_RFC_1812_CHECKS
static inline int
is_valid_ipv4_pkt(struct rte_ipv4_hdr *pkt, uint32_t link_len, uint64_t ol_flags)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (link_len < sizeof(struct rte_ipv4_hdr))
		return -1;

	/* 2. The IP checksum must be correct. */
	/* if this is not checked in H/W, check it. */
	if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_NONE) {
		uint16_t actual_cksum, expected_cksum;
		actual_cksum = pkt->hdr_checksum;
		pkt->hdr_checksum = 0;
		expected_cksum = rte_ipv4_cksum(pkt);
		if (actual_cksum != expected_cksum)
			return -2;
	}

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (((pkt->version_ihl) >> 4) != 4)
		return -3;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
	if ((pkt->version_ihl & 0xf) < 5)
		return -4;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct rte_ipv4_hdr))
		return -5;

	return 0;
}
#endif /* DO_RFC_1812_CHECKS */

enum rte_acl_classify_alg
parse_acl_alg(const char *alg);

int
usage_acl_alg(char *buf, size_t sz);

int
init_mem(uint16_t portid, unsigned int nb_mbuf);

int config_port_max_pkt_len(struct rte_eth_conf *conf,
			    struct rte_eth_dev_info *dev_info);

/* Function pointers for ACL, LPM, EM or FIB functionality. */
void
setup_acl(const int socketid);

void
setup_lpm(const int socketid);

void
setup_hash(const int socketid);

void
setup_fib(const int socketid);

int
em_check_ptype(int portid);

int
lpm_check_ptype(int portid);

uint16_t
em_cb_parse_ptype(uint16_t port, uint16_t queue, struct rte_mbuf *pkts[],
		  uint16_t nb_pkts, uint16_t max_pkts, void *user_param);

uint16_t
lpm_cb_parse_ptype(uint16_t port, uint16_t queue, struct rte_mbuf *pkts[],
		   uint16_t nb_pkts, uint16_t max_pkts, void *user_param);

int
acl_main_loop(__rte_unused void *dummy);

int
em_main_loop(__rte_unused void *dummy);

int
lpm_main_loop(__rte_unused void *dummy);

int
fib_main_loop(__rte_unused void *dummy);

int
lpm_event_main_loop_tx_d(__rte_unused void *dummy);
int
lpm_event_main_loop_tx_d_burst(__rte_unused void *dummy);
int
lpm_event_main_loop_tx_q(__rte_unused void *dummy);
int
lpm_event_main_loop_tx_q_burst(__rte_unused void *dummy);
int
lpm_event_main_loop_tx_d_vector(__rte_unused void *dummy);
int
lpm_event_main_loop_tx_d_burst_vector(__rte_unused void *dummy);
int
lpm_event_main_loop_tx_q_vector(__rte_unused void *dummy);
int
lpm_event_main_loop_tx_q_burst_vector(__rte_unused void *dummy);

int
em_event_main_loop_tx_d(__rte_unused void *dummy);
int
em_event_main_loop_tx_d_burst(__rte_unused void *dummy);
int
em_event_main_loop_tx_q(__rte_unused void *dummy);
int
em_event_main_loop_tx_q_burst(__rte_unused void *dummy);
int
em_event_main_loop_tx_d_vector(__rte_unused void *dummy);
int
em_event_main_loop_tx_d_burst_vector(__rte_unused void *dummy);
int
em_event_main_loop_tx_q_vector(__rte_unused void *dummy);
int
em_event_main_loop_tx_q_burst_vector(__rte_unused void *dummy);

int
fib_event_main_loop_tx_d(__rte_unused void *dummy);
int
fib_event_main_loop_tx_d_burst(__rte_unused void *dummy);
int
fib_event_main_loop_tx_q(__rte_unused void *dummy);
int
fib_event_main_loop_tx_q_burst(__rte_unused void *dummy);
int
fib_event_main_loop_tx_d_vector(__rte_unused void *dummy);
int
fib_event_main_loop_tx_d_burst_vector(__rte_unused void *dummy);
int
fib_event_main_loop_tx_q_vector(__rte_unused void *dummy);
int
fib_event_main_loop_tx_q_burst_vector(__rte_unused void *dummy);

#endif  /* __L3_FWD_H__ */
