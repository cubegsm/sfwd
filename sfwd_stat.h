#ifndef __SFWD_STAT_H__
#define __SFWD_STAT_H__

#include <stdio.h>
#include <rte_atomic.h>

#define PORTS_MAX 16

typedef struct {
  rte_atomic64_t rx_packets[PORTS_MAX];
  rte_atomic64_t tx_packets[PORTS_MAX];
  rte_atomic64_t rx_bytes[PORTS_MAX];
  rte_atomic64_t tx_bytes[PORTS_MAX];
  rte_atomic64_t drop[PORTS_MAX];
  volatile uint32_t period;
} pstat;

extern pstat stat;

int stat_init();
int stat_create();
int stat_join();
int stat_destroy();

#endif  /* __SFWD_STAT_H__ */
