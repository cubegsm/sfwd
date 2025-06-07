#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <rte_atomic.h>
#include "sfwd_stat.h"
#include "sfwd.h"

pthread_t thread;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pstat stat;

void* thread_stat(void* arg) {
    (void)arg;
    struct timespec ts;

    while (1) {
        printf("\n");
        for (int port=0; port<2; port++)
            printf("Port %d: rx %.8llu pkts, %.12llu bytes; tx %.8llu pkts, %.12llu bytes, drop %.8llu pkts\n",
                port,
                (unsigned long long) rte_atomic64_read(&stat.rx_packets[port]),
                (unsigned long long) rte_atomic64_read(&stat.rx_bytes[port]),
                (unsigned long long) rte_atomic64_read(&stat.tx_packets[port]),
                (unsigned long long) rte_atomic64_read(&stat.tx_bytes[port]),
                (unsigned long long) rte_atomic64_read(&stat.drop[port]));

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += stat.period;

        pthread_mutex_lock(&lock);
        if (!force_quit)
            pthread_cond_timedwait(&cond, &lock, &ts);

        if (force_quit) {
            pthread_mutex_unlock(&lock);
            break;
        }
        pthread_mutex_unlock(&lock);
    }

    return NULL;
}

int stat_destroy()
{
    pthread_mutex_lock(&lock);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
    return 0;
}

int stat_init()
{
    stat.period = 1;
    rte_atomic64_init(&stat.rx_packets[0]);
    rte_atomic64_init(&stat.rx_bytes[0]);
    rte_atomic64_init(&stat.tx_packets[1]);
    rte_atomic64_init(&stat.tx_bytes[1]);
    rte_atomic64_init(&stat.drop[0]);
    rte_atomic64_init(&stat.drop[1]);
}

int stat_create()
{
    if (pthread_create(&thread, NULL, thread_stat, NULL) != 0) {
        perror("pthread_create");
        fflush(stdout);
        return 1;
    }
    return 0;
}

int stat_join()
{
    pthread_join(thread, NULL);
    return 0;
}
