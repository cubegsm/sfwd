#include "sfwd_rlimit.h"
#include <rte_cycles.h>

void token_bucket_init_struct(struct token_bucket *tb, uint64_t rate_pps, uint64_t burst) {
    tb->rate_pps = rate_pps;
    tb->burst = burst;
    tb->tokens = burst;
    tb->last_tsc = rte_get_timer_cycles();
}

static struct token_bucket tb[2];

//#define RLIMIT_MAX_RATE 500
//#define RLIMIT_BOOST 100
#define RLIMIT_MAX_RATE 500000   // 500k pkts/sec
#define RLIMIT_BOOST 5000        // 5k pkts/sec boost

void token_bucket_init()
{
    token_bucket_init_struct(&tb[0], RLIMIT_MAX_RATE, RLIMIT_BOOST);
    token_bucket_init_struct(&tb[1], RLIMIT_MAX_RATE, RLIMIT_BOOST);
}

int token_bucket_consume(uint16_t port) {
    uint64_t now = rte_get_timer_cycles();
    uint64_t hz = rte_get_timer_hz();
    double delta_sec = (double)(now - tb[port].last_tsc) / hz;

    tb[port].tokens += delta_sec * tb[port].rate_pps;
    if (tb[port].tokens > tb[port].burst)
        tb[port].tokens = tb[port].burst;

    tb[port].last_tsc = now;

    if (tb[port].tokens >= 1.0) {
        tb[port].tokens -= 1.0;
        return 1;  // pass
    }

    return 0;  // drop
}
