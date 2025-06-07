#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>

struct token_bucket {
    uint64_t rate_pps;
    uint64_t burst;
    double tokens;
    uint64_t last_tsc;
};

void token_bucket_init();
int token_bucket_consume(uint16_t port);
