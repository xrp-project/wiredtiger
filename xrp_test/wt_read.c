/*
 * wt_read: point-lookup verification and timing through the WiredTiger API.
 *
 * With WT_BPF_BTREE_PATH set, cold lookups run through the XRP pushdown. The
 * connection close statistics report how many reads went through XRP.
 *
 * usage: wt_read <home> <nkeys> [cache_mb] [passes] [seq|rand] [warm]
 *
 * With "warm", a full cursor scan runs before the timed passes. The scan uses
 * the normal read path, so it loads the internal levels into the cache, which
 * makes the timed lookups exercise the cached-prefix XRP scenario.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wiredtiger.h>

#include "kv.h"

#define URI "file:xrp_test.wt"

int
main(int argc, char **argv)
{
    WT_CONNECTION *conn;
    WT_CURSOR *cursor;
    WT_SESSION *session;
    struct timespec start_ts, end_ts;
    uint64_t elapsed_ns;
    uint32_t cache_mb, i, k, nkeys, nfound, nmissing, nmismatch, pass, passes, rng;
    int randomized, ret, warm;
    const char *got;
    char config[128], key[32], expect[KV_VALUE_MAX];

    if (argc < 3) {
        fprintf(stderr, "usage: %s <home> <nkeys> [cache_mb] [passes]\n", argv[0]);
        return (1);
    }
    nkeys = (uint32_t)strtoul(argv[2], NULL, 10);
    cache_mb = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 10) : 16;
    passes = argc > 4 ? (uint32_t)strtoul(argv[4], NULL, 10) : 1;
    randomized = argc > 5 && strcmp(argv[5], "rand") == 0;
    warm = argc > 6 && strcmp(argv[6], "warm") == 0;

    snprintf(config, sizeof(config),
      "cache_size=%uMB,direct_io=[data],buffer_alignment=512B,mmap=false", cache_mb);
    if ((ret = wiredtiger_open(argv[1], NULL, config, &conn)) != 0) {
        fprintf(stderr, "wiredtiger_open: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0) {
        fprintf(stderr, "open_session: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    if ((ret = session->open_cursor(session, URI, NULL, NULL, &cursor)) != 0) {
        fprintf(stderr, "open_cursor: %s\n", wiredtiger_strerror(ret));
        return (1);
    }

    if (warm) {
        i = 0;
        cursor->reset(cursor);
        while ((ret = cursor->next(cursor)) == 0)
            ++i;
        if (ret != WT_NOTFOUND) {
            fprintf(stderr, "warmup scan: %s\n", wiredtiger_strerror(ret));
            return (1);
        }
        cursor->reset(cursor);
        printf("warmup scan: %u keys\n", i);
    }

    rng = 0x2545f491;
    for (pass = 0; pass < passes; ++pass) {
        nfound = nmissing = nmismatch = 0;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        for (i = 0; i < nkeys; ++i) {
            if (randomized) {
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                k = rng % nkeys;
            } else
                k = i;
            kv_make_key(key, k);
            kv_make_value(expect, k);
            cursor->set_key(cursor, key);
            ret = cursor->search(cursor);
            if (ret == WT_NOTFOUND) {
                ++nmissing;
                if (nmissing < 5)
                    printf("missing: %s\n", key);
                continue;
            }
            if (ret != 0) {
                fprintf(stderr, "search %s: %s\n", key, wiredtiger_strerror(ret));
                return (1);
            }
            if ((ret = cursor->get_value(cursor, &got)) != 0) {
                fprintf(stderr, "get_value %s: %s\n", key, wiredtiger_strerror(ret));
                return (1);
            }
            if (strcmp(got, expect) == 0)
                ++nfound;
            else {
                ++nmismatch;
                if (nmismatch < 5)
                    printf("mismatch %s: got %s expect %s\n", key, got, expect);
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        elapsed_ns = (uint64_t)(end_ts.tv_sec - start_ts.tv_sec) * 1000000000 +
          (uint64_t)(end_ts.tv_nsec - start_ts.tv_nsec);
        printf("pass %u: %u keys, %u ok, %u missing, %u mismatch, %.2f us/op\n", pass, nkeys,
          nfound, nmissing, nmismatch, (double)elapsed_ns / 1000.0 / nkeys);
    }

    if ((ret = conn->close(conn, NULL)) != 0) {
        fprintf(stderr, "conn close: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    return (nmissing != 0 || nmismatch != 0);
}
