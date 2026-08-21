/*
 * create_db: build a single-file row-store B-tree for XRP testing.
 *
 * The tree uses 4KB allocation units and 4KB internal/leaf pages, matching
 * the XRP per-hop read size: every page is exactly one 4KB block, so a point
 * lookup is a chain of dependent 4KB reads.
 *
 * With "bulk" the keys are loaded through a bulk cursor (sorted append-only
 * load, no splits, near-full pages, deterministic geometry), which is the
 * only practical way to build a ~100GB tree. Value length comes from
 * XRP_VALUE_LEN (see kv.h).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wiredtiger.h>

#include "kv.h"

#define URI "file:xrp_test.wt"

static const char *conn_config = "create,cache_size=1GB";
static const char *table_config =
  "key_format=S,value_format=S,"
  "allocation_size=4096,internal_page_max=4096,leaf_page_max=4096,"
  "checksum=on";

int
main(int argc, char **argv)
{
    WT_CONNECTION *conn;
    WT_CURSOR *cursor;
    WT_SESSION *session;
    struct timespec start_ts, now_ts;
    double elapsed;
    uint32_t i, nkeys;
    int bulk, ret;
    char key[32], value[KV_VALUE_MAX];

    if (argc < 3) {
        fprintf(stderr, "usage: %s <home> <nkeys> [bulk]\n", argv[0]);
        return (1);
    }
    nkeys = (uint32_t)strtoul(argv[2], NULL, 10);
    bulk = argc > 3 && strcmp(argv[3], "bulk") == 0;

    if ((ret = wiredtiger_open(argv[1], NULL, conn_config, &conn)) != 0) {
        fprintf(stderr, "wiredtiger_open: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0) {
        fprintf(stderr, "open_session: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    if ((ret = session->create(session, URI, table_config)) != 0) {
        fprintf(stderr, "create: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    if ((ret = session->open_cursor(session, URI, NULL, bulk ? "bulk" : NULL, &cursor)) != 0) {
        fprintf(stderr, "open_cursor: %s\n", wiredtiger_strerror(ret));
        return (1);
    }

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    for (i = 0; i < nkeys; ++i) {
        kv_make_key(key, i);
        kv_make_value(value, i);
        cursor->set_key(cursor, key);
        cursor->set_value(cursor, value);
        if ((ret = cursor->insert(cursor)) != 0) {
            fprintf(stderr, "insert %s: %s\n", key, wiredtiger_strerror(ret));
            return (1);
        }
        if ((i + 1) % 5000000 == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            elapsed = (double)(now_ts.tv_sec - start_ts.tv_sec) +
              (double)(now_ts.tv_nsec - start_ts.tv_nsec) / 1e9;
            printf("progress: %u/%u keys, %.0f keys/s\n", i + 1, nkeys, (i + 1) / elapsed);
            fflush(stdout);
        }
    }
    if ((ret = cursor->close(cursor)) != 0) {
        fprintf(stderr, "cursor close: %s\n", wiredtiger_strerror(ret));
        return (1);
    }

    if ((ret = session->checkpoint(session, NULL)) != 0) {
        fprintf(stderr, "checkpoint: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    if ((ret = conn->close(conn, NULL)) != 0) {
        fprintf(stderr, "conn close: %s\n", wiredtiger_strerror(ret));
        return (1);
    }

    printf("created %s with %u keys, value_len %u%s\n", URI, nkeys, kv_value_len(),
      bulk ? " (bulk)" : "");
    return (0);
}
