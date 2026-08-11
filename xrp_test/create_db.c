/*
 * create_db: build a small single-file row-store B-tree for XRP testing.
 *
 * The tree uses 512-byte allocation units and 512-byte internal/leaf pages so
 * that a point lookup requires several dependent 512-byte reads, matching the
 * assumptions of the XRP BPF program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wiredtiger.h>

#define URI "file:xrp_test.wt"

static const char *conn_config = "create,cache_size=200MB";
static const char *table_config =
  "key_format=S,value_format=S,"
  "allocation_size=512,internal_page_max=512,leaf_page_max=512,"
  "checksum=on";

int
main(int argc, char **argv)
{
    WT_CONNECTION *conn;
    WT_CURSOR *cursor;
    WT_SESSION *session;
    uint32_t i, nkeys;
    int ret;
    char key[32], value[32];

    if (argc != 3) {
        fprintf(stderr, "usage: %s <home> <nkeys>\n", argv[0]);
        return (1);
    }
    nkeys = (uint32_t)strtoul(argv[2], NULL, 10);

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
    if ((ret = session->open_cursor(session, URI, NULL, NULL, &cursor)) != 0) {
        fprintf(stderr, "open_cursor: %s\n", wiredtiger_strerror(ret));
        return (1);
    }

    for (i = 0; i < nkeys; ++i) {
        snprintf(key, sizeof(key), "%08u", i);
        snprintf(value, sizeof(value), "V%08u-%06x", i, i * 7919u);
        cursor->set_key(cursor, key);
        cursor->set_value(cursor, value);
        if ((ret = cursor->insert(cursor)) != 0) {
            fprintf(stderr, "insert %s: %s\n", key, wiredtiger_strerror(ret));
            return (1);
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

    printf("created %s with %u keys\n", URI, nkeys);
    return (0);
}
