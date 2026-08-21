/*
 * user_lookup: userspace prototype of the XRP B-tree point lookup.
 *
 * Discovers the root page address from the WiredTiger metadata, then performs
 * the whole traversal on raw 512-byte disk blocks with pread, using the same
 * parsing logic that the BPF program will use. Results are compared against
 * the values the workload generator wrote.
 *
 * usage:
 *   user_lookup <home> <file.wt> get <key>
 *   user_lookup <home> <file.wt> verify <nkeys>
 *   user_lookup <home> <file.wt> bench <nkeys> <nthreads> <seconds>
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <wiredtiger.h>

#include "kv.h"

#define BTREE_BLOCK_SIZE 4096
#define BTREE_MAX_DEPTH 8
#define BTREE_PAGE_HEADER_SIZE 28
#define BTREE_BLOCK_HEADER_SIZE 12
#define BTREE_VALUE_MAX_LEN 1400

#define BTREE_PAGE_ROW_INT 6
#define BTREE_PAGE_ROW_LEAF 7

#define CELL_KEY_SHORT 0x01
#define CELL_KEY_SHORT_PFX 0x02
#define CELL_VALUE_SHORT 0x03
#define CELL_SHORT_TYPE(v) ((v)&0x03U)
#define CELL_SHORT_SHIFT 2
#define CELL_SIZE_ADJUST 64

#define CELL_64V 0x04
#define CELL_SECOND_DESC 0x08

#define CELL_ADDR_DEL (0)
#define CELL_ADDR_INT (1 << 4)
#define CELL_ADDR_LEAF (2 << 4)
#define CELL_ADDR_LEAF_NO (3 << 4)
#define CELL_DEL (4 << 4)
#define CELL_KEY (5 << 4)
#define CELL_KEY_OVFL (6 << 4)
#define CELL_KEY_PFX (7 << 4)
#define CELL_VALUE (8 << 4)
#define CELL_VALUE_COPY (9 << 4)
#define CELL_VALUE_OVFL (10 << 4)
#define CELL_TYPE(v) ((v)&0xf0U)

#define TW_PREPARE 0x01
#define TW_TS_DURABLE_START 0x02
#define TW_TS_DURABLE_STOP 0x04
#define TW_TS_START 0x08
#define TW_TS_STOP 0x10
#define TW_TXN_START 0x20
#define TW_TXN_STOP 0x40

#define POS_1BYTE_MARKER ((uint8_t)0x80)
#define POS_2BYTE_MARKER ((uint8_t)0xc0)
#define POS_MULTI_MARKER ((uint8_t)0xe0)
#define POS_1BYTE_MAX ((1 << 6) - 1)
#define POS_2BYTE_MAX ((1 << 13) + POS_1BYTE_MAX)

#define GET_BITS(x, start, end) (((uint64_t)(x) & ((1U << (start)) - 1U)) >> (end))

#define RET_NOTFOUND 1
#define RET_UNSUPPORTED 2
#define RET_CORRUPT 3

struct page_header {
    uint64_t recno;
    uint64_t write_gen;
    uint32_t mem_size;
    uint32_t entries;
    uint8_t type;
    uint8_t flags;
    uint8_t unused;
    uint8_t version;
};

struct lookup_result {
    int found;
    uint64_t value_len;
    uint8_t value[BTREE_VALUE_MAX_LEN];
    int depth;
};

static int
unpack_posint(const uint8_t **pp, uint64_t *retp)
{
    uint64_t x;
    uint8_t len;
    const uint8_t *p;

    p = *pp;
    len = (*p++ & 0xf);
    for (x = 0; len != 0; --len)
        x = (x << 8) | *p++;
    *retp = x;
    *pp = p;
    return (0);
}

static int
vunpack_uint(const uint8_t **pp, uint64_t *xp)
{
    const uint8_t *p;
    int ret;

    p = *pp;
    switch (*p & 0xf0) {
    case POS_1BYTE_MARKER:
    case POS_1BYTE_MARKER | 0x10:
    case POS_1BYTE_MARKER | 0x20:
    case POS_1BYTE_MARKER | 0x30:
        *xp = GET_BITS(*p, 6, 0);
        p += 1;
        break;
    case POS_2BYTE_MARKER:
    case POS_2BYTE_MARKER | 0x10:
        *xp = GET_BITS(*p++, 5, 0) << 8;
        *xp |= *p++;
        *xp += POS_1BYTE_MAX + 1;
        break;
    case POS_MULTI_MARKER:
        ret = unpack_posint(&p, xp);
        if (ret != 0)
            return (ret);
        *xp += POS_2BYTE_MAX + 1;
        break;
    default:
        return (-RET_CORRUPT);
    }
    *pp = p;
    return (0);
}

static int
addr_to_offset(const uint8_t **pp, uint64_t *offset, uint64_t *size)
{
    uint64_t raw_offset, raw_size, raw_checksum;
    int ret;

    if ((ret = vunpack_uint(pp, &raw_offset)) != 0)
        return (ret);
    if ((ret = vunpack_uint(pp, &raw_size)) != 0)
        return (ret);
    if ((ret = vunpack_uint(pp, &raw_checksum)) != 0)
        return (ret);
    if (raw_size == 0) {
        *offset = 0;
        *size = 0;
    } else {
        *offset = BTREE_BLOCK_SIZE * (raw_offset + 1);
        *size = BTREE_BLOCK_SIZE * raw_size;
    }
    return (0);
}

static int
cell_type(uint8_t desc)
{
    return (CELL_SHORT_TYPE(desc) ? CELL_SHORT_TYPE(desc) : CELL_TYPE(desc));
}

/*
 * Parse an address cell and advance the cursor past it.
 */
static int
parse_cell_addr(const uint8_t **pp, uint64_t *offset, uint64_t *size)
{
    const uint8_t *p;
    uint64_t addr_len;
    uint8_t desc, flags;
    int ret;

    p = *pp;
    desc = *p++;
    if ((cell_type(desc) != CELL_ADDR_INT && cell_type(desc) != CELL_ADDR_LEAF &&
          cell_type(desc) != CELL_ADDR_LEAF_NO) ||
      (desc & CELL_64V) != 0)
        return (-RET_UNSUPPORTED);
    if ((desc & CELL_SECOND_DESC) != 0) {
        flags = *p++;
        if (flags != 0)
            return (-RET_UNSUPPORTED);
    }
    if ((ret = vunpack_uint(&p, &addr_len)) != 0)
        return (ret);
    {
        const uint8_t *addr = p;
        if ((ret = addr_to_offset(&addr, offset, size)) != 0)
            return (ret);
    }
    *pp = p + addr_len;
    return (0);
}

/*
 * Parse a KEY or KEY_SHORT cell and advance the cursor past it.
 */
static int
parse_cell_key(const uint8_t **pp, const uint8_t **key, uint64_t *key_len)
{
    const uint8_t *p;
    uint64_t len;
    uint8_t desc;
    int ret;

    p = *pp;
    desc = *p;
    switch (cell_type(desc)) {
    case CELL_KEY_SHORT:
        p += 1;
        len = desc >> CELL_SHORT_SHIFT;
        break;
    case CELL_KEY:
        if ((desc & (CELL_64V | CELL_SECOND_DESC)) != 0)
            return (-RET_UNSUPPORTED);
        p += 1;
        if ((ret = vunpack_uint(&p, &len)) != 0)
            return (ret);
        len += CELL_SIZE_ADJUST;
        break;
    default:
        return (-RET_UNSUPPORTED);
    }
    *key = p;
    *key_len = len;
    *pp = p + len;
    return (0);
}

/*
 * Skip the validity window that optionally follows a value cell descriptor.
 */
static int
skip_value_window(const uint8_t **pp, uint8_t desc)
{
    const uint8_t *p;
    uint64_t unused;
    uint8_t flags;
    int ret;

    if ((desc & CELL_SECOND_DESC) == 0)
        return (0);
    p = *pp;
    flags = *p++;
    if ((flags & TW_PREPARE) != 0)
        return (-RET_UNSUPPORTED);
    if ((flags & TW_TS_START) != 0 && (ret = vunpack_uint(&p, &unused)) != 0)
        return (ret);
    if ((flags & TW_TXN_START) != 0 && (ret = vunpack_uint(&p, &unused)) != 0)
        return (ret);
    if ((flags & TW_TS_DURABLE_START) != 0 && (ret = vunpack_uint(&p, &unused)) != 0)
        return (ret);
    if ((flags & TW_TS_STOP) != 0 && (ret = vunpack_uint(&p, &unused)) != 0)
        return (ret);
    if ((flags & TW_TXN_STOP) != 0 && (ret = vunpack_uint(&p, &unused)) != 0)
        return (ret);
    if ((flags & TW_TS_DURABLE_STOP) != 0 && (ret = vunpack_uint(&p, &unused)) != 0)
        return (ret);
    *pp = p;
    return (0);
}

/*
 * Parse a VALUE or VALUE_SHORT cell and advance the cursor past it.
 */
static int
parse_cell_value(const uint8_t **pp, const uint8_t **value, uint64_t *value_len)
{
    const uint8_t *p;
    uint64_t len;
    uint8_t desc;
    int ret;

    p = *pp;
    desc = *p;
    switch (cell_type(desc)) {
    case CELL_VALUE_SHORT:
        p += 1;
        len = desc >> CELL_SHORT_SHIFT;
        break;
    case CELL_VALUE:
        if ((desc & CELL_64V) != 0)
            return (-RET_UNSUPPORTED);
        p += 1;
        if ((ret = skip_value_window(&p, desc)) != 0)
            return (ret);
        if ((ret = vunpack_uint(&p, &len)) != 0)
            return (ret);
        if ((desc & CELL_SECOND_DESC) == 0)
            len += CELL_SIZE_ADJUST;
        break;
    default:
        return (-RET_UNSUPPORTED);
    }
    *value = p;
    *value_len = len;
    *pp = p + len;
    return (0);
}

static int
lex_compare(const uint8_t *a, uint64_t alen, const uint8_t *b, uint64_t blen)
{
    uint64_t len;

    len = alen < blen ? alen : blen;
    for (; len > 0; --len, ++a, ++b)
        if (*a != *b)
            return (*a < *b ? -1 : 1);
    return (alen == blen ? 0 : (alen < blen ? -1 : 1));
}

/*
 * Search a row-store internal page for the child that covers the key.
 */
static int
search_int_page(
  const uint8_t *page, const uint8_t *key, uint64_t key_len, uint64_t *child_offset)
{
    const struct page_header *hdr;
    const uint8_t *p;
    const uint8_t *cell_key;
    uint64_t cell_key_len, cell_off, cell_size, prev_off;
    uint32_t i, nr_kv;
    int cmp, ret;

    hdr = (const struct page_header *)page;
    nr_kv = hdr->entries / 2;
    p = page + BTREE_PAGE_HEADER_SIZE + BTREE_BLOCK_HEADER_SIZE;
    prev_off = 0;

    for (i = 0; i < nr_kv; ++i) {
        if ((ret = parse_cell_key(&p, &cell_key, &cell_key_len)) != 0)
            return (ret);
        if ((ret = parse_cell_addr(&p, &cell_off, &cell_size)) != 0)
            return (ret);
        if (cell_size != BTREE_BLOCK_SIZE)
            return (-RET_UNSUPPORTED);

        /* The 0th key on an internal page sorts before any key. */
        if (i == 0)
            cmp = 1;
        else
            cmp = lex_compare(key, key_len, cell_key, cell_key_len);
        if (cmp == 0) {
            *child_offset = cell_off;
            return (0);
        }
        if (cmp < 0) {
            *child_offset = prev_off;
            return (0);
        }
        prev_off = cell_off;
    }
    *child_offset = prev_off;
    return (0);
}

/*
 * Search a row-store leaf page for an exact key match.
 */
static int
search_leaf_page(
  const uint8_t *page, const uint8_t *key, uint64_t key_len, struct lookup_result *res)
{
    const struct page_header *hdr;
    const uint8_t *p;
    const uint8_t *cell_key, *cell_value;
    uint64_t cell_key_len, cell_value_len;
    uint32_t consumed;
    uint8_t desc;
    int cmp, ret, type;

    hdr = (const struct page_header *)page;
    p = page + BTREE_PAGE_HEADER_SIZE + BTREE_BLOCK_HEADER_SIZE;
    consumed = 0;

    while (consumed < hdr->entries) {
        desc = *p;
        type = cell_type(desc);
        switch (type) {
        case CELL_KEY_SHORT:
        case CELL_KEY:
            if ((ret = parse_cell_key(&p, &cell_key, &cell_key_len)) != 0)
                return (ret);
            ++consumed;
            cmp = lex_compare(key, key_len, cell_key, cell_key_len);
            if (cmp < 0)
                return (RET_NOTFOUND);
            if (cmp == 0) {
                res->found = 1;
                res->value_len = 0;
                if (consumed < hdr->entries) {
                    type = cell_type(*p);
                    if (type == CELL_VALUE_SHORT || type == CELL_VALUE) {
                        if ((ret = parse_cell_value(&p, &cell_value, &cell_value_len)) != 0)
                            return (ret);
                        if (cell_value_len > BTREE_VALUE_MAX_LEN)
                            return (-RET_UNSUPPORTED);
                        memcpy(res->value, cell_value, cell_value_len);
                        res->value_len = cell_value_len;
                    } else if (type == CELL_VALUE_COPY || type == CELL_VALUE_OVFL)
                        return (-RET_UNSUPPORTED);
                }
                return (0);
            }
            break;
        case CELL_VALUE_SHORT:
        case CELL_VALUE:
            if ((ret = parse_cell_value(&p, &cell_value, &cell_value_len)) != 0)
                return (ret);
            ++consumed;
            break;
        default:
            return (-RET_UNSUPPORTED);
        }
    }
    return (RET_NOTFOUND);
}

/*
 * Full traversal from the root block.
 */
static __thread uint8_t *page_buf;

static int
raw_lookup(int fd, uint64_t root_offset, const uint8_t *key, uint64_t key_len,
  struct lookup_result *res)
{
    struct page_header *hdr;
    uint64_t offset;
    int depth, ret;
    uint8_t *page = page_buf;

    offset = root_offset;
    memset(res, 0, sizeof(*res));

    for (depth = 0; depth < BTREE_MAX_DEPTH; ++depth) {
        if (pread(fd, page, BTREE_BLOCK_SIZE, (off_t)offset) != BTREE_BLOCK_SIZE) {
            perror("pread");
            return (-RET_CORRUPT);
        }
        res->depth = depth + 1;
        hdr = (struct page_header *)page;
        switch (hdr->type) {
        case BTREE_PAGE_ROW_INT:
            if ((ret = search_int_page(page, key, key_len, &offset)) != 0)
                return (ret);
            break;
        case BTREE_PAGE_ROW_LEAF:
            return (search_leaf_page(page, key, key_len, res));
        default:
            fprintf(stderr, "unexpected page type %u at offset %llu\n", hdr->type,
              (unsigned long long)offset);
            return (-RET_CORRUPT);
        }
    }
    return (-RET_CORRUPT);
}

/*
 * Find the root block address of a file from the WiredTiger metadata.
 */
static int
find_root(const char *home, const char *uri, uint64_t *root_offset, uint64_t *root_size)
{
    WT_CONNECTION *conn;
    WT_CURSOR *cursor;
    WT_SESSION *session;
    const char *config, *hex, *end, *p;
    uint64_t checksum;
    size_t i, len;
    int ret;
    uint8_t cookie[64];
    const uint8_t *cp;

    if ((ret = wiredtiger_open(home, NULL, "readonly=true", &conn)) != 0) {
        fprintf(stderr, "wiredtiger_open: %s\n", wiredtiger_strerror(ret));
        return (-1);
    }
    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0)
        goto err;
    if ((ret = session->open_cursor(session, "metadata:", NULL, NULL, &cursor)) != 0)
        goto err;
    cursor->set_key(cursor, uri);
    if ((ret = cursor->search(cursor)) != 0) {
        fprintf(stderr, "metadata search %s: %s\n", uri, wiredtiger_strerror(ret));
        goto err;
    }
    if ((ret = cursor->get_value(cursor, &config)) != 0)
        goto err;

    /* Use the last checkpoint address in the config string. */
    hex = NULL;
    for (p = config; (p = strstr(p, "addr=\"")) != NULL; p += 6)
        hex = p + 6;
    if (hex == NULL) {
        fprintf(stderr, "no checkpoint address in metadata: %s\n", config);
        ret = -1;
        goto err;
    }
    end = strchr(hex, '"');
    len = (size_t)(end - hex);
    if (len / 2 > sizeof(cookie)) {
        ret = -1;
        goto err;
    }
    for (i = 0; i < len / 2; ++i) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        cookie[i] = (uint8_t)byte;
    }

    /* Cookie layout: version byte, then a packed root address triple. */
    if (cookie[0] != 1) {
        fprintf(stderr, "unexpected checkpoint cookie version %u\n", cookie[0]);
        ret = -1;
        goto err;
    }
    cp = cookie + 1;
    if ((ret = vunpack_uint(&cp, root_offset)) != 0)
        goto err;
    if ((ret = vunpack_uint(&cp, root_size)) != 0)
        goto err;
    if ((ret = vunpack_uint(&cp, &checksum)) != 0)
        goto err;
    if (*root_size == 0) {
        fprintf(stderr, "empty tree, no root page\n");
        ret = -1;
        goto err;
    }
    *root_offset = BTREE_BLOCK_SIZE * (*root_offset + 1);
    *root_size = BTREE_BLOCK_SIZE * *root_size;
    ret = 0;

err:
    conn->close(conn, NULL);
    return (ret);
}

static struct {
    int fd;
    uint64_t root_offset;
    uint32_t nkeys;
    volatile int stop;
    atomic_ulong ops, errors;
} bench_state;

static void *
bench_worker(void *varg)
{
    struct lookup_result res;
    unsigned int seed;
    uint32_t k;
    int ret;
    char expect[KV_VALUE_MAX], key[32];

    seed = (unsigned int)(0x9e3779b9u * (uint32_t)((uintptr_t)varg + 1));
    page_buf = aligned_alloc(4096, 4096);
    if (page_buf == NULL)
        return (NULL);
    while (!bench_state.stop) {
        k = (uint32_t)rand_r(&seed) % bench_state.nkeys;
        kv_make_key(key, k);
        kv_make_value(expect, k);
        ret = raw_lookup(bench_state.fd, bench_state.root_offset, (const uint8_t *)key,
          strlen(key) + 1, &res);
        if (ret == 0 && res.found && res.value_len == strlen(expect) + 1 &&
          memcmp(res.value, expect, res.value_len) == 0)
            atomic_fetch_add(&bench_state.ops, 1);
        else
            atomic_fetch_add(&bench_state.errors, 1);
    }
    return (NULL);
}

static int
run_bench(int fd, uint64_t root_offset, uint32_t nkeys, uint32_t nthreads, uint32_t seconds)
{
    pthread_t *threads;
    uint64_t ops;
    uint32_t i;

    bench_state.fd = fd;
    bench_state.root_offset = root_offset;
    bench_state.nkeys = nkeys;
    threads = calloc(nthreads, sizeof(*threads));
    for (i = 0; i < nthreads; ++i)
        pthread_create(&threads[i], NULL, bench_worker, (void *)(uintptr_t)i);
    sleep(seconds);
    bench_state.stop = 1;
    for (i = 0; i < nthreads; ++i)
        pthread_join(threads[i], NULL);
    ops = atomic_load(&bench_state.ops);
    printf("bench: %u threads, %llu ops, %llu errors, %.0f ops/s, %.2f us/op per thread\n",
      nthreads, (unsigned long long)ops, (unsigned long long)atomic_load(&bench_state.errors),
      (double)ops / seconds, (double)seconds * 1e6 * nthreads / (double)(ops ? ops : 1));
    return (atomic_load(&bench_state.errors) == 0 ? 0 : 1);
}

int
main(int argc, char **argv)
{
    struct lookup_result res;
    uint64_t root_offset, root_size;
    int fd, ret;
    char path[512];

    if (argc < 4) {
        fprintf(stderr, "usage: %s <home> <file.wt> get <key> | verify <nkeys>\n", argv[0]);
        return (1);
    }

    snprintf(path, sizeof(path), "file:%s", argv[2]);
    if (find_root(argv[1], path, &root_offset, &root_size) != 0)
        return (1);
    printf("root: offset=%llu size=%llu\n", (unsigned long long)root_offset,
      (unsigned long long)root_size);
    if (root_size != BTREE_BLOCK_SIZE) {
        fprintf(stderr, "root size %llu unsupported\n", (unsigned long long)root_size);
        return (1);
    }

    snprintf(path, sizeof(path), "%s/%s", argv[1], argv[2]);
    if ((fd = open(path, O_RDONLY | O_DIRECT)) < 0) {
        perror("open");
        return (1);
    }
    if ((page_buf = aligned_alloc(4096, 4096)) == NULL) {
        fprintf(stderr, "aligned_alloc failed\n");
        return (1);
    }

    if (strcmp(argv[3], "bench") == 0 && argc >= 7)
        return (run_bench(fd, root_offset, (uint32_t)strtoul(argv[4], NULL, 10),
          (uint32_t)strtoul(argv[5], NULL, 10), (uint32_t)strtoul(argv[6], NULL, 10)));

    if (strcmp(argv[3], "get") == 0) {
        const char *key = argv[4];
        ret = raw_lookup(fd, root_offset, (const uint8_t *)key, strlen(key) + 1, &res);
        if (ret == 0 && res.found)
            printf("found (depth %d): %.*s\n", res.depth, (int)res.value_len, res.value);
        else if (ret == RET_NOTFOUND || (ret == 0 && !res.found))
            printf("not found (depth %d)\n", res.depth);
        else {
            printf("error %d (depth %d)\n", ret, res.depth);
            return (1);
        }
    } else if (strcmp(argv[3], "verify") == 0) {
        struct timespec start_ts, end_ts;
        uint64_t elapsed_ns;
        uint32_t i, nkeys, nfound, nmissing, nmismatch, nerror;
        int max_depth;
        char key[32], expect[KV_VALUE_MAX];

        nkeys = (uint32_t)strtoul(argv[4], NULL, 10);
        nfound = nmissing = nmismatch = nerror = 0;
        max_depth = 0;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        for (i = 0; i < nkeys; ++i) {
            kv_make_key(key, i);
            kv_make_value(expect, i);
            ret = raw_lookup(fd, root_offset, (const uint8_t *)key, strlen(key) + 1, &res);
            if (res.depth > max_depth)
                max_depth = res.depth;
            if (ret == 0 && res.found) {
                if (res.value_len == strlen(expect) + 1 &&
                  memcmp(res.value, expect, res.value_len) == 0)
                    ++nfound;
                else {
                    ++nmismatch;
                    if (nmismatch < 5)
                        printf("mismatch %s: got %.*s\n", key, (int)res.value_len, res.value);
                }
            } else if (ret == RET_NOTFOUND) {
                ++nmissing;
                if (nmissing < 5)
                    printf("missing: %s\n", key);
            } else {
                ++nerror;
                if (nerror < 5)
                    printf("error %d on key %s\n", ret, key);
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        elapsed_ns = (uint64_t)(end_ts.tv_sec - start_ts.tv_sec) * 1000000000 +
          (uint64_t)(end_ts.tv_nsec - start_ts.tv_nsec);
        printf("verify: %u keys, %u ok, %u missing, %u mismatch, %u error, max depth %d, "
               "%.2f us/op\n",
          nkeys, nfound, nmissing, nmismatch, nerror, max_depth,
          (double)elapsed_ns / 1000.0 / nkeys);
        if (nmissing != 0 || nmismatch != 0 || nerror != 0)
            return (1);
    } else {
        fprintf(stderr, "unknown mode %s\n", argv[3]);
        return (1);
    }
    return (0);
}
