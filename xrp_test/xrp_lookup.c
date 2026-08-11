/*
 * xrp_lookup: drive the wt_btree_bpf XRP program against a WiredTiger file.
 *
 * Discovers the root page address from the WiredTiger metadata, loads the BPF
 * program, then performs point lookups with the read_xrp syscall and reports
 * the results from the scratch buffer.
 *
 * usage:
 *   xrp_lookup <home> <file.wt> <wt_btree_bpf.o> get <key>
 *   xrp_lookup <home> <file.wt> <wt_btree_bpf.o> verify <nkeys>
 *   xrp_lookup <home> <file.wt> <wt_btree_bpf.o> bench <nkeys> <nthreads> <seconds>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <wiredtiger.h>

#define __NR_read_xrp 445

#define BTREE_BLOCK_SIZE 512
#define BTREE_KEY_MAX_LEN 18
#define BTREE_VALUE_MAX_LEN 128
#define BUFFER_SIZE 4096

#define BTREE_FOUND 0
#define BTREE_NOTFOUND 1

#define POS_1BYTE_MARKER ((uint8_t)0x80)
#define POS_2BYTE_MARKER ((uint8_t)0xc0)
#define POS_MULTI_MARKER ((uint8_t)0xe0)
#define POS_1BYTE_MAX ((1 << 6) - 1)
#define POS_2BYTE_MAX ((1 << 13) + POS_1BYTE_MAX)

#define GET_BITS(x, start, end) (((uint64_t)(x) & ((1U << (start)) - 1U)) >> (end))

/* Must match struct wt_btree_scratch in bpf_prog/wt_btree_bpf.c. */
struct wt_btree_scratch {
    uint64_t key_size;
    char key[BTREE_KEY_MAX_LEN];

    int32_t state;
    int32_t nr_page;
    uint64_t value_size;
    char value[BTREE_VALUE_MAX_LEN];
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
        return (-1);
    }
    *pp = p;
    return (0);
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

/*
 * One point lookup through the read_xrp syscall.
 */
static int
xrp_lookup(int fd, int bpf_fd, uint64_t root_offset, const char *key, size_t key_len,
  uint8_t *data_buf, uint8_t *scratch_buf, struct wt_btree_scratch **resp)
{
    struct wt_btree_scratch *scratch;
    long ret;

    scratch = (struct wt_btree_scratch *)scratch_buf;
    if (key_len > BTREE_KEY_MAX_LEN) {
        fprintf(stderr, "key too long\n");
        return (-1);
    }

    memset(data_buf, 0, BUFFER_SIZE);
    memset(scratch_buf, 0, BUFFER_SIZE);
    scratch->key_size = key_len;
    memcpy(scratch->key, key, key_len);
    scratch->state = -1;

    ret = syscall(
      __NR_read_xrp, fd, data_buf, BTREE_BLOCK_SIZE, (off_t)root_offset, bpf_fd, scratch_buf);
    if (ret != BTREE_BLOCK_SIZE) {
        fprintf(stderr, "read_xrp: ret %ld errno %d\n", ret, errno);
        return (-1);
    }
    *resp = scratch;
    return (0);
}

static struct {
    int fd, bpf_fd;
    uint64_t root_offset;
    uint32_t nkeys;
    volatile int stop;
    atomic_ulong ops, errors;
} bench_state;

static void *
bench_worker(void *varg)
{
    struct wt_btree_scratch *res;
    unsigned int seed;
    uint32_t k;
    uint8_t *data_buf, *scratch_buf;
    char expect[32], key[32];

    seed = (unsigned int)(0x85ebca6bu * (uint32_t)((uintptr_t)varg + 1));
    data_buf = aligned_alloc(BUFFER_SIZE, BUFFER_SIZE);
    scratch_buf = aligned_alloc(BUFFER_SIZE, BUFFER_SIZE);
    if (data_buf == NULL || scratch_buf == NULL)
        return (NULL);
    while (!bench_state.stop) {
        k = (uint32_t)rand_r(&seed) % bench_state.nkeys;
        snprintf(key, sizeof(key), "%08u", k);
        snprintf(expect, sizeof(expect), "V%08u-%06x", k, k * 7919u);
        if (xrp_lookup(bench_state.fd, bench_state.bpf_fd, bench_state.root_offset, key,
              strlen(key) + 1, data_buf, scratch_buf, &res) == 0 &&
          res->state == BTREE_FOUND && res->value_size == strlen(expect) + 1 &&
          memcmp(res->value, expect, res->value_size) == 0)
            atomic_fetch_add(&bench_state.ops, 1);
        else
            atomic_fetch_add(&bench_state.errors, 1);
    }
    return (NULL);
}

static int
run_bench(int fd, int bpf_fd, uint64_t root_offset, uint32_t nkeys, uint32_t nthreads,
  uint32_t seconds)
{
    pthread_t *threads;
    uint64_t ops;
    uint32_t i;

    bench_state.fd = fd;
    bench_state.bpf_fd = bpf_fd;
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
    return (0);
}

int
main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct wt_btree_scratch *res;
    uint64_t root_offset, root_size;
    int bpf_fd, fd, ret;
    uint8_t *data_buf, *scratch_buf;
    char path[512];

    if (argc < 6) {
        fprintf(stderr,
          "usage: %s <home> <file.wt> <bpf.o> get <key> | verify <nkeys>\n", argv[0]);
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

    if ((ret = bpf_prog_load(argv[3], BPF_PROG_TYPE_XRP, &obj, &bpf_fd)) != 0) {
        fprintf(stderr, "bpf_prog_load %s: %d\n", argv[3], ret);
        return (1);
    }

    snprintf(path, sizeof(path), "%s/%s", argv[1], argv[2]);
    if ((fd = open(path, O_RDONLY | O_DIRECT)) < 0) {
        perror("open");
        return (1);
    }

    data_buf = aligned_alloc(BUFFER_SIZE, BUFFER_SIZE);
    scratch_buf = aligned_alloc(BUFFER_SIZE, BUFFER_SIZE);
    if (data_buf == NULL || scratch_buf == NULL) {
        fprintf(stderr, "aligned_alloc failed\n");
        return (1);
    }

    if (strcmp(argv[4], "bench") == 0 && argc >= 8)
        return (run_bench(fd, bpf_fd, root_offset, (uint32_t)strtoul(argv[5], NULL, 10),
          (uint32_t)strtoul(argv[6], NULL, 10), (uint32_t)strtoul(argv[7], NULL, 10)));

    if (strcmp(argv[4], "get") == 0) {
        const char *key = argv[5];
        if (xrp_lookup(fd, bpf_fd, root_offset, key, strlen(key) + 1, data_buf, scratch_buf,
              &res) != 0)
            return (1);
        if (res->state == BTREE_FOUND)
            printf("found (pages %d): %.*s\n", res->nr_page, (int)res->value_size, res->value);
        else if (res->state == BTREE_NOTFOUND)
            printf("not found (pages %d)\n", res->nr_page);
        else {
            printf("bad state %d (pages %d)\n", res->state, res->nr_page);
            return (1);
        }
    } else if (strcmp(argv[4], "verify") == 0) {
        struct timespec start_ts, end_ts;
        uint64_t elapsed_ns;
        uint32_t i, nkeys, nfound, nmissing, nmismatch, nerror;
        int max_pages;
        char key[32], expect[32];

        nkeys = (uint32_t)strtoul(argv[5], NULL, 10);
        nfound = nmissing = nmismatch = nerror = 0;
        max_pages = 0;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        for (i = 0; i < nkeys; ++i) {
            snprintf(key, sizeof(key), "%08u", i);
            snprintf(expect, sizeof(expect), "V%08u-%06x", i, i * 7919u);
            if (xrp_lookup(fd, bpf_fd, root_offset, key, strlen(key) + 1, data_buf,
                  scratch_buf, &res) != 0) {
                ++nerror;
                if (nerror < 5)
                    printf("syscall error on key %s\n", key);
                continue;
            }
            if (res->nr_page > max_pages)
                max_pages = res->nr_page;
            if (res->state == BTREE_FOUND) {
                if (res->value_size == strlen(expect) + 1 &&
                  memcmp(res->value, expect, res->value_size) == 0)
                    ++nfound;
                else {
                    ++nmismatch;
                    if (nmismatch < 5)
                        printf(
                          "mismatch %s: got %.*s\n", key, (int)res->value_size, res->value);
                }
            } else if (res->state == BTREE_NOTFOUND) {
                ++nmissing;
                if (nmissing < 5)
                    printf("missing: %s\n", key);
            } else {
                ++nerror;
                if (nerror < 5)
                    printf("bad state %d on key %s\n", res->state, key);
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        elapsed_ns = (uint64_t)(end_ts.tv_sec - start_ts.tv_sec) * 1000000000 +
          (uint64_t)(end_ts.tv_nsec - start_ts.tv_nsec);
        printf("verify: %u keys, %u ok, %u missing, %u mismatch, %u error, max pages %d, "
               "%.2f us/op\n",
          nkeys, nfound, nmissing, nmismatch, nerror, max_pages,
          (double)elapsed_ns / 1000.0 / nkeys);
        if (nmissing != 0 || nmismatch != 0 || nerror != 0)
            return (1);
    } else {
        fprintf(stderr, "unknown mode %s\n", argv[4]);
        return (1);
    }
    return (0);
}
