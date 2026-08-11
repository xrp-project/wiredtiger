/*
 * rw_bench: multithreaded 50/50 read/write soundness test for the XRP B-tree
 * pushdown.
 *
 * Values are self-validating: "<key>|<version-hex>|<checksum-hex>". A reader
 * can verify any committed version of a key without knowing which one it
 * should see. The soundness properties checked are:
 *
 *   1. every value returned for a key embeds that exact key and a valid
 *      checksum (no wrong-page, torn or garbage reads);
 *   2. base keys are never reported missing (no lost keys under splits,
 *      eviction, checkpoints or block reuse);
 *   3. keys from a reserved never-written range are never reported found.
 *
 * Writers update existing keys and insert new keys interleaved between the
 * base keys, forcing leaf splits across the whole tree. A checkpointer
 * reconciles the tree to disk on an interval, exercising the cache prefix
 * property against a moving disk image.
 *
 * usage:
 *   rw_bench <home> init <nkeys> [nthreads]
 *   rw_bench <home> run <nkeys> <seconds> <nthreads> <write_pct> [cache_mb] [warm]
 *
 * Every thread runs a mixed workload: each operation is a write with
 * write_pct percent probability, otherwise a validated read. With "warm", a
 * full sequential scan runs before the timed phase; the scan uses the normal
 * read path and loads the internal levels into the cache.
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <wiredtiger.h>

#define URI "file:xrp_test.wt"

static const char *table_config =
  "key_format=S,value_format=S,"
  "allocation_size=512,internal_page_max=512,leaf_page_max=512,"
  "checksum=on";

static WT_CONNECTION *conn;
static uint32_t nkeys, write_pct;
static volatile int stop_flag;

static atomic_ulong version_counter;
static atomic_ulong reads_found, reads_notfound, writes_updates, writes_inserts;
static atomic_ulong rollbacks;
static atomic_ulong fail_bad_value, fail_missing_base, fail_found_reserved, fail_hard;
static atomic_ulong fail_prints;

#define FAIL_PRINT_MAX 20

static uint32_t
val_csum(const char *key, uint64_t version)
{
    uint32_t h;
    const char *p;

    h = 2166136261u;
    for (p = key; *p != '\0'; ++p)
        h = (h ^ (uint8_t)*p) * 16777619u;
    h = (h ^ (uint32_t)(version & 0xffffffffu)) * 16777619u;
    h = (h ^ (uint32_t)(version >> 32)) * 16777619u;
    return (h);
}

static void
make_value(char *buf, size_t buf_size, const char *key)
{
    uint64_t version;

    version = atomic_fetch_add(&version_counter, 1);
    snprintf(buf, buf_size, "%s|%012llx|%08x", key, (unsigned long long)version,
      val_csum(key, version));
}

/*
 * Check a value returned for a key: exact key match and checksum over the
 * embedded version.
 */
static int
check_value(const char *key, const char *value)
{
    unsigned long long version;
    unsigned int csum;
    char vkey[32];

    if (sscanf(value, "%31[^|]|%12llx|%8x", vkey, &version, &csum) != 3)
        return (-1);
    if (strcmp(vkey, key) != 0)
        return (-1);
    if (csum != val_csum(key, (uint64_t)version))
        return (-1);
    return (0);
}

static void
report_failure(const char *what, const char *key, const char *value)
{
    if (atomic_fetch_add(&fail_prints, 1) < FAIL_PRINT_MAX)
        printf("FAILURE: %s key=%s value=%s\n", what, key, value == NULL ? "(none)" : value);
}

struct thread_arg {
    int id;
};

/*
 * Base keys: "%08u" in [0, nkeys). Inserted keys: base key plus an "x"
 * suffix, sorting immediately after their base key, spreading splits across
 * the whole tree. Reserved keys: "z%07u", never written.
 */
static void *
worker(void *varg)
{
    struct thread_arg *arg;
    WT_CURSOR *cursor;
    WT_SESSION *session;
    const char *got;
    unsigned int seed;
    uint32_t k, op;
    int ret;
    char key[32], value[64];

    arg = varg;
    seed = (unsigned int)(0x9e3779b9u * (uint32_t)(arg->id + 1));

    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0) {
        printf("worker %d: open_session: %s\n", arg->id, wiredtiger_strerror(ret));
        atomic_fetch_add(&fail_hard, 1);
        return (NULL);
    }
    if ((ret = session->open_cursor(session, URI, NULL, getenv("RW_CURSOR_CONF"), &cursor)) !=
      0) {
        printf("worker %d: open_cursor: %s\n", arg->id, wiredtiger_strerror(ret));
        atomic_fetch_add(&fail_hard, 1);
        return (NULL);
    }

    while (!stop_flag) {
        op = (uint32_t)rand_r(&seed);
        k = (uint32_t)rand_r(&seed) % nkeys;

        if ((uint32_t)rand_r(&seed) % 100 < write_pct) {
            if (op % 100 < 80)
                snprintf(key, sizeof(key), "%08u", k);
            else
                snprintf(key, sizeof(key), "%08ux", k);
            make_value(value, sizeof(value), key);
            cursor->set_key(cursor, key);
            cursor->set_value(cursor, value);
            ret = cursor->insert(cursor);
            if (ret == 0) {
                if (op % 100 < 80)
                    atomic_fetch_add(&writes_updates, 1);
                else
                    atomic_fetch_add(&writes_inserts, 1);
            } else if (ret == WT_ROLLBACK)
                atomic_fetch_add(&rollbacks, 1);
            else {
                atomic_fetch_add(&fail_hard, 1);
                report_failure(wiredtiger_strerror(ret), key, NULL);
            }
            cursor->reset(cursor);
        } else {
            if (op % 100 < 90) {
                /* base key, must exist */
                snprintf(key, sizeof(key), "%08u", k);
                cursor->set_key(cursor, key);
                ret = cursor->search(cursor);
                if (ret == 0) {
                    if (cursor->get_value(cursor, &got) != 0 || check_value(key, got) != 0) {
                        atomic_fetch_add(&fail_bad_value, 1);
                        report_failure("bad value", key, got);
                    } else
                        atomic_fetch_add(&reads_found, 1);
                } else if (ret == WT_NOTFOUND) {
                    atomic_fetch_add(&fail_missing_base, 1);
                    report_failure("missing base key", key, NULL);
                } else if (ret == WT_ROLLBACK)
                    atomic_fetch_add(&rollbacks, 1);
                else {
                    atomic_fetch_add(&fail_hard, 1);
                    report_failure(wiredtiger_strerror(ret), key, NULL);
                }
            } else if (op % 100 < 95) {
                /* maybe-inserted key, must validate if present */
                snprintf(key, sizeof(key), "%08ux", k);
                cursor->set_key(cursor, key);
                ret = cursor->search(cursor);
                if (ret == 0) {
                    if (cursor->get_value(cursor, &got) != 0 || check_value(key, got) != 0) {
                        atomic_fetch_add(&fail_bad_value, 1);
                        report_failure("bad value", key, got);
                    } else
                        atomic_fetch_add(&reads_found, 1);
                } else if (ret == WT_NOTFOUND)
                    atomic_fetch_add(&reads_notfound, 1);
                else if (ret == WT_ROLLBACK)
                    atomic_fetch_add(&rollbacks, 1);
                else {
                    atomic_fetch_add(&fail_hard, 1);
                    report_failure(wiredtiger_strerror(ret), key, NULL);
                }
            } else {
                /* reserved key, must never exist */
                snprintf(key, sizeof(key), "z%07u", k % 10000000);
                cursor->set_key(cursor, key);
                ret = cursor->search(cursor);
                if (ret == 0) {
                    cursor->get_value(cursor, &got);
                    atomic_fetch_add(&fail_found_reserved, 1);
                    report_failure("found reserved key", key, got);
                } else if (ret == WT_NOTFOUND)
                    atomic_fetch_add(&reads_notfound, 1);
                else if (ret == WT_ROLLBACK)
                    atomic_fetch_add(&rollbacks, 1);
                else {
                    atomic_fetch_add(&fail_hard, 1);
                    report_failure(wiredtiger_strerror(ret), key, NULL);
                }
            }
            cursor->reset(cursor);
        }
    }

    session->close(session, NULL);
    return (NULL);
}

static void *
checkpointer(void *varg)
{
    WT_SESSION *session;
    int i, ret;

    (void)varg;
    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0) {
        printf("checkpointer: open_session: %s\n", wiredtiger_strerror(ret));
        return (NULL);
    }
    while (!stop_flag) {
        for (i = 0; i < 10 && !stop_flag; ++i)
            sleep(1);
        if (stop_flag)
            break;
        if ((ret = session->checkpoint(session, NULL)) != 0) {
            printf("checkpoint: %s\n", wiredtiger_strerror(ret));
            atomic_fetch_add(&fail_hard, 1);
        }
    }
    session->close(session, NULL);
    return (NULL);
}

struct init_arg {
    uint32_t lo, hi;
    int failed;
};

static void *
init_worker(void *varg)
{
    struct init_arg *arg;
    WT_CURSOR *cursor;
    WT_SESSION *session;
    uint32_t i;
    int ret;
    char key[32], value[64];

    arg = varg;
    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0 ||
      (ret = session->open_cursor(session, URI, NULL, NULL, &cursor)) != 0) {
        fprintf(stderr, "init worker: %s\n", wiredtiger_strerror(ret));
        arg->failed = 1;
        return (NULL);
    }
    for (i = arg->lo; i < arg->hi; ++i) {
        snprintf(key, sizeof(key), "%08u", i);
        make_value(value, sizeof(value), key);
        cursor->set_key(cursor, key);
        cursor->set_value(cursor, value);
        while ((ret = cursor->insert(cursor)) == WT_ROLLBACK)
            ;
        if (ret != 0) {
            fprintf(stderr, "insert %s: %s\n", key, wiredtiger_strerror(ret));
            arg->failed = 1;
            return (NULL);
        }
    }
    session->close(session, NULL);
    return (NULL);
}

static int
do_init(const char *home, uint32_t n, uint32_t nthreads)
{
    struct init_arg *args;
    pthread_t *threads;
    WT_SESSION *session;
    struct timespec start_ts, end_ts;
    uint32_t i, per;
    int failed, ret;

    if ((ret = wiredtiger_open(home, NULL, "create,cache_size=2GB", &conn)) != 0) {
        fprintf(stderr, "wiredtiger_open: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0)
        return (1);
    if ((ret = session->create(session, URI, table_config)) != 0) {
        fprintf(stderr, "create: %s\n", wiredtiger_strerror(ret));
        return (1);
    }

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    threads = calloc(nthreads, sizeof(*threads));
    args = calloc(nthreads, sizeof(*args));
    per = n / nthreads;
    for (i = 0; i < nthreads; ++i) {
        args[i].lo = i * per;
        args[i].hi = i == nthreads - 1 ? n : (i + 1) * per;
        pthread_create(&threads[i], NULL, init_worker, &args[i]);
    }
    failed = 0;
    for (i = 0; i < nthreads; ++i) {
        pthread_join(threads[i], NULL);
        failed += args[i].failed;
    }
    if (failed != 0)
        return (1);

    if ((ret = session->checkpoint(session, NULL)) != 0) {
        fprintf(stderr, "checkpoint: %s\n", wiredtiger_strerror(ret));
        return (1);
    }
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    if ((ret = conn->close(conn, NULL)) != 0)
        return (1);
    printf("initialized %u keys with %u threads in %lds\n", n, nthreads,
      (long)(end_ts.tv_sec - start_ts.tv_sec));
    return (0);
}

/*
 * Post-run validation: a sequential walk of the whole table. Every value must
 * validate against its key and the number of base keys seen must be exactly
 * nkeys (base keys are 8 digits with no suffix).
 */
static int
final_scan(void)
{
    WT_CURSOR *cursor;
    WT_SESSION *session;
    const char *got, *key;
    uint64_t nbase, nrows;
    uint32_t bad;
    int ret;

    if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0)
        return (-1);
    if ((ret = session->open_cursor(session, URI, NULL, NULL, &cursor)) != 0)
        return (-1);
    bad = 0;
    nbase = nrows = 0;
    while ((ret = cursor->next(cursor)) == 0) {
        ++nrows;
        if (cursor->get_key(cursor, &key) != 0 || cursor->get_value(cursor, &got) != 0 ||
          check_value(key, got) != 0) {
            ++bad;
            if (bad < 10)
                printf("final scan failure: key=%s value=%s\n", key == NULL ? "?" : key,
                  got == NULL ? "?" : got);
            continue;
        }
        if (strlen(key) == 8)
            ++nbase;
    }
    if (ret != WT_NOTFOUND) {
        printf("final scan: next failed: %s\n", wiredtiger_strerror(ret));
        ++bad;
    }
    cursor->close(cursor);
    session->close(session, NULL);
    printf("final scan: %llu rows, %llu base keys (expected %u), %u bad\n",
      (unsigned long long)nrows, (unsigned long long)nbase, nkeys, bad);
    return (bad == 0 && nbase == nkeys ? 0 : -1);
}

int
main(int argc, char **argv)
{
    struct thread_arg *args;
    pthread_t *threads, ckpt_thread;
    uint64_t total_fail;
    struct timespec run_start, run_end;
    uint64_t run_ns, total_ops;
    uint32_t cache_mb, duration, elapsed, i, nthreads;
    int ret, scan_ret, warm;
    char config[256];

    if (argc < 4) {
        fprintf(stderr,
          "usage: %s <home> init <nkeys> | run <nkeys> <seconds> <nreaders> <nwriters> "
          "[cache_mb]\n",
          argv[0]);
        return (1);
    }
    nkeys = (uint32_t)strtoul(argv[3], NULL, 10);

    if (strcmp(argv[2], "init") == 0)
        return (do_init(argv[1], nkeys, argc > 4 ? (uint32_t)strtoul(argv[4], NULL, 10) : 1));

    if (strcmp(argv[2], "run") != 0 || argc < 7) {
        fprintf(stderr, "bad arguments\n");
        return (1);
    }
    duration = (uint32_t)strtoul(argv[4], NULL, 10);
    nthreads = (uint32_t)strtoul(argv[5], NULL, 10);
    write_pct = (uint32_t)strtoul(argv[6], NULL, 10);
    cache_mb = argc > 7 ? (uint32_t)strtoul(argv[7], NULL, 10) : 16;
    warm = argc > 8 && strcmp(argv[8], "warm") == 0;

    {
        const char *extra = getenv("RW_EXTRA_CONF");
        snprintf(config, sizeof(config),
          "cache_size=%uMB,direct_io=[data],buffer_alignment=512B,mmap=false%s%s", cache_mb,
          extra != NULL ? "," : "", extra != NULL ? extra : "");
    }
    if ((ret = wiredtiger_open(argv[1], NULL, config, &conn)) != 0) {
        fprintf(stderr, "wiredtiger_open: %s\n", wiredtiger_strerror(ret));
        return (1);
    }

    if (warm) {
        WT_CURSOR *scan_cursor;
        WT_SESSION *scan_session;
        uint64_t scanned = 0;

        if ((ret = conn->open_session(conn, NULL, NULL, &scan_session)) != 0 ||
          (ret = scan_session->open_cursor(scan_session, URI, NULL, NULL, &scan_cursor)) != 0) {
            fprintf(stderr, "warmup: %s\n", wiredtiger_strerror(ret));
            return (1);
        }
        while ((ret = scan_cursor->next(scan_cursor)) == 0)
            ++scanned;
        if (ret != WT_NOTFOUND) {
            fprintf(stderr, "warmup scan: %s\n", wiredtiger_strerror(ret));
            return (1);
        }
        scan_session->close(scan_session, NULL);
        printf("warmup scan: %llu rows\n", (unsigned long long)scanned);
        fflush(stdout);
    }

    clock_gettime(CLOCK_MONOTONIC, &run_start);
    threads = calloc(nthreads, sizeof(*threads));
    args = calloc(nthreads, sizeof(*args));
    for (i = 0; i < nthreads; ++i) {
        args[i].id = (int)i;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }
    pthread_create(&ckpt_thread, NULL, checkpointer, NULL);

    for (elapsed = 0; elapsed < duration; elapsed += 30) {
        sleep(30);
        printf("[%4us] reads_found=%lu reads_notfound=%lu updates=%lu inserts=%lu "
               "rollbacks=%lu failures=%lu\n",
          elapsed + 30, atomic_load(&reads_found), atomic_load(&reads_notfound),
          atomic_load(&writes_updates), atomic_load(&writes_inserts), atomic_load(&rollbacks),
          atomic_load(&fail_bad_value) + atomic_load(&fail_missing_base) +
            atomic_load(&fail_found_reserved) + atomic_load(&fail_hard));
        fflush(stdout);
    }
    stop_flag = 1;
    for (i = 0; i < nthreads; ++i)
        pthread_join(threads[i], NULL);
    pthread_join(ckpt_thread, NULL);
    clock_gettime(CLOCK_MONOTONIC, &run_end);

    run_ns = (uint64_t)(run_end.tv_sec - run_start.tv_sec) * 1000000000 +
      (uint64_t)(run_end.tv_nsec - run_start.tv_nsec);
    total_ops = atomic_load(&reads_found) + atomic_load(&reads_notfound) +
      atomic_load(&writes_updates) + atomic_load(&writes_inserts) + atomic_load(&rollbacks);
    printf("---\n");
    printf("throughput: %.0f ops/s, per-thread latency: %.2f us/op\n",
      (double)total_ops * 1e9 / (double)run_ns,
      (double)run_ns / 1000.0 * nthreads / (double)total_ops);
    printf("reads_found: %lu\n", atomic_load(&reads_found));
    printf("reads_notfound: %lu\n", atomic_load(&reads_notfound));
    printf("writes_updates: %lu\n", atomic_load(&writes_updates));
    printf("writes_inserts: %lu\n", atomic_load(&writes_inserts));
    printf("rollbacks: %lu\n", atomic_load(&rollbacks));
    printf("fail_bad_value: %lu\n", atomic_load(&fail_bad_value));
    printf("fail_missing_base: %lu\n", atomic_load(&fail_missing_base));
    printf("fail_found_reserved: %lu\n", atomic_load(&fail_found_reserved));
    printf("fail_hard: %lu\n", atomic_load(&fail_hard));

    scan_ret = final_scan();

    total_fail = atomic_load(&fail_bad_value) + atomic_load(&fail_missing_base) +
      atomic_load(&fail_found_reserved) + atomic_load(&fail_hard);
    if ((ret = conn->close(conn, NULL)) != 0)
        fprintf(stderr, "conn close: %s\n", wiredtiger_strerror(ret));

    if (total_fail == 0 && scan_ret == 0)
        printf("SOUNDNESS: PASS\n");
    else
        printf("SOUNDNESS: FAIL (%llu failures, scan %d)\n", (unsigned long long)total_fail,
          scan_ret);
    return (total_fail == 0 && scan_ret == 0 ? 0 : 1);
}
