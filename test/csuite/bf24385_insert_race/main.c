/*-
 * Public Domain 2014-present MongoDB, Inc.
 * Public Domain 2008-2014 WiredTiger, Inc.
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "test_util.h"

#define NUM_RECORDS 1000000
#define NUM_THREADS 20

typedef struct {
    TEST_OPTS *opts;
    uint64_t thread_dx;
} TEST_OPTS_INSERT;
/*
 * JIRA ticket reference: TODO
 */

void *thread_insert_race(void *);

static uint64_t ready_counter;

/*
 * set_key --
 *     Wrapper providing the correct typing for the WT_CURSOR::set_key variadic argument.
 */
static void
set_key(WT_CURSOR *c, uint64_t value)
{
    c->set_key(c, value);
}

/*
 * set_value --
 *     Wrapper providing the correct typing for the WT_CURSOR::set_value variadic argument.
 */
static void
set_value(TEST_OPTS *opts, WT_CURSOR *c, uint64_t value)
{
    if (opts->table_type == TABLE_FIX)
        c->set_value(c, (uint8_t)value);
    else
        c->set_value(c, value);
}

/*
 * get_value --
 *     Wrapper providing the correct typing for the WT_CURSOR::get_value variadic argument.
 */
static uint64_t
get_value(TEST_OPTS *opts, WT_CURSOR *c)
{
    uint64_t value64;
    uint8_t value8;

    if (opts->table_type == TABLE_FIX) {
        testutil_check(c->get_value(c, &value8));
        return (value8);
    } else {
        testutil_check(c->get_value(c, &value64));
        return (value64);
    }
}

/*
 * main --
 *     TODO: Add a comment describing this function.
 */
int
main(int argc, char *argv[])
{
    TEST_OPTS *opts, _opts;
    WT_CURSOR *c;
    WT_SESSION *session;
    clock_t ce, cs;
    pthread_t id[100];
    int i, ret;
    char tableconf[128];
    TEST_OPTS_INSERT opt_ins[NUM_THREADS];
    uint64_t val, prev_val;
    bool prev_val_valid = false;

    opts = &_opts;
    memset(opts, 0, sizeof(*opts));
    opts->nthreads = NUM_THREADS;
    opts->nrecords = NUM_RECORDS;
    opts->table_type = TABLE_ROW;
    testutil_check(testutil_parse_opts(argc, argv, opts));
    testutil_make_work_dir(opts->home);

    testutil_check(wiredtiger_open(opts->home, NULL,
      "create,cache_size=2G,eviction=(threads_max=5),statistics=(fast)", &opts->conn));
    testutil_check(opts->conn->open_session(opts->conn, NULL, NULL, &session));
    testutil_check(__wt_snprintf(tableconf, sizeof(tableconf),
      "key_format=%s,value_format=%s,leaf_page_max=32k,", opts->table_type == TABLE_ROW ? "Q" : "r",
      opts->table_type == TABLE_FIX ? "8t" : "Q"));
    testutil_check(session->create(session, opts->uri, tableconf));

    cs = clock();
    
    /* Multithreaded insert */
    for (i = 0; i < (int)opts->nthreads; ++i) {
        opt_ins[i].opts = opts;
        opt_ins[i].thread_dx = (uint64_t)i;
        testutil_check(pthread_create(&id[i], NULL, thread_insert_race, &opt_ins[i]));
    }
    while (--i >= 0)
        testutil_check(pthread_join(id[i], NULL));

    /* Reopen connection for WT_SESSION::verify. It requires exclusive access to the file. */
    testutil_check(opts->conn->close(opts->conn, NULL));
    opts->conn = NULL;
    testutil_check(wiredtiger_open(opts->home, NULL,
      "create,cache_size=2G,eviction=(threads_max=5),statistics=(fast)", &opts->conn));

    /* Validate */
    testutil_check(opts->conn->open_session(opts->conn, NULL, NULL, &session));
    testutil_check(session->verify(session, opts->uri, NULL));

    testutil_check(session->open_cursor(session, opts->uri, NULL, NULL, &c));
    i = 0;
    while ((ret = c->next(c)) == 0) {
        val = get_value(opts, c);
        if (prev_val_valid)
            testutil_assert(val == (prev_val + 1));
        else
            testutil_assert(val == 1);

        prev_val = val;
        prev_val_valid = true;
        i++;
    }

    testutil_assert(ret == WT_NOTFOUND);
    testutil_assert(i == NUM_RECORDS);

    ce = clock();
    printf("Number of records: %" PRIu64 "\nDuration: %.2lf\n", opts->nrecords, (ce - cs) / (double)CLOCKS_PER_SEC);

    testutil_cleanup(opts);
    return (EXIT_SUCCESS);
}

/*
 * thread_insert_race --
 *     Append to a table in a "racy" fashion - that is attempt to insert the same record another
 *     thread is likely to also be inserting.
 */
void *
thread_insert_race(void *arg)
{
    TEST_OPTS_INSERT *opts_insert;
    TEST_OPTS *opts;
    WT_CONNECTION *conn;
    WT_CURSOR *cursor;
    WT_DECL_RET;
    WT_SESSION *session;
    uint64_t i, ready_counter_local, thread_dx;

    opts_insert = (TEST_OPTS_INSERT *)arg;
    opts = opts_insert->opts;
    thread_dx = opts_insert->thread_dx;
    conn = opts->conn;

    printf("Running insert thread\n");

    testutil_check(conn->open_session(conn, NULL, NULL, &session));
    testutil_check(session->open_cursor(session, opts->uri, NULL, NULL, &cursor));

    /* Wait until all the threads are ready to go. */
    (void)__wt_atomic_add64(&ready_counter, 1);
    for (;; __wt_yield()) {
        WT_ORDERED_READ(ready_counter_local, ready_counter);
        if (ready_counter_local >= opts->nthreads)
            break;
    }

    for (i = 0; i < opts->nrecords; i += opts->nthreads) {
        testutil_check(session->begin_transaction(session, "isolation=snapshot"));

        set_key(cursor, i + thread_dx + 1);
        set_value(opts, cursor, i + thread_dx + 1);
        
        if ((ret = cursor->insert(cursor)) != 0) {
            if (ret == WT_ROLLBACK) {
                testutil_check(session->rollback_transaction(session, NULL));
                i--;
                continue;
            }
            printf("Error in insert: %d\n", ret);
        }
        testutil_check(session->commit_transaction(session, NULL));
    }

    return (NULL);
}
