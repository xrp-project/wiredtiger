/*
 * MVP for memory sharing!
 *
 * Only allowed to use type definitions from 'wiredtiger.h'.
 * Meant to simulate an XDP program's environment in userspace, where it's
 * easier to debug!
 */

#include <pthread.h>
#include <stdlib.h>

///////////////////////////////////////////////////////////
// Wiredtiger helper functions and macros, ported to BPF //
///////////////////////////////////////////////////////////
#include "wiredtiger_internal.h"

// TODO: Include session implementation

#define bpf_printk(fmt, ...) printf(fmt, __VA_ARGS__)


// include/cursor.i

static inline int
__cursor_enter(WT_SESSION_IMPL *session)
{
    /*
     * Skip cache check here.
     */
    // if (session->ncursors == 0)
    //     WT_RET(__wt_cache_eviction_check(session, false, false, NULL));
    ++session->ncursors;
    return (0);
}

static inline void
__cursor_leave(WT_SESSION_IMPL *session)
{
    /* Decrement the count of active cursors in the session. */
    WT_ASSERT(session, session->ncursors > 0);
    --session->ncursors;
}

// src/lsm/lsm_cursor.c

#define WT_FORALL_CURSORS(clsm, c, i)     \
    for ((i) = (clsm)->nchunks; (i) > 0;) \
        if (((c) = (clsm)->chunks[--(i)]->cursor) != NULL)

// Misc

#define __wt_err(session, error, ...) bpf_printk(__VA__ARGS)

#define WT_RET(a)               \
    do {                        \
        int __ret;              \
        if ((__ret = (a)) != 0) \
            return (__ret);     \
    } while (0)

#define WT_RET_MSG(session, v, ...)            \
    do {                                       \
        int __ret = (v);                       \
        __wt_err(session, __ret, __VA_ARGS__); \
        return (__ret);                        \
    } while (0)

#define RET_MSG(ret, ...)               \
    do {                                \
        int __ret = (ret);              \
        fprintf("Error code: %d", ret); \
        fprintf(__VA__ARGS__);          \
        fprintf("\n");                  \
        return (__ret);                 \
    } while (0)

static inline int
__wt_txn_context_prepare_check(WT_SESSION_IMPL *session)
{
    if (F_ISSET(session->txn, WT_TXN_PREPARE))
        WT_RET_MSG(session, EINVAL, "not permitted in a prepared transaction");
    return (0);
}

static inline void
__cursor_novalue(WT_CURSOR *cursor)
{
    F_CLR(cursor, WT_CURSTD_VALUE_INT);
}


///////////////////////
// Main BPF function //
///////////////////////

struct thread_fn_args {
    WT_CONNECTION *conn;
    WT_SESSION *session;
    WT_CURSOR *cursor;
};

void *thread_fn(void *arg) {
    struct thread_fn_args *args;
    args = (struct thread_fn_args *)arg;
    WT_SESSION_IMPL session = (WT_SESSION_IMPL *) args->cursor->session;
    // Logic...
    // simulate_bpf_read(args->conn, session, args->cursor);

    printf("Simulating read from BPF!\n\n");
}

// int simulate_bpf_read(WT_CONNECTION *conn, WT_SESSION_IMPL *session,
//                        WT_CURSOR *cursor) {

//     // TODO: Use WT_SESSION_IMPL

//     ///////////////////
//     // __clsm_search //
//     ///////////////////

//     WT_CURSOR_LSM *clsm;
//     clsm = (WT_CURSOR_LSM *)cursor;

//     int __prepare_ret;
//     __prepare_ret = __wt_txn_context_prepare_check(session);
//     WT_RET(__prepare_ret);
//     if (F_ISSET(cursor, WT_CURSTD_CACHED)) RET_MSG(-1, "cursor is cached! aborting!");
//     if (!F_ISSET(cursor, WT_CURSTD_KEY_SET)) RET_MSG(-1, "need to set key on cursor!");
//     __cursor_novalue(cursor);
//     // __clsm_enter
//     if (clsm->dsk_gen != lsm_tree->dsk_gen && lsm_tree->nchunks != 0) RET_MSG(-1, "need to re-open cursor on lsm tree!");
//     if (!F_ISSET(clsm, WT_CLSM_ACTIVE)) {
//         ++session->ncursors;
//         WT_RET(__cursor_enter(session));
//         F_SET(clsm, WT_CLSM_ACTIVE);
//     }
//     F_CLR(clsm, WT_CLSM_ITERATE_NEXT | WT_CLSM_ITERATE_PREV);


//     ///////////////////
//     // __clsm_lookup //
//     ///////////////////

//     WT_CURSOR *c = NULL;
//     WT_FORALL_CURSORS(clsm, c, i)
//     {
//         // Skip bloom filters for now!


//     }

//     // __clsm_leave
//     if (F_ISSET(clsm, WT_CLSM_ACTIVE)) {
//         --session->ncursors;
//         __cursor_leave(session);
//         F_CLR(clsm, WT_CLSM_ACTIVE);
//     }

// }

inline void error(int exit_code, int return_code, char *msg) {
    printf("Return code: %d. Message: %s", return_code, msg);
    exit(exit_code);
}

int main() {
    // Create a connection, session and cursor
    const char *data_dir = "/tigerhome/directio";
    const char *conn_config =
        "create,direct_io=[data,checkpoint],buffer_alignment=512B,mmap=false,"
        "cache_size=128M,"
        "eviction_trigger=95,eviction_target=80,eviction=(threads_max=2,"
        "threads_min=2),statistics=("
        "fast)";
    const char *session_config = "isolation=read-uncommitted";
    const char *cursor_config = "";
    const char *table_name = "lsm:karaage";

    WT_CONNECTION *conn;
    WT_CURSOR *cursor;
    WT_SESSION *session;

    int ret = wiredtiger_open(data_dir, NULL, conn_config, &conn);
    if (ret) {
        error(1, ret, "Failed to open wiredtiger database");
    }

    // Once per process / thread: Open session and create table
    ret = conn->open_session(conn, NULL, session_config, &session);
    if (ret) {
        error(1, ret, "Failed to create wiredtiger db session");
    }

    // Once per thread: Create cursor to access data
    ret =
        session->open_cursor(session, table_name, NULL, cursor_config, &cursor);
    if (ret) {
        error(1, ret, "Failed to create wiredtiger db cursor");
    }

    // Create a child thread which simulates the BPF program.
    // Use threads as they share memory.
    pthread_t thread_id;
    struct thread_fn_args args = {
        .conn = conn,
        .cursor = cursor,
        .session = session,
    };
    int err = pthread_create(&thread_id, NULL, &thread_fn, (void *)&args);
    // Wait for thread to exit
    err = pthread_join(thread_id, NULL);
    if (err) {
        error(1, err, "Failed to join thread!");
    }
    return 0;
}
