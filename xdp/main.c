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
    // NOTE: Skip the cache check here.
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

#define WT_ERR(a)             \
    do {                      \
        if ((ret = (a)) != 0) \
            goto err;         \
    } while (0)

#define WT_ERR_MSG(session, v, ...)          \
    do {                                     \
        ret = (v);                           \
        printf("Return code: %d", ret);      \
        printf(__VA__ARGS__);                \
        goto err;                            \
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

/*
 * __wt_txn_autocommit_check --
 *     If an auto-commit transaction is required, start one.
 */
static inline int
__wt_txn_autocommit_check(WT_SESSION_IMPL *session)
{
    WT_TXN *txn;

    txn = session->txn;
    if (F_ISSET(txn, WT_TXN_AUTOCOMMIT)) {
        RET_MSG(-1, "__wt_txn_autocommit_check: Autocommit should not be set");
        // F_CLR(txn, WT_TXN_AUTOCOMMIT);
        // return (__wt_txn_begin(session, NULL));
    }
    return (0);
}

static inline void
__cursor_novalue(WT_CURSOR *cursor)
{
    F_CLR(cursor, WT_CURSTD_VALUE_INT);
}

/*
 * __wt_cursor_set_keyv --
 *     WT_CURSOR->set_key default implementation.
 */
int
__wt_cursor_set_keyv(WT_CURSOR *cursor, uint32_t flags, va_list ap)
{
    WT_DECL_RET;
    WT_ITEM *buf, *item, tmp;
    WT_SESSION_IMPL *session;
    size_t sz;
    const char *fmt, *str;
    va_list ap_copy;

    buf = &cursor->key;
    tmp.mem = NULL;

    // CURSOR_API_CALL(cursor, session, set_key, NULL);
    // WT_ERR(__cursor_copy_release(cursor));
    if (F_ISSET(cursor, WT_CURSTD_KEY_SET) && WT_DATA_IN_ITEM(buf)) {
        tmp = *buf;
        buf->mem = NULL;
        buf->memsize = 0;
    }

    F_CLR(cursor, WT_CURSTD_KEY_SET);

    if (WT_CURSOR_RECNO(cursor)) {
        if (LF_ISSET(WT_CURSTD_RAW)) {
            // We should never enter this
            RET_MSG(-1, "__wt_cursor_set_keyv: WT_CURSTD_RAW!");
            // item = va_arg(ap, WT_ITEM *);
            // WT_ERR(__wt_struct_unpack(session, item->data, item->size, "q", &cursor->recno));
        } else
            // Bloom filter code enters here
            cursor->recno = va_arg(ap, uint64_t);
        if (cursor->recno == WT_RECNO_OOB)
            WT_ERR_MSG(session, EINVAL, "%d is an invalid record number", WT_RECNO_OOB);
        buf->data = &cursor->recno;
        sz = sizeof(cursor->recno);
    } else {
        /* Fast path some common cases and special case WT_ITEMs. */
        fmt = cursor->key_format;
        if (LF_ISSET(WT_CURSOR_RAW_OK | WT_CURSTD_DUMP_JSON) || WT_STREQ(fmt, "u")) {
            // Used inside __clsm_lookup to copy key from clsm cursor to btree cursor
            item = va_arg(ap, WT_ITEM *);
            sz = item->size;
            buf->data = item->data;
        } else if (WT_STREQ(fmt, "S")) {
            // Used to point lsm cursor to user-provided string.
            // We won't enter this.
            RET_MSG(-1, "__wt_cursor_set_keyv: format=S!");
            // str = va_arg(ap, const char *);
            // sz = strlen(str) + 1;
            // buf->data = (void *)str;
        } else {
            // We should never enter this!
            RET_MSG(-1, "__wt_cursor_set_keyv: format=S!");
            // va_copy(ap_copy, ap);
            // ret = __wt_struct_sizev(session, &sz, cursor->key_format, ap_copy);
            // va_end(ap_copy);
            // WT_ERR(ret);

            // WT_ERR(__wt_buf_initsize(session, buf, sz));
            // WT_ERR(__wt_struct_packv(session, buf->mem, sz, cursor->key_format, ap));
        }
    }
    if (sz == 0)
        WT_ERR_MSG(session, EINVAL, "Empty keys not permitted");
    else if ((uint32_t)sz != sz)
        WT_ERR_MSG(session, EINVAL, "Key size (%lu) out of range", (uint64_t)sz);
    cursor->saved_err = 0;
    buf->size = sz;
    F_SET(cursor, WT_CURSTD_KEY_EXT);
    if (0) {
err:
        cursor->saved_err = ret;
    }

    /*
     * If we copied the key, either put the memory back into the cursor, or if we allocated some
     * memory in the meantime, free it.
     */
    if (tmp.mem != NULL) {
        // We should never enter here!
        RET_MSG(-1 "__wt_cursor_set_keyv: tmp.mem != NULL");
    //     if (buf->mem == NULL && !FLD_ISSET(S2C(session)->debug_flags, WT_CONN_DEBUG_CURSOR_COPY)) {
    //         buf->mem = tmp.mem;
    //         buf->memsize = tmp.memsize;
    //         F_SET(cursor, WT_CURSTD_DEBUG_COPY_KEY);
    //     } else
    //         __wt_free(session, tmp.mem);
    }
    // API_END_RET(session, ret);
}

void
__wt_cursor_set_key(WT_CURSOR *cursor, ...)
{
    va_list ap;

    va_start(ap, cursor);
    // WT_IGNORE_RET(__wt_cursor_set_keyv(cursor, cursor->flags, ap));
    __wt_cursor_set_keyv(cursor, cursor->flags, ap);
    va_end(ap);
}

/*
 * When returning an error, we need to restore the cursor to a valid state, the upper-level cursor
 * code is likely to retry. This structure and the associated functions are used save and restore
 * the cursor state.
 */
typedef struct {
    WT_ITEM key;
    WT_ITEM value;
    uint64_t recno;
    uint32_t flags;
} WT_CURFILE_STATE;


/*
 * __cursor_state_save --
 *     Save the cursor's external state.
 */
static inline void
__cursor_state_save(WT_CURSOR *cursor, WT_CURFILE_STATE *state)
{
    WT_ITEM_SET(state->key, cursor->key);
    WT_ITEM_SET(state->value, cursor->value);
    state->recno = cursor->recno;
    state->flags = cursor->flags;
}

static inline void
__cursor_state_restore(WT_CURSOR *cursor, WT_CURFILE_STATE *state)
{
    if (F_ISSET(state, WT_CURSTD_KEY_EXT))
        WT_ITEM_SET(cursor->key, state->key);
    if (F_ISSET(state, WT_CURSTD_VALUE_EXT))
        WT_ITEM_SET(cursor->value, state->value);
    cursor->recno = state->recno;
    F_CLR(cursor, WT_CURSTD_KEY_INT | WT_CURSTD_VALUE_INT);
    F_SET(cursor, F_MASK(state, WT_CURSTD_KEY_EXT | WT_CURSTD_VALUE_EXT));
}

/*
 * __cursor_page_pinned --
 *     Return if we have a page pinned.
 */
static inline bool
__cursor_page_pinned(WT_CURSOR_BTREE *cbt, bool search_operation)
{
    WT_CURSOR *cursor;
    WT_SESSION_IMPL *session;

    cursor = &cbt->iface;
    session = CUR2S(cbt);

    /*
     * Check the page active flag, asserting the page reference with any external key.
     */
    if (!F_ISSET(cbt, WT_CBT_ACTIVE)) {
        WT_ASSERT(session, cbt->ref == NULL && !F_ISSET(cursor, WT_CURSTD_KEY_INT));
        return (false);
    }

    /*
     * Check if the key references an item on a page. When returning from search, the page is pinned
     * and the key is internal. After the application sets a key, the key becomes external. For the
     * search and search-near operations, we assume locality and check any pinned page first on each
     * new search operation. For operations other than search and search-near, check if we have an
     * internal key. If the page is pinned and we're pointing into the page, we don't need to search
     * at all, we can proceed with the operation. However, if the key has been set, that is, it's an
     * external key, we're going to have to do a full search.
     */
    if (!search_operation && !F_ISSET(cursor, WT_CURSTD_KEY_INT))
        return (false);

    /*
     * XXX No fast-path searches at read-committed isolation. Underlying transactional functions
     * called by the fast and slow path search code handle transaction IDs differently, resulting in
     * different search results at read-committed isolation. This makes no difference for the update
     * functions, but in the case of a search, we will see different results based on the cursor's
     * initial location. See WT-5134 for the details.
     */
    if (search_operation && session->txn->isolation == WT_ISO_READ_COMMITTED)
        return (false);

    /*
     * Fail if the page is flagged for forced eviction (so we periodically release pages grown too
     * large).
     */
    if (cbt->ref->page->read_gen == WT_READGEN_OLDEST)
        return (false);

    return (true);
}

/*
 * __cursor_localkey --
 *     If the key points into the tree, get a local copy.
 */
static inline int
__cursor_localkey(WT_CURSOR *cursor)
{
    if (F_ISSET(cursor, WT_CURSTD_KEY_INT)) {
        // This should never happen!
        RET_MSG(-1, "__cursor_localkey: WT_CURSTD_KEY_INT");

        // if (!WT_DATA_IN_ITEM(&cursor->key))
        //     WT_RET(__wt_buf_set(CUR2S(cursor), &cursor->key, cursor->key.data, cursor->key.size));
        // F_CLR(cursor, WT_CURSTD_KEY_INT);
        // F_SET(cursor, WT_CURSTD_KEY_EXT);
    }
    return (0);
}

/*
 * __cursor_leave --
 *     Deactivate a cursor.
 */
static inline void
__cursor_leave(WT_SESSION_IMPL *session)
{
    /* Decrement the count of active cursors in the session. */
    WT_ASSERT(session, session->ncursors > 0);
    --session->ncursors;
}

/*
 * __cursor_pos_clear --
 *     Reset the cursor's location.
 */
static inline void
__cursor_pos_clear(WT_CURSOR_BTREE *cbt)
{
    /*
     * Most of the cursor's location information that needs to be set on successful return is always
     * set by a successful return, for example, we don't initialize the compare return value because
     * it's always set by the row-store search. The other stuff gets cleared here, and it's a
     * minimal set of things we need to clear. It would be a lot simpler to clear everything, but we
     * call this function a lot.
     */
    cbt->recno = WT_RECNO_OOB;

    cbt->ins = NULL;
    cbt->ins_head = NULL;
    cbt->ins_stack[0] = NULL;

    F_CLR(cbt, WT_CBT_POSITION_MASK);
}

/*
 * __wt_ref_is_root --
 *     Return if the page reference is for the root page.
 */
static inline bool
__wt_ref_is_root(WT_REF *ref)
{
    return (ref->home == NULL);
}

/*
 * __wt_split_descent_race --
 *     Return if we raced with an internal page split when descending the tree.
 */
static inline bool
__wt_split_descent_race(WT_SESSION_IMPL *session, WT_REF *ref, WT_PAGE_INDEX *saved_pindex)
{
    WT_PAGE_INDEX *pindex;

    /* No test when starting the descent (there's no home to check). */
    if (__wt_ref_is_root(ref))
        return (false);

    /*
     * A place to hang this comment...
     *
     * There's a page-split race when we walk the tree: if we're splitting
     * an internal page into its parent, we update the parent's page index
     * before updating the split page's page index, and it's not an atomic
     * update. A thread can read the parent page's original page index and
     * then read the split page's replacement index.
     *
     * For example, imagine a search descending the tree.
     *
     * Because internal page splits work by truncating the original page to
     * the initial part of the original page, the result of this race is we
     * will have a search key that points past the end of the current page.
     * This is only an issue when we search past the end of the page, if we
     * find a WT_REF in the page with the namespace we're searching for, we
     * don't care if the WT_REF moved or not while we were searching, we
     * have the correct page.
     *
     * For example, imagine an internal page with 3 child pages, with the
     * namespaces a-f, g-h and i-j; the first child page splits. The parent
     * starts out with the following page-index:
     *
     *	| ... | a | g | i | ... |
     *
     * which changes to this:
     *
     *	| ... | a | c | e | g | i | ... |
     *
     * The child starts out with the following page-index:
     *
     *	| a | b | c | d | e | f |
     *
     * which changes to this:
     *
     *	| a | b |
     *
     * The thread searches the original parent page index for the key "cat",
     * it couples to the "a" child page; if it uses the replacement child
     * page index, it will search past the end of the page and couple to the
     * "b" page, which is wrong.
     *
     * To detect the problem, we remember the parent page's page index used
     * to descend the tree. Whenever we search past the end of a page, we
     * check to see if the parent's page index has changed since our use of
     * it during descent. As the problem only appears if we read the split
     * page's replacement index, the parent page's index must already have
     * changed, ensuring we detect the problem.
     *
     * It's possible for the opposite race to happen (a thread could read
     * the parent page's replacement page index and then read the split
     * page's original index). This isn't a problem because internal splits
     * work by truncating the split page, so the split page search is for
     * content the split page retains after the split, and we ignore this
     * race.
     *
     * This code is a general purpose check for a descent race and we call
     * it in other cases, for example, a cursor traversing backwards through
     * the tree.
     *
     * Presumably we acquired a page index on the child page before calling
     * this code, don't re-order that acquisition with this check.
     */
    WT_BARRIER();
    WT_INTL_INDEX_GET(session, ref->home, pindex);
    return (pindex != saved_pindex);
}

/*
 * __wt_cache_read_gen --
 *     Get the current read generation number.
 */
static inline uint64_t
__wt_cache_read_gen(WT_SESSION_IMPL *session)
{
    return (S2C(session)->cache->read_gen);
}

/*
 * __wt_cache_read_gen_bump --
 *     Update the page's read generation.
 */
static inline void
__wt_cache_read_gen_bump(WT_SESSION_IMPL *session, WT_PAGE *page)
{
    /* Ignore pages set for forcible eviction. */
    if (page->read_gen == WT_READGEN_OLDEST)
        return;

    /* Ignore pages already in the future. */
    if (page->read_gen > __wt_cache_read_gen(session))
        return;

    /*
     * We set read-generations in the future (where "the future" is measured by increments of the
     * global read generation). The reason is because when acquiring a new hazard pointer for a
     * page, we can check its read generation, and if the read generation isn't less than the
     * current global generation, we don't bother updating the page. In other words, the goal is to
     * avoid some number of updates immediately after each update we have to make.
     */
    page->read_gen = __wt_cache_read_gen(session) + WT_READGEN_STEP;
}

/*
 * __wt_cache_read_gen_new --
 *     Get the read generation for a new page in memory.
 */
static inline void
__wt_cache_read_gen_new(WT_SESSION_IMPL *session, WT_PAGE *page)
{
    WT_CACHE *cache;

    cache = S2C(session)->cache;
    page->read_gen = (__wt_cache_read_gen(session) + cache->read_gen_oldest) / 2;
}


/*
 * __wt_hazard_clear --
 *     Clear a hazard pointer.
 */
int
__wt_hazard_clear(WT_SESSION_IMPL *session, WT_REF *ref)
{
    WT_HAZARD *hp;

    /* If a file can never be evicted, hazard pointers aren't required. */
    if (F_ISSET(S2BT(session), WT_BTREE_IN_MEMORY))
        return (0);

    /*
     * Clear the caller's hazard pointer. The common pattern is LIFO, so do a reverse search.
     */
    for (hp = session->hazard + session->hazard_inuse - 1; hp >= session->hazard; --hp)
        if (hp->ref == ref) {
            /*
             * We don't publish the hazard pointer clear in the general case. It's not required for
             * correctness; it gives an eviction thread faster access to the page were the page
             * selected for eviction.
             */
            hp->ref = NULL;

            /*
             * If this was the last hazard pointer in the session, reset the size so that checks can
             * skip this session.
             *
             * A write-barrier() is necessary before the change to the in-use value, the number of
             * active references can never be less than the number of in-use slots.
             */
            if (--session->nhazard == 0)
                WT_PUBLISH(session->hazard_inuse, 0);
            return (0);
        }

    /*
     * A serious error, we should always find the hazard pointer. Panic, because using a page we
     * didn't have pinned down implies corruption.
     */
    // TODO: Handle the panic here, possibly convert to return int.
    WT_RET_PANIC(session, EINVAL, "session %p: clear hazard pointer: %p: not found",
      (void *)session, (void *)ref);
}


/*
 * __wt_page_release --
 *     Release a reference to a page.
 */
static inline int
__wt_page_release(WT_SESSION_IMPL *session, WT_REF *ref, uint32_t flags)
{
    WT_BTREE *btree;
    WT_PAGE *page;
    bool inmem_split;

    btree = S2BT(session);

    /*
     * Discard our hazard pointer. Ignore pages we don't have and the root page, which sticks in
     * memory, regardless.
     */
    if (ref == NULL || ref->page == NULL || __wt_ref_is_root(ref))
        return (0);

    /*
     * If hazard pointers aren't necessary for this file, we can't be evicting, we're done.
     */
    if (F_ISSET(btree, WT_BTREE_IN_MEMORY))
        return (0);

    /*
     * Attempt to evict pages with the special "oldest" read generation. This is set for pages that
     * grow larger than the configured memory_page_max setting, when we see many deleted items, and
     * when we are attempting to scan without trashing the cache.
     *
     * Checkpoint should not queue pages for urgent eviction if they require dirty eviction: there
     * is a special exemption that allows checkpoint to evict dirty pages in a tree that is being
     * checkpointed, and no other thread can help with that. Checkpoints don't rely on this code for
     * dirty eviction: that is handled explicitly in __wt_sync_file.
     *
     * If the operation has disabled eviction or splitting, or the session is preventing from
     * reconciling, then just queue the page for urgent eviction. Otherwise, attempt to release and
     * evict it.
     */
    // NOTE: Skip this path for now. Eviction introduces a spinlock. Not good!
    // page = ref->page;
    // if (WT_READGEN_EVICT_SOON(page->read_gen) && btree->evict_disabled == 0 &&
    //   __wt_page_can_evict(session, ref, &inmem_split) &&
    //   (!WT_SESSION_IS_CHECKPOINT(session) || __wt_page_evict_clean(page))) {
    //     // TODO:
    //     if (LF_ISSET(WT_READ_NO_EVICT) ||
    //       (inmem_split ? LF_ISSET(WT_READ_NO_SPLIT) : F_ISSET(session, WT_SESSION_NO_RECONCILE)))
    //         WT_IGNORE_RET_BOOL(__wt_page_evict_urgent(session, ref));
    //     else {
    //         WT_RET_BUSY_OK(__wt_page_release_evict(session, ref, flags));
    //         return (0);
    //     }
    // }

    return (__wt_hazard_clear(session, ref));
}

/*
 * __cursor_reset --
 *     Reset the cursor, it no longer holds any position.
 */
static inline int
__cursor_reset(WT_CURSOR_BTREE *cbt)
{
    WT_CURSOR *cursor;
    WT_DECL_RET;
    WT_SESSION_IMPL *session;

    cursor = &cbt->iface;
    session = CUR2S(cbt);

    __cursor_pos_clear(cbt);

    /* If the cursor was active, deactivate it. */
    if (F_ISSET(cbt, WT_CBT_ACTIVE)) {
        if (!F_ISSET(cbt, WT_CBT_NO_TRACKING))
            __cursor_leave(session);
        F_CLR(cbt, WT_CBT_ACTIVE);
    }

    /*
     * When the count of active cursors in the session goes to zero, there are no active cursors,
     * and we can release any snapshot we're holding for read committed isolation.
     */
    // NOTE: We don't hold any snapshot anyways.
    if (session->ncursors == 0 && !F_ISSET(cbt, WT_CBT_NO_TXN)) RET_MSG(-1, "__cursor_reset: holding a snapshot?");
        // __wt_txn_read_last(session);

    /* If we're not holding a cursor reference, we're done. */
    if (cbt->ref == NULL)
        return (0);

    /*
     * If we were scanning and saw a lot of deleted records on this page, try to evict the page when
     * we release it.
     *
     * A visible stop timestamp could have been treated as a tombstone and accounted in the deleted
     * count. Such a page might not have any new updates and be clean, but could benefit from
     * reconciliation getting rid of the obsolete content. Hence mark the page dirty to force it
     * through reconciliation.
     */
    // NOTE: We don't care about this now.
    // if (cbt->page_deleted_count > WT_BTREE_DELETE_THRESHOLD) {
    //     WT_RET(__wt_page_dirty_and_evict_soon(session, cbt->ref));
    //     WT_STAT_CONN_INCR(session, cache_eviction_force_delete);
    // }
    cbt->page_deleted_count = 0;

    /*
     * Release any page references we're holding. This can trigger eviction (for example, forced
     * eviction of big pages), so it must happen after releasing our snapshot above. Additionally,
     * there's a debug mode where an application can force the eviction in order to test or stress
     * the system. Clear the reference so we never try the release twice.
     */
    // NOTE: We don't care about debug mode
    if (F_ISSET(cursor, WT_CURSTD_DEBUG_RESET_EVICT)) RET_MSG(-1, "__cursor_reset: debug mode?");
        // WT_TRET_BUSY_OK(__wt_page_release_evict(session, cbt->ref, 0));
    else
        ret = __wt_page_release(session, cbt->ref, 0);
    cbt->ref = NULL;

    return (ret);
}

/*
 * __wt_txn_cursor_op --
 *     Called for each cursor operation.
 */
static inline void
__wt_txn_cursor_op(WT_SESSION_IMPL *session)
{
    WT_TXN *txn;
    WT_TXN_GLOBAL *txn_global;
    WT_TXN_SHARED *txn_shared;

    txn = session->txn;
    txn_global = &S2C(session)->txn_global;
    txn_shared = WT_SESSION_TXN_SHARED(session);

    /*
     * We are about to read data, which means we need to protect against
     * updates being freed from underneath this cursor. Read-uncommitted
     * isolation protects values by putting a transaction ID in the global
     * table to prevent any update that we are reading from being freed.
     * Other isolation levels get a snapshot to protect their reads.
     *
     * !!!
     * Note:  We are updating the global table unprotected, so the global
     * oldest_id may move past our snap_min if a scan races with this value
     * being published. That said, read-uncommitted operations always see
     * the most recent update for each record that has not been aborted
     * regardless of the snap_min value published here.  Even if there is a
     * race while publishing this ID, it prevents the oldest ID from moving
     * further forward, so that once a read-uncommitted cursor is
     * positioned on a value, it can't be freed.
     */
    if (txn->isolation == WT_ISO_READ_UNCOMMITTED) {
        if (txn_shared->pinned_id == WT_TXN_NONE)
            txn_shared->pinned_id = txn_global->last_running;
        if (txn_shared->metadata_pinned == WT_TXN_NONE)
            txn_shared->metadata_pinned = txn_shared->pinned_id;
    } else if (!F_ISSET(txn, WT_TXN_HAS_SNAPSHOT))
        // NOTE: This should never happen
        RET_MSG(-1, "__wt_txn_cursor_op: requested snapshot");
        // __wt_txn_get_snapshot(session);
}



/*
 * __cursor_func_init --
 *     Cursor call setup.
 */
static inline int
__cursor_func_init(WT_CURSOR_BTREE *cbt, bool reenter)
{
    WT_SESSION_IMPL *session;

    session = CUR2S(cbt);

    if (reenter)
        WT_RET(__cursor_reset(cbt));

    /*
     * Any old insert position is now invalid. We rely on this being cleared to detect if a new
     * skiplist is installed after a search.
     */
    cbt->ins_stack[0] = NULL;

    /* If the transaction is idle, check that the cache isn't full. */
    // NOTE: Let's skip eviction-related stuff for now.
    // WT_RET(__wt_txn_idle_cache_check(session));

    /* Activate the file cursor. */
    if (!F_ISSET(cbt, WT_CBT_ACTIVE)) {
        if (!F_ISSET(cbt, WT_CBT_NO_TRACKING))
            WT_RET(__cursor_enter(session));
        F_SET(cbt, WT_CBT_ACTIVE);
    }

    /*
     * If this is an ordinary transactional cursor, make sure we are set up to read.
     */
    if (!F_ISSET(cbt, WT_CBT_NO_TXN))
        __wt_txn_cursor_op(session);
    return (0);
}

/*
 * __wt_session_gen --
 *     Return the thread's resource generation.
 */
uint64_t
__wt_session_gen(WT_SESSION_IMPL *session, int which)
{
    return (session->generations[which]);
}

/*
 * __wt_gen --
 *     Return the resource's generation.
 */
uint64_t
__wt_gen(WT_SESSION_IMPL *session, int which)
{
    return (S2C(session)->generations[which]);
}

/*
 * __wt_session_gen_enter --
 *     Publish a thread's resource generation.
 */
void
__wt_session_gen_enter(WT_SESSION_IMPL *session, int which)
{
    /*
     * Don't enter a generation we're already in, it will likely result in code intended to be
     * protected by a generation running outside one.
     */
    WT_ASSERT(session, session->generations[which] == 0);

    /*
     * Assign the thread's resource generation and publish it, ensuring threads waiting on a
     * resource to drain see the new value. Check we haven't raced with a generation update after
     * publishing, we rely on the published value not being missed when scanning for the oldest
     * generation.
     */
    do {
        session->generations[which] = __wt_gen(session, which);
        WT_WRITE_BARRIER();
    } while (session->generations[which] != __wt_gen(session, which));
}

/*
 * __wt_session_gen_leave --
 *     Leave a thread's resource generation.
 */
void
__wt_session_gen_leave(WT_SESSION_IMPL *session, int which)
{
    /* Ensure writes made by this thread are visible. */
    WT_PUBLISH(session->generations[which], 0);

    /* Let threads waiting for the resource to drain proceed quickly. */
    WT_FULL_BARRIER();
}

/*
 * __cursor_row_search --
 *     Row-store search from a cursor.
 */
static inline int
__cursor_row_search(WT_CURSOR_BTREE *cbt, bool insert, WT_REF *leaf, bool *leaf_foundp)
{
    WT_DECL_RET;
    WT_SESSION_IMPL *session;

    session = CUR2S(cbt);
    WT_WITH_PAGE_INDEX(
      session, ret = __wt_row_search(cbt, &cbt->iface.key, insert, leaf, false, leaf_foundp));
    return (ret);
}

/*
 * __wt_page_in_func --
 *     Acquire a hazard pointer to a page; if the page is not in-memory, read it from the disk and
 *     build an in-memory version.
 */
int
__wt_page_in_func(WT_SESSION_IMPL *session, WT_REF *ref, uint32_t flags)
{
    WT_BTREE *btree;
    WT_DECL_RET;
    WT_PAGE *page;
    uint64_t sleep_usecs, yield_cnt;
    uint8_t current_state;
    int force_attempts;
    bool busy, cache_work, evict_skip, stalled, wont_need;

    btree = S2BT(session);

    if (F_ISSET(session, WT_SESSION_IGNORE_CACHE_SIZE))
        LF_SET(WT_READ_IGNORE_CACHE_SIZE);

    /* Sanity check flag combinations. */
    WT_ASSERT(session,
      !LF_ISSET(WT_READ_DELETED_SKIP) || !LF_ISSET(WT_READ_NO_WAIT) || LF_ISSET(WT_READ_CACHE));
    WT_ASSERT(session, !LF_ISSET(WT_READ_DELETED_CHECK) || !LF_ISSET(WT_READ_DELETED_SKIP));

    /*
     * Ignore reads of pages already known to be in cache, otherwise the eviction server can
     * dominate these statistics.
     */
    // Note: We don't care about statistics.
    // if (!LF_ISSET(WT_READ_CACHE)) {
    //     WT_STAT_CONN_INCR(session, cache_pages_requested);
    //     WT_STAT_DATA_INCR(session, cache_pages_requested);
    // }

    for (evict_skip = stalled = wont_need = false, force_attempts = 0, sleep_usecs = yield_cnt = 0;
         ;) {
        switch (current_state = ref->state) {
        case WT_REF_DELETED:
            // Note: The background processes use these, we don't care about them.
            // if (LF_ISSET(WT_READ_DELETED_SKIP | WT_READ_NO_WAIT))
            //     return (WT_NOTFOUND);
            // if (LF_ISSET(WT_READ_DELETED_CHECK) &&
            //   __wt_delete_page_skip(session, ref, !F_ISSET(session->txn, WT_TXN_HAS_SNAPSHOT)))
            //     return (WT_NOTFOUND);
            goto read;
        case WT_REF_DISK:
            /* Optionally limit reads to cache-only. */
            if (LF_ISSET(WT_READ_CACHE))
                return (WT_NOTFOUND);
read:
            /*
             * The page isn't in memory, read it. If this thread respects the cache size, check for
             * space in the cache.
             */
            // Note: We don't read from disk, only the userspace thread does that!
            return (WT_NOTFOUND);
            // if (!LF_ISSET(WT_READ_IGNORE_CACHE_SIZE))
            //     WT_RET(__wt_cache_eviction_check(
            //       session, true, !F_ISSET(session->txn, WT_TXN_HAS_ID), NULL));
            // WT_RET(__page_read(session, ref, flags));

            // /* We just read a page, don't evict it before we have a chance to use it. */
            // evict_skip = true;

            // /*
            //  * If configured to not trash the cache, leave the page generation unset, we'll set it
            //  * before returning to the oldest read generation, so the page is forcibly evicted as
            //  * soon as possible. We don't do that set here because we don't want to evict the page
            //  * before we "acquire" it.
            //  */
            // wont_need = LF_ISSET(WT_READ_WONT_NEED) ||
            //   F_ISSET(session, WT_SESSION_READ_WONT_NEED) ||
            //   F_ISSET(S2C(session)->cache, WT_CACHE_EVICT_NOKEEP);
            // continue;
        case WT_REF_LOCKED:
            if (LF_ISSET(WT_READ_NO_WAIT))
                return (WT_NOTFOUND);

            if (F_ISSET(ref, WT_REF_FLAG_READING)) {
                if (LF_ISSET(WT_READ_CACHE))
                    return (WT_NOTFOUND);

                /* Waiting on another thread's read, stall. */
                // NOTE: We don't care about stats.
                // WT_STAT_CONN_INCR(session, page_read_blocked);
            } else
                // NOTE: We don't care about stats.
                /* Waiting on eviction, stall. */
                // WT_STAT_CONN_INCR(session, page_locked_blocked);

            stalled = true;
            break;
        case WT_REF_SPLIT:
            return (WT_RESTART);
        case WT_REF_MEM:
            /*
             * The page is in memory.
             *
             * Get a hazard pointer if one is required. We cannot be evicting if no hazard pointer
             * is required, we're done.
             */
            if (F_ISSET(btree, WT_BTREE_IN_MEMORY))
                goto skip_evict;

/*
 * The expected reason we can't get a hazard pointer is because the page is being evicted, yield,
 * try again.
 */
            WT_RET(__wt_hazard_set_func(session, ref, &busy));
            // NOTE: We don't care about stats.
            // if (busy) {
            //     WT_STAT_CONN_INCR(session, page_busy_blocked);
            //     break;
            // }

            // Skip eviction!
            // /*
            //  * If a page has grown too large, we'll try and forcibly evict it before making it
            //  * available to the caller. There are a variety of cases where that's not possible.
            //  * Don't involve a thread resolving a transaction in forced eviction, they're usually
            //  * making the problem better.
            //  */
            // if (evict_skip || F_ISSET(session, WT_SESSION_RESOLVING_TXN) ||
            //   LF_ISSET(WT_READ_NO_SPLIT) || btree->evict_disabled > 0 || btree->lsm_primary)
            //     goto skip_evict;

            // /*
            //  * If reconciliation is disabled (e.g., when inserting into the history store table),
            //  * skip forced eviction if the page can't split.
            //  */
            // if (F_ISSET(session, WT_SESSION_NO_RECONCILE) &&
            //   !__wt_leaf_page_can_split(session, ref->page))
            //     goto skip_evict;

            // /*
            //  * Forcibly evict pages that are too big.
            //  */
            // if (force_attempts < 10 && __evict_force_check(session, ref)) {
            //     ++force_attempts;
            //     ret = __wt_page_release_evict(session, ref, 0);
            //     /*
            //      * If forced eviction succeeded, don't retry. If it failed, stall.
            //      */
            //     if (ret == 0)
            //         evict_skip = true;
            //     else if (ret == EBUSY) {
            //         WT_NOT_READ(ret, 0);
            //         WT_STAT_CONN_INCR(session, page_forcible_evict_blocked);
            //         /*
            //          * Forced eviction failed: check if this transaction is keeping content pinned
            //          * in cache.
            //          */
            //         if (force_attempts > 1 &&
            //           (ret = __wt_txn_is_blocking(session, true)) == WT_ROLLBACK)
            //             WT_STAT_CONN_INCR(session, cache_eviction_force_rollback);
            //         WT_RET(ret);
            //         stalled = true;
            //         break;
            //     }
            //     WT_RET(ret);

            //     /*
            //      * The result of a successful forced eviction is a page-state transition
            //      * (potentially to an in-memory page we can use, or a restart return for our
            //      * caller), continue the outer page-acquisition loop.
            //      */
            //     continue;
            // }

skip_evict:
            /*
             * If we read the page and are configured to not trash the cache, and no other thread
             * has already used the page, set the read generation so the page is evicted soon.
             *
             * Otherwise, if we read the page, or, if configured to update the page's read
             * generation and the page isn't already flagged for forced eviction, update the page
             * read generation.
             */
            page = ref->page;
            if (page->read_gen == WT_READGEN_NOTSET) {
                if (wont_need)
                    page->read_gen = WT_READGEN_WONT_NEED;
                else
                    // NEXTDAY: Continue here!
                    __wt_cache_read_gen_new(session, page);
            } else if (!LF_ISSET(WT_READ_NO_GEN))
                __wt_cache_read_gen_bump(session, page);

            /*
             * Check if we need an autocommit transaction. Starting a transaction can trigger
             * eviction, so skip it if eviction isn't permitted.
             *
             * The logic here is a little weird: some code paths do a blanket ban on checking the
             * cache size in sessions, but still require a transaction (e.g., when updating metadata
             * or the history store). If WT_READ_IGNORE_CACHE_SIZE was passed in explicitly, we're
             * done. If we set WT_READ_IGNORE_CACHE_SIZE because it was set in the session then make
             * sure we start a transaction.
             */
            return (LF_ISSET(WT_READ_IGNORE_CACHE_SIZE) &&
                  !F_ISSET(session, WT_SESSION_IGNORE_CACHE_SIZE) ?
                0 :
                __wt_txn_autocommit_check(session));
        default:
            RET_MSG(-1, "__wt_page_in_func: ILLEGAL VALUE!");
            // return (__wt_illegal_value(session, current_state));
        }

        /*
         * We failed to get the page -- yield before retrying, and if we've yielded enough times,
         * start sleeping so we don't burn CPU to no purpose.
         */
        // NOTE: We can't yield in BPF!
        // TODO: Should we retry in BPF here?
        // if (yield_cnt < WT_THOUSAND) {
        //     if (!stalled) {
        //         ++yield_cnt;
        //         __wt_yield();
        //         continue;
        //     }
        //     yield_cnt = WT_THOUSAND;
        // }

        /*
         * If stalling and this thread is allowed to do eviction work, check if the cache needs help
         * evicting clean pages (don't force a read to do dirty eviction). If we do work for the
         * cache, substitute that for a sleep.
         */
        // NOTE: No evictions, no yields.
        // if (!LF_ISSET(WT_READ_IGNORE_CACHE_SIZE)) {
        //     WT_RET(__wt_cache_eviction_check(session, true, true, &cache_work));
        //     if (cache_work)
        //         continue;
        // }
        // __wt_spin_backoff(&yield_cnt, &sleep_usecs);
        // WT_STAT_CONN_INCRV(session, page_sleep, sleep_usecs);
    }
}


/*
 * __wt_lex_compare_skip --
 *     Lexicographic comparison routine, skipping leading bytes. Returns: < 0 if user_item is
 *     lexicographically < tree_item = 0 if user_item is lexicographically = tree_item > 0 if
 *     user_item is lexicographically > tree_item We use the names "user" and "tree" so it's clear
 *     in the btree code which the application is looking at when we call its comparison function.
 */
static inline int
__wt_lex_compare_skip(const WT_ITEM *user_item, const WT_ITEM *tree_item, size_t *matchp)
{
    size_t len, usz, tsz;
    const uint8_t *userp, *treep;

    usz = user_item->size;
    tsz = tree_item->size;
    len = WT_MIN(usz, tsz) - *matchp;

    userp = (const uint8_t *)user_item->data + *matchp;
    treep = (const uint8_t *)tree_item->data + *matchp;

    // NOTE: Remove all vectorized instructions. They are not available in
    // the kernel.
// #ifdef HAVE_X86INTRIN_H
//     /* Use vector instructions if we'll execute at least 2 of them. */
//     if (len >= WT_VECTOR_SIZE * 2) {
//         size_t remain;
//         __m128i res_eq, u, t;

//         remain = len % WT_VECTOR_SIZE;
//         len -= remain;
//         if (WT_ALIGNED_16(userp) && WT_ALIGNED_16(treep))
//             for (; len > 0; len -= WT_VECTOR_SIZE, userp += WT_VECTOR_SIZE, treep += WT_VECTOR_SIZE,
//                  *matchp += WT_VECTOR_SIZE) {
//                 u = _mm_load_si128((const __m128i *)userp);
//                 t = _mm_load_si128((const __m128i *)treep);
//                 res_eq = _mm_cmpeq_epi8(u, t);
//                 if (_mm_movemask_epi8(res_eq) != 65535)
//                     break;
//             }
//         else
//             for (; len > 0; len -= WT_VECTOR_SIZE, userp += WT_VECTOR_SIZE, treep += WT_VECTOR_SIZE,
//                  *matchp += WT_VECTOR_SIZE) {
//                 u = _mm_loadu_si128((const __m128i *)userp);
//                 t = _mm_loadu_si128((const __m128i *)treep);
//                 res_eq = _mm_cmpeq_epi8(u, t);
//                 if (_mm_movemask_epi8(res_eq) != 65535)
//                     break;
//             }
//         len += remain;
//     }
// #elif defined(HAVE_ARM_NEON_INTRIN_H)
//     /* Use vector instructions if we'll execute  at least 1 of them. */
//     if (len >= WT_VECTOR_SIZE) {
//         size_t remain;
//         uint8x16_t res_eq, u, t;
//         remain = len % WT_VECTOR_SIZE;
//         len -= remain;
//         if (WT_ALIGNED_16(userp) && WT_ALIGNED_16(treep))
//             for (; len > 0; len -= WT_VECTOR_SIZE, userp += WT_VECTOR_SIZE, treep += WT_VECTOR_SIZE,
//                  *matchp += WT_VECTOR_SIZE) {
//                 u = vld1q_u8(userp);
//                 t = vld1q_u8(treep);
//                 res_eq = vceqq_u8(u, t);
//                 if (vminvq_u8(res_eq) != 255)
//                     break;
//             }
//         len += remain;
//     }
// #endif
    /*
     * Use the non-vectorized version for the remaining bytes and for the small key sizes.
     */
    for (; len > 0; --len, ++userp, ++treep, ++*matchp)
        if (*userp != *treep)
            return (*userp < *treep ? -1 : 1);

    /* Contents are equal up to the smallest length. */
    return ((usz == tsz) ? 0 : (usz < tsz) ? -1 : 1);
}


/*
 * __wt_page_swap_func --
 *     Swap one page's hazard pointer for another one when hazard pointer coupling up/down the tree.
 */
static inline int
__wt_page_swap_func(WT_SESSION_IMPL *session, WT_REF *held, WT_REF *want, uint32_t flags
#ifdef HAVE_DIAGNOSTIC
  ,
  const char *func, int line
#endif
  )
{
    WT_DECL_RET;
    bool acquired;

    /*
     * This function is here to simplify the error handling during hazard
     * pointer coupling so we never leave a hazard pointer dangling.  The
     * assumption is we're holding a hazard pointer on "held", and want to
     * acquire a hazard pointer on "want", releasing the hazard pointer on
     * "held" when we're done.
     *
     * When walking the tree, we sometimes swap to the same page. Fast-path
     * that to avoid thinking about error handling.
     */
    if (held == want)
        return (0);

    /* Get the wanted page. */
    ret = __wt_page_in_func(session, want, flags
#ifdef HAVE_DIAGNOSTIC
      ,
      func, line
#endif
      );

    /*
     * Expected failures: page not found or restart. Our callers list the errors they're expecting
     * to handle.
     */
    if (LF_ISSET(WT_READ_NOTFOUND_OK) && ret == WT_NOTFOUND)
        return (WT_NOTFOUND);
    if (LF_ISSET(WT_READ_RESTART_OK) && ret == WT_RESTART)
        return (WT_RESTART);

    /* Discard the original held page on either success or error. */
    acquired = ret == 0;
    WT_TRET(__wt_page_release(session, held, flags));

    /* Fast-path expected success. */
    if (ret == 0)
        return (0);

    /*
     * If there was an error at any point that our caller isn't prepared to handle, discard any page
     * we acquired.
     */
    if (acquired)
        WT_TRET(__wt_page_release(session, want, flags));

    /*
     * If we're returning an error, don't let it be one our caller expects to handle as returned by
     * page-in: the expectation includes the held page not having been released, and that's not the
     * case.
     */
    if (LF_ISSET(WT_READ_NOTFOUND_OK) && ret == WT_NOTFOUND)
        WT_RET_MSG(session, EINVAL, "page-release WT_NOTFOUND error mapped to EINVAL");
    if (LF_ISSET(WT_READ_RESTART_OK) && ret == WT_RESTART)
        WT_RET_MSG(session, EINVAL, "page-release WT_RESTART error mapped to EINVAL");

    return (ret);
}

/*
 * __wt_ref_key --
 *     Return a reference to a row-store internal page key as cheaply as possible.
 */
static inline void
__wt_ref_key(WT_PAGE *page, WT_REF *ref, void *keyp, size_t *sizep)
{
    uintptr_t v;

/*
 * An internal page key is in one of two places: if we instantiated the
 * key (for example, when reading the page), WT_REF.ref_ikey references
 * a WT_IKEY structure, otherwise WT_REF.ref_ikey references an on-page
 * key offset/length pair.
 *
 * Now the magic: allocated memory must be aligned to store any standard
 * type, and we expect some standard type to require at least quad-byte
 * alignment, so allocated memory should have some clear low-order bits.
 * On-page objects consist of an offset/length pair: the maximum page
 * size currently fits into 29 bits, so we use the low-order bits of the
 * pointer to mark the other bits of the pointer as encoding the key's
 * location and length.  This breaks if allocated memory isn't aligned,
 * of course.
 *
 * In this specific case, we use bit 0x01 to mark an on-page key, else
 * it's a WT_IKEY reference.  The bit pattern for internal row-store
 * on-page keys is:
 *	32 bits		key length
 *	31 bits		page offset of the key's bytes,
 *	 1 bits		flags
 */
#define WT_IK_FLAG 0x01
#define WT_IK_ENCODE_KEY_LEN(v) ((uintptr_t)(v) << 32)
#define WT_IK_DECODE_KEY_LEN(v) ((v) >> 32)
#define WT_IK_ENCODE_KEY_OFFSET(v) ((uintptr_t)(v) << 1)
#define WT_IK_DECODE_KEY_OFFSET(v) (((v)&0xFFFFFFFF) >> 1)
    v = (uintptr_t)ref->ref_ikey;
    if (v & WT_IK_FLAG) {
        *(void **)keyp = WT_PAGE_REF_OFFSET(page, WT_IK_DECODE_KEY_OFFSET(v));
        *sizep = WT_IK_DECODE_KEY_LEN(v);
    } else {
        *(void **)keyp = WT_IKEY_DATA(ref->ref_ikey);
        *sizep = ((WT_IKEY *)ref->ref_ikey)->size;
    }
}


/*
 * __wt_row_search --
 *     Search a row-store tree for a specific key.
 */
int
__wt_row_search(WT_CURSOR_BTREE *cbt, WT_ITEM *srch_key, bool insert, WT_REF *leaf, bool leaf_safe,
  bool *leaf_foundp)
{
    WT_BTREE *btree;
    WT_COLLATOR *collator;
    WT_DECL_RET;
    WT_INSERT_HEAD *ins_head;
    WT_ITEM *item;
    WT_PAGE *page;
    WT_PAGE_INDEX *pindex, *parent_pindex;
    WT_REF *current, *descent;
    WT_ROW *rip;
    WT_SESSION_IMPL *session;
    size_t match, skiphigh, skiplow;
    uint32_t base, indx, limit, read_flags;
    int cmp, depth;
    bool append_check, descend_right, done;

    session = CUR2S(cbt);
    btree = S2BT(session);
    collator = btree->collator;
    item = cbt->tmp;
    current = NULL;

    /*
     * Assert the session and cursor have the right relationship (not search specific, but search is
     * a convenient place to check given any operation on a cursor will likely search a page).
     */
    // WT_ASSERT(session, session->dhandle == cbt->dhandle);

    __cursor_pos_clear(cbt);

    /*
     * In some cases we expect we're comparing more than a few keys with matching prefixes, so it's
     * faster to avoid the memory fetches by skipping over those prefixes. That's done by tracking
     * the length of the prefix match for the lowest and highest keys we compare as we descend the
     * tree. The high boundary is reset on each new page, the lower boundary is maintained.
     */
    skiplow = 0;

    /*
     * If a cursor repeatedly appends to the tree, compare the search key against the last key on
     * each internal page during insert before doing the full binary search.
     *
     * Track if the descent is to the right-side of the tree, used to set the cursor's append
     * history.
     */
    append_check = insert && cbt->append_tree;
    descend_right = true;

    /*
     * We may be searching only a single leaf page, not the full tree. In the normal case where we
     * are searching a tree, check the page's parent keys before doing the full search, it's faster
     * when the cursor is being re-positioned. Skip that check if we know the page is the right one
     * (for example, when re-instantiating a page in memory, in that case we know the target must be
     * on the current page).
     */
    if (leaf != NULL) {
        // NOTE: We should never enter this path!
        RET_MSG(-1, "__wt_row_search: leaf page path!");
        // if (!leaf_safe) {
        //     WT_RET(__check_leaf_key_range(session, srch_key, leaf, cbt));
        //     *leaf_foundp = cbt->compare == 0;
        //     if (!*leaf_foundp)
        //         return (0);
        // }

        // current = leaf;
        // goto leaf_only;
    }

    if (0) {
restart:
        /*
         * Discard the currently held page and restart the search from the root.
         */
        WT_RET(__wt_page_release(session, current, 0));
        skiplow = 0;
    }

    /* Search the internal pages of the tree. */
    current = &btree->root;
    for (depth = 2, pindex = NULL;; ++depth) {
        parent_pindex = pindex;
        page = current->page;
        // We reached a leaf page!
        if (page->type != WT_PAGE_ROW_INT)
            break;

        WT_INTL_INDEX_GET(session, page, pindex);

        /*
         * Fast-path appends.
         *
         * The 0th key on an internal page is a problem for a couple of reasons. First, we have to
         * force the 0th key to sort less than any application key, so internal pages don't have to
         * be updated if the application stores a new, "smallest" key in the tree. Second,
         * reconciliation is aware of this and will store a byte of garbage in the 0th key, so the
         * comparison of an application key and a 0th key is meaningless (but doing the comparison
         * could still incorrectly modify our tracking of the leading bytes in each key that we can
         * skip during the comparison). For these reasons, special-case the 0th key, and never pass
         * it to a collator.
         */
        // NOTE: We don't do appends!
        // if (append_check) {
        //     descent = pindex->index[pindex->entries - 1];

        //     if (pindex->entries == 1)
        //         goto append;
        //     __wt_ref_key(page, descent, &item->data, &item->size);
        //     WT_ERR(__wt_compare(session, collator, srch_key, item, &cmp));
        //     if (cmp >= 0)
        //         goto append;

        //     /* A failed append check turns off append checks. */
        //     append_check = false;
        // }

        /*
         * Binary search of an internal page. There are three versions (keys with no
         * application-specified collation order, in long and short versions, and keys with an
         * application-specified collation order), because doing the tests and error handling inside
         * the loop costs about 5%.
         *
         * Reference the comment above about the 0th key: we continue to special-case it.
         */
        base = 1;
        limit = pindex->entries - 1;
        if (collator == NULL && srch_key->size <= WT_COMPARE_SHORT_MAXLEN)
            RET_MSG(-1, "__wt_row_search: wrong search code path, 1 instead of 2");
            // for (; limit != 0; limit >>= 1) {
            //     indx = base + (limit >> 1);
            //     descent = pindex->index[indx];
            //     __wt_ref_key(page, descent, &item->data, &item->size);

            //     cmp = __wt_lex_compare_short(srch_key, item);
            //     if (cmp > 0) {
            //         base = indx + 1;
            //         --limit;
            //     } else if (cmp == 0)
            //         goto descend;
            // }
        else if (collator == NULL) {
            // THIS IS THE ONE WE CARE ABOUT!

            /*
             * Reset the skipped prefix counts; we'd normally expect the parent's skipped prefix
             * values to be larger than the child's values and so we'd only increase them as we walk
             * down the tree (in other words, if we can skip N bytes on the parent, we can skip at
             * least N bytes on the child). However, if a child internal page was split up into the
             * parent, the child page's key space will have been truncated, and the values from the
             * parent's search may be wrong for the child. We only need to reset the high count
             * because the split-page algorithm truncates the end of the internal page's key space,
             * the low count is still correct.
             */
            skiphigh = 0;

            for (; limit != 0; limit >>= 1) {
                indx = base + (limit >> 1);
                descent = pindex->index[indx];
                __wt_ref_key(page, descent, &item->data, &item->size);

                match = WT_MIN(skiplow, skiphigh);
                cmp = __wt_lex_compare_skip(srch_key, item, &match);
                if (cmp > 0) {
                    skiplow = match;
                    base = indx + 1;
                    --limit;
                } else if (cmp < 0)
                    skiphigh = match;
                else
                    goto descend;
            }
        } else
            RET_MSG(-1, "__wt_row_search: wrong search code path, 1 instead of 2");
            // for (; limit != 0; limit >>= 1) {
            //     indx = base + (limit >> 1);
            //     descent = pindex->index[indx];
            //     __wt_ref_key(page, descent, &item->data, &item->size);

            //     WT_ERR(__wt_compare(session, collator, srch_key, item, &cmp));
            //     if (cmp > 0) {
            //         base = indx + 1;
            //         --limit;
            //     } else if (cmp == 0)
            //         goto descend;
            // }

        /*
         * Set the slot to descend the tree: descent was already set if there was an exact match on
         * the page, otherwise, base is the smallest index greater than key, possibly one past the
         * last slot.
         */
        descent = pindex->index[base - 1];

        /*
         * If we end up somewhere other than the last slot, it's not a right-side descent.
         */
        if (pindex->entries != base)
            descend_right = false;

        /*
         * If on the last slot (the key is larger than any key on the page), check for an internal
         * page split race.
         */
        if (pindex->entries == base) {
append:
            if (__wt_split_descent_race(session, current, parent_pindex))
                goto restart;
        }

descend:
        /* Encourage races. */
        // Note: Disable diagnostics.
        // WT_DIAGNOSTIC_YIELD;

        /*
         * Swap the current page for the child page. If the page splits while we're retrieving it,
         * restart the search at the root. We cannot restart in the "current" page; for example, if
         * a thread is appending to the tree, the page it's waiting for did an insert-split into the
         * parent, then the parent split into its parent, the name space we are searching for may
         * have moved above the current page in the tree.
         *
         * On other error, simply return, the swap call ensures we're holding nothing on failure.
         */
        read_flags = WT_READ_RESTART_OK;
        if (F_ISSET(cbt, WT_CBT_READ_ONCE))
            FLD_SET(read_flags, WT_READ_WONT_NEED);
        if ((ret = __wt_page_swap(session, current, descent, read_flags)) == 0) {
            current = descent;
            continue;
        }
        if (ret == WT_RESTART)
            goto restart;
        return (ret);
    }

    // TREE DESCENT END

    /* Track how deep the tree gets. */
    // TODO: Why is this here???
    if (depth > btree->maximum_depth)
        btree->maximum_depth = depth;

leaf_only:
    page = current->page;
    cbt->ref = current;

    /*
     * Clear current now that we have moved the reference into the btree cursor, so that cleanup
     * never releases twice.
     */
    current = NULL;

    /*
     * In the case of a right-side tree descent during an insert, do a fast check for an append to
     * the page, try to catch cursors appending data into the tree.
     *
     * It's tempting to make this test more rigorous: if a cursor inserts randomly into a two-level
     * tree (a root referencing a single child that's empty except for an insert list), the
     * right-side descent flag will be set and this comparison wasted. The problem resolves itself
     * as the tree grows larger: either we're no longer doing right-side descent, or we'll avoid
     * additional comparisons in internal pages, making up for the wasted comparison here.
     * Similarly, the cursor's history is set any time it's an insert and a right-side descent, both
     * to avoid a complicated/expensive test, and, in the case of multiple threads appending to the
     * tree, we want to mark them all as appending, even if this test doesn't work.
     */
    if (insert && descend_right) {
        cbt->append_tree = 1;

        if (page->entries == 0) {
            cbt->slot = WT_ROW_SLOT(page, page->pg_row);

            F_SET(cbt, WT_CBT_SEARCH_SMALLEST);
            ins_head = WT_ROW_INSERT_SMALLEST(page);
        } else {
            cbt->slot = WT_ROW_SLOT(page, page->pg_row + (page->entries - 1));

            ins_head = WT_ROW_INSERT_SLOT(page, cbt->slot);
        }

        WT_ERR(__search_insert_append(session, cbt, ins_head, srch_key, &done));
        if (done)
            return (0);
    }

    /*
     * Binary search of an leaf page. There are three versions (keys with no application-specified
     * collation order, in long and short versions, and keys with an application-specified collation
     * order), because doing the tests and error handling inside the loop costs about 5%.
     */
    base = 0;
    limit = page->entries;
    if (collator == NULL && srch_key->size <= WT_COMPARE_SHORT_MAXLEN)
        for (; limit != 0; limit >>= 1) {
            indx = base + (limit >> 1);
            rip = page->pg_row + indx;
            WT_ERR(__wt_row_leaf_key(session, page, rip, item, true));

            cmp = __wt_lex_compare_short(srch_key, item);
            if (cmp > 0) {
                base = indx + 1;
                --limit;
            } else if (cmp == 0)
                goto leaf_match;
        }
    else if (collator == NULL) {
        /*
         * Reset the skipped prefix counts; we'd normally expect the parent's skipped prefix values
         * to be larger than the child's values and so we'd only increase them as we walk down the
         * tree (in other words, if we can skip N bytes on the parent, we can skip at least N bytes
         * on the child). However, leaf pages at the end of the tree can be extended, causing the
         * parent's search to be wrong for the child. We only need to reset the high count, the page
         * can only be extended so the low count is still correct.
         */
        skiphigh = 0;

        for (; limit != 0; limit >>= 1) {
            indx = base + (limit >> 1);
            rip = page->pg_row + indx;
            WT_ERR(__wt_row_leaf_key(session, page, rip, item, true));

            match = WT_MIN(skiplow, skiphigh);
            cmp = __wt_lex_compare_skip(srch_key, item, &match);
            if (cmp > 0) {
                skiplow = match;
                base = indx + 1;
                --limit;
            } else if (cmp < 0)
                skiphigh = match;
            else
                goto leaf_match;
        }
    } else
        for (; limit != 0; limit >>= 1) {
            indx = base + (limit >> 1);
            rip = page->pg_row + indx;
            WT_ERR(__wt_row_leaf_key(session, page, rip, item, true));

            WT_ERR(__wt_compare(session, collator, srch_key, item, &cmp));
            if (cmp > 0) {
                base = indx + 1;
                --limit;
            } else if (cmp == 0)
                goto leaf_match;
        }

    /*
     * The best case is finding an exact match in the leaf page's WT_ROW array, probable for any
     * read-mostly workload. Check that case and get out fast.
     */
    if (0) {
leaf_match:
        cbt->compare = 0;
        cbt->slot = WT_ROW_SLOT(page, rip);
        return (0);
    }

    /*
     * We didn't find an exact match in the WT_ROW array.
     *
     * Base is the smallest index greater than key and may be the 0th index or the (last + 1) index.
     * Set the slot to be the largest index less than the key if that's possible (if base is the 0th
     * index it means the application is inserting a key before any key found on the page).
     *
     * It's still possible there is an exact match, but it's on an insert list. Figure out which
     * insert chain to search and then set up the return information assuming we'll find nothing in
     * the insert list (we'll correct as needed inside the search routine, depending on what we
     * find).
     *
     * If inserting a key smaller than any key found in the WT_ROW array, use the extra slot of the
     * insert array, otherwise the insert array maps one-to-one to the WT_ROW array.
     */
    if (base == 0) {
        cbt->compare = 1;
        cbt->slot = 0;

        F_SET(cbt, WT_CBT_SEARCH_SMALLEST);
        ins_head = WT_ROW_INSERT_SMALLEST(page);
    } else {
        cbt->compare = -1;
        cbt->slot = base - 1;

        ins_head = WT_ROW_INSERT_SLOT(page, cbt->slot);
    }

    /* If there's no insert list, we're done. */
    if (WT_SKIP_FIRST(ins_head) == NULL)
        return (0);

    /*
     * Test for an append first when inserting onto an insert list, try to catch cursors repeatedly
     * inserting at a single point.
     */
    if (insert) {
        WT_ERR(__search_insert_append(session, cbt, ins_head, srch_key, &done));
        if (done)
            return (0);
    }
    WT_ERR(__wt_search_insert(session, cbt, ins_head, srch_key));

    return (0);

err:
    WT_TRET(__wt_page_release(session, current, 0));
    return (ret);
}



int
__wt_btcur_search(WT_CURSOR_BTREE *cbt)
{
    WT_BTREE *btree;
    WT_CURFILE_STATE state;
    WT_CURSOR *cursor;
    WT_DECL_RET;
    WT_SESSION_IMPL *session;
    bool leaf_found, valid;

    btree = CUR2BT(cbt);
    cursor = &cbt->iface;
    session = CUR2S(cbt);

    // WT_RET(__wt_txn_search_check(session));
    __cursor_state_save(cursor, &state);

    /*
     * The pinned page goes away if we search the tree, get a local copy of any pinned key and
     * discard any pinned value, then re-save the cursor state. Done before searching pinned pages
     * (unlike other cursor functions), because we don't anticipate applications searching for a key
     * they currently have pinned.)
     */
    WT_ERR(__cursor_localkey(cursor));
    __cursor_novalue(cursor);
    __cursor_state_save(cursor, &state);

    /*
     * If we have a page pinned, search it; if we don't have a page pinned, or the search of the
     * pinned page doesn't find an exact match, search from the root.
     */
    valid = false;
    if (__cursor_page_pinned(cbt, true)) {
        RET_MSG(-1, "Page pinned but bloom filters disabled.");
    // TODO: Uncomment for bloom filters
    //     __wt_txn_cursor_op(session);
    //     if (btree->type == BTREE_ROW) {
    //         RET_MSG(-1, "__wt_btcur_search: pinned page of type BTREE_ROW")
    //         // WT_ERR(__cursor_row_search(cbt, false, cbt->ref, &leaf_found));
    //         // if (leaf_found && cbt->compare == 0)
    //         //     WT_ERR(__wt_cursor_valid(cbt, cbt->tmp, WT_RECNO_OOB, &valid));
    //     } else {
    //         // Should only enter here for bloom filters!
    //         WT_ERR(__cursor_col_search(cbt, cbt->ref, &leaf_found));
    //         if (leaf_found && cbt->compare == 0)
    //             WT_ERR(__wt_cursor_valid(cbt, NULL, cbt->recno, &valid));
    //     }
    }
    if (!valid) {
        WT_ERR(__cursor_func_init(cbt, true));

        if (btree->type == BTREE_ROW) {
            WT_ERR(__cursor_row_search(cbt, false, NULL, NULL));
            if (cbt->compare == 0)
                WT_ERR(__wt_cursor_valid(cbt, cbt->tmp, WT_RECNO_OOB, &valid));
        } else {
            WT_ERR(__cursor_col_search(cbt, NULL, NULL));
            if (cbt->compare == 0)
                WT_ERR(__wt_cursor_valid(cbt, NULL, cbt->recno, &valid));
        }
    }

    if (valid)
        ret = __cursor_kv_return(cbt, cbt->upd_value);
    else if (__cursor_fix_implicit(btree, cbt)) {
        /*
         * Creating a record past the end of the tree in a fixed-length column-store implicitly
         * fills the gap with empty records.
         */
        cbt->recno = cursor->recno;
        cbt->v = 0;
        cursor->value.data = &cbt->v;
        cursor->value.size = 1;
        F_CLR(cursor, WT_CURSTD_KEY_SET | WT_CURSTD_VALUE_SET);
        F_SET(cursor, WT_CURSTD_KEY_INT | WT_CURSTD_VALUE_INT);
    } else
        ret = WT_NOTFOUND;

    // NOTE: No diagnostics!
    // #ifdef HAVE_DIAGNOSTIC
    //     if (ret == 0)
    //         WT_ERR(__wt_cursor_key_order_init(cbt));
    // #endif

err:
    if (ret != 0) {
        WT_TRET(__cursor_reset(cbt));
        __cursor_state_restore(cursor, &state);
    }
    return (ret);
}


///////////////////////
// Main BPF function //
///////////////////////

// TODO:
// - __cursor_row_search
// - __cursor_col_search
// - __cursor_kv_return
// - __cursor_fix_implicit

struct thread_fn_args {
    WT_CONNECTION *conn;
    WT_SESSION *session;
    WT_CURSOR *cursor;
};

void *thread_fn(void *arg) {
    struct thread_fn_args *args;
    args = (struct thread_fn_args *)arg;
    WT_SESSION_IMPL *session = (WT_SESSION_IMPL *) args->cursor->session;
    // Logic...
    // simulate_bpf_read(args->conn, session, args->cursor);

    printf("Simulating read from BPF!\n\n");
}

int simulate_bpf_read(WT_CONNECTION *conn, WT_SESSION_IMPL *session,
                       WT_CURSOR *cursor) {

    // TODO: Use WT_SESSION_IMPL
    ///////////////////
    // __clsm_search //
    ///////////////////

    WT_CURSOR_LSM *clsm;
    clsm = (WT_CURSOR_LSM *)cursor;

    int __prepare_ret;
    __prepare_ret = __wt_txn_context_prepare_check(session);
    WT_RET(__prepare_ret);
    if (F_ISSET(cursor, WT_CURSTD_CACHED)) RET_MSG(-1, "cursor is cached! aborting!");
    if (!F_ISSET(cursor, WT_CURSTD_KEY_SET)) RET_MSG(-1, "need to set key on cursor!");
    __cursor_novalue(cursor);
    // __clsm_enter
    if (clsm->dsk_gen != clsm->lsm_tree->dsk_gen && clsm->lsm_tree->nchunks != 0) RET_MSG(-1, "need to re-open cursor on lsm tree!");
    if (!F_ISSET(clsm, WT_CLSM_ACTIVE)) {
        ++session->ncursors;
        WT_RET(__cursor_enter(session));
        F_SET(clsm, WT_CLSM_ACTIVE);
    }
    F_CLR(clsm, WT_CLSM_ITERATE_NEXT | WT_CLSM_ITERATE_PREV);


    ///////////////////
    // __clsm_lookup //
    ///////////////////

    WT_CURSOR *c = NULL;
    u_int i;
    WT_FORALL_CURSORS(clsm, c, i)
    {
        // Skip bloom filters for now!
        // 1. Set search key for the b-tree cursor of this level
        //    Original code: c->set_key(c, &cursor->key);
        __wt_cursor_set_key(c, &cursor->key);

        // 2. Search for that key on this level's btree.

        //////////////////////
        // __curfile_search //
        //////////////////////
        WT_CURSOR_BTREE *cbt = (WT_CURSOR_BTREE *) c;

        ///////////////////////
        // __wt_btcur_search //
        ///////////////////////
        WT_BTREE *btree = CUR2BT(cbt);

        // TODO: If found, set key, value

    }

    // TODO (end of __clsm_lookup): Set some cursor flags

    // __clsm_leave
    if (F_ISSET(clsm, WT_CLSM_ACTIVE)) {
        --session->ncursors;
        __cursor_leave(session);
        F_CLR(clsm, WT_CLSM_ACTIVE);
    }

}

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
