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
 * __key_return --
 *     Change the cursor to reference an internal return key.
 */
static inline int
__key_return(WT_CURSOR_BTREE *cbt)
{
    WT_CURSOR *cursor;
    WT_ITEM *tmp;
    WT_PAGE *page;
    WT_ROW *rip;
    WT_SESSION_IMPL *session;

    page = cbt->ref->page;
    cursor = &cbt->iface;
    session = CUR2S(cbt);

    if (page->type == WT_PAGE_ROW_LEAF) {
        rip = &page->pg_row[cbt->slot];

        /*
         * If the cursor references a WT_INSERT item, take its key. Else, if we have an exact match,
         * we copied the key in the search function, take it from there. If we don't have an exact
         * match, take the key from the original page.
         */
        if (cbt->ins != NULL) {
            cursor->key.data = WT_INSERT_KEY(cbt->ins);
            cursor->key.size = WT_INSERT_KEY_SIZE(cbt->ins);
            return (0);
        }

        if (cbt->compare == 0) {
            /*
             * If not in an insert list and there's an exact match, the row-store search function
             * built the key we want to return in the cursor's temporary buffer. Swap the cursor's
             * search-key and temporary buffers so we can return it (it's unsafe to return the
             * temporary buffer itself because our caller might do another search in this table
             * using the key we return, and we'd corrupt the search key during any subsequent search
             * that used the temporary buffer).
             */
            tmp = cbt->row_key;
            cbt->row_key = cbt->tmp;
            cbt->tmp = tmp;

            cursor->key.data = cbt->row_key->data;
            cursor->key.size = cbt->row_key->size;
            return (0);
        }
        return (__wt_row_leaf_key(session, page, rip, &cursor->key, false));
    }

    /*
     * WT_PAGE_COL_FIX, WT_PAGE_COL_VAR:
     *	The interface cursor's record has usually been set, but that
     * isn't universally true, specifically, cursor.search_near may call
     * here without first setting the interface cursor.
     */
    cursor->recno = cbt->recno;
    return (0);
}


/*
 * __wt_key_return --
 *     Change the cursor to reference an internal return key.
 */
int
__wt_key_return(WT_CURSOR_BTREE *cbt)
{
    WT_CURSOR *cursor;

    cursor = &cbt->iface;

    /*
     * We may already have an internal key and the cursor may not be set up to get another copy, so
     * we have to leave it alone. Consider a cursor search followed by an update: the update doesn't
     * repeat the search, it simply updates the currently referenced key's value. We will end up
     * here with the correct internal key, but we can't "return" the key again even if we wanted to
     * do the additional work, the cursor isn't set up for that because we didn't just complete a
     * search.
     */
    F_CLR(cursor, WT_CURSTD_KEY_EXT);
    if (!F_ISSET(cursor, WT_CURSTD_KEY_INT)) {
        WT_RET(__key_return(cbt));
        F_SET(cursor, WT_CURSTD_KEY_INT);
    }
    return (0);
}

/*
 * __wt_row_leaf_value --
 *     Return the value for a row-store leaf page encoded key/value pair.
 */
static inline bool
__wt_row_leaf_value(WT_PAGE *page, WT_ROW *rip, WT_ITEM *value)
{
    uintptr_t v;

    /* The row-store key can change underfoot; explicitly take a copy. */
    v = (uintptr_t)WT_ROW_KEY_COPY(rip);

    /*
     * See the comment in __wt_row_leaf_key_info for an explanation of the magic.
     */
    if ((v & 0x03) == WT_KV_FLAG) {
        value->data = WT_PAGE_REF_OFFSET(page, WT_KV_DECODE_VALUE_OFFSET(v));
        value->size = WT_KV_DECODE_VALUE_LEN(v);
        return (true);
    }
    return (false);
}

/*
 * __wt_row_leaf_value --
 *     Return the value for a row-store leaf page encoded key/value pair.
 */
static inline bool
__wt_row_leaf_value(WT_PAGE *page, WT_ROW *rip, WT_ITEM *value)
{
    uintptr_t v;

    /* The row-store key can change underfoot; explicitly take a copy. */
    v = (uintptr_t)WT_ROW_KEY_COPY(rip);

    /*
     * See the comment in __wt_row_leaf_key_info for an explanation of the magic.
     */
    if ((v & 0x03) == WT_KV_FLAG) {
        value->data = WT_PAGE_REF_OFFSET(page, WT_KV_DECODE_VALUE_OFFSET(v));
        value->size = WT_KV_DECODE_VALUE_LEN(v);
        return (true);
    }
    return (false);
}

/*
 * __wt_buf_grow_worker --
 *     Grow a buffer that may be in-use, and ensure that all data is local to the buffer.
 */
int
__wt_buf_grow_worker(WT_SESSION_IMPL *session, WT_ITEM *buf, size_t size)
  WT_GCC_FUNC_ATTRIBUTE((visibility("default")))
{
    size_t offset;
    bool copy_data;

    /*
     * Maintain the existing data: there are 3 cases:
     *	No existing data: allocate the required memory, and initialize
     * the data to reference it.
     *	Existing data local to the buffer: set the data to the same
     * offset in the re-allocated memory.
     *	Existing data not-local to the buffer: copy the data into the
     * buffer and set the data to reference it.
     */
    if (WT_DATA_IN_ITEM(buf)) {
        offset = WT_PTRDIFF(buf->data, buf->mem);
        copy_data = false;
    } else {
        offset = 0;
        copy_data = buf->size > 0;
    }

    /*
     * This function is also used to ensure data is local to the buffer, check to see if we actually
     * need to grow anything.
     */
    if (size > buf->memsize) {
        RET_MSG(-1, "__wt_buf_grow_worker: We should never enter this!");
        // if (F_ISSET(buf, WT_ITEM_ALIGNED))
        //     WT_RET(__wt_realloc_aligned(session, &buf->memsize, size, &buf->mem));
        // else
        //     WT_RET(__wt_realloc_noclear(session, &buf->memsize, size, &buf->mem));
    }

    if (buf->data == NULL) {
        buf->data = buf->mem;
        buf->size = 0;
    } else {
        if (copy_data)
            memcpy(buf->mem, buf->data, buf->size);
        buf->data = (uint8_t *)buf->mem + offset;
    }

    return (0);
}

/*
 * __wt_buf_grow --
 *     Grow a buffer that may be in-use, and ensure that all data is local to the buffer.
 */
static inline int
__wt_buf_grow(WT_SESSION_IMPL *session, WT_ITEM *buf, size_t size)
{
    return (
      size > buf->memsize || !WT_DATA_IN_ITEM(buf) ? __wt_buf_grow_worker(session, buf, size) : 0);
}

/*
 * __wt_buf_set --
 *     Set the contents of the buffer.
 */
static inline int
__wt_buf_set(WT_SESSION_IMPL *session, WT_ITEM *buf, const void *data, size_t size)
{
    /*
     * The buffer grow function does what we need, but expects the data to be referenced by the
     * buffer. If we're copying data from outside the buffer, set it up so it makes sense to the
     * buffer grow function. (No test needed, this works if WT_ITEM.data is already set to "data".)
     */
    buf->data = data;
    buf->size = size;
    return (__wt_buf_grow(session, buf, size));
}


/*
 * __wt_value_return_buf --
 *     Change a buffer to reference an internal original-page return value.
 */
int
__wt_value_return_buf(WT_CURSOR_BTREE *cbt, WT_REF *ref, WT_ITEM *buf, WT_TIME_WINDOW *tw)
{
    WT_BTREE *btree;
    WT_CELL *cell;
    // WT_CELL_UNPACK_KV unpack;
    WT_CURSOR *cursor;
    WT_PAGE *page;
    WT_ROW *rip;
    WT_SESSION_IMPL *session;
    uint8_t v;

    session = CUR2S(cbt);
    btree = S2BT(session);

    page = ref->page;
    cursor = &cbt->iface;

    if (page->type == WT_PAGE_ROW_LEAF) {
        rip = &page->pg_row[cbt->slot];

        /*
         * If a value is simple and is globally visible at the time of reading a page into cache, we
         * encode its location into the WT_ROW.
         */
        if (__wt_row_leaf_value(page, rip, buf)) {
            if (tw != NULL)
                WT_TIME_WINDOW_INIT(tw);
            return (0);
        }

        // NOTE: This should never happen!
        RET_MSG(-1, "__wt_value_return_buf: invalid path");

        // /* Take the value from the original page cell. */
        // __wt_row_leaf_value_cell(session, page, rip, NULL, &unpack);
        // if (tw != NULL)
        //     WT_TIME_WINDOW_COPY(tw, &unpack.tw);
        // return (__wt_page_cell_data_ref(session, page, &unpack, buf));
    }

    if (page->type == WT_PAGE_COL_VAR) {
        // NOTE: We should never enter this!
        RET_MSG(-1, "__wt_value_return_buf: variable column store variable");
        // /* Take the value from the original page cell. */
        // cell = WT_COL_PTR(page, &page->pg_var[cbt->slot]);
        // __wt_cell_unpack_kv(session, page->dsk, cell, &unpack);
        // if (tw != NULL)
        //     WT_TIME_WINDOW_COPY(tw, &unpack.tw);
        // return (__wt_page_cell_data_ref(session, page, &unpack, buf));
    }

    /*
     * WT_PAGE_COL_FIX: Take the value from the original page.
     *
     * FIXME-WT-6126: Should also check visibility here
     */
    if (tw != NULL)
        WT_TIME_WINDOW_INIT(tw);
    v = __bit_getv_recno(ref, cursor->recno, btree->bitcnt);
    return (__wt_buf_set(session, buf, &v, 1));
}


/*
 * __value_return --
 *     Change the cursor to reference an internal original-page return value.
 */
static inline int
__value_return(WT_CURSOR_BTREE *cbt)
{
    return (__wt_value_return_buf(cbt, cbt->ref, &cbt->iface.value, NULL));
}

/*
 * __wt_value_return --
 *     Change the cursor to reference an update return value.
 */
int
__wt_value_return(WT_CURSOR_BTREE *cbt, WT_UPDATE_VALUE *upd_value)
{
    WT_CURSOR *cursor;
    WT_SESSION_IMPL *session;

    cursor = &cbt->iface;
    session = CUR2S(cbt);

    F_CLR(cursor, WT_CURSTD_VALUE_EXT);
    if (upd_value->type == WT_UPDATE_INVALID) {
        /*
         * FIXME-WT-6127: This is a holdover from the pre-durable history read logic where we used
         * to fallback to the on-page value if we didn't find a visible update elsewhere. This is
         * still required for fixed length column store as we have issues with this table type in
         * durable history which we're planning to address in PM-1814.
         */
        WT_ASSERT(session, CUR2BT(cbt)->type == BTREE_COL_FIX);
        WT_RET(__value_return(cbt));
    } else {
        /*
         * We're passed a "standard" update that's visible to us. Our caller should have already
         * checked for deleted items (we're too far down the call stack to return not-found) and any
         * modify updates should be have been reconstructed into a full standard update.
         */
        WT_ASSERT(session, upd_value->type == WT_UPDATE_STANDARD);
        cursor->value.data = upd_value->buf.data;
        cursor->value.size = upd_value->buf.size;
    }
    F_SET(cursor, WT_CURSTD_VALUE_INT);
    return (0);
}

/*
 * __wt_upd_value_clear --
 *     Clear an update value to its defaults.
 */
static inline void
__wt_upd_value_clear(WT_UPDATE_VALUE *upd_value)
{
    /*
     * Make sure we don't touch the memory pointers here. If we have some allocated memory, that
     * could come in handy next time we need to write to the buffer.
     */
    upd_value->buf.data = NULL;
    upd_value->buf.size = 0;
    WT_TIME_WINDOW_INIT(&upd_value->tw);
    upd_value->type = WT_UPDATE_INVALID;
}

/*
 * __wt_cell_type --
 *     Return the cell's type (collapsing special types).
 */
static inline u_int
__wt_cell_type(WT_CELL *cell)
{
    u_int type;

    switch (WT_CELL_SHORT_TYPE(cell->__chunk[0])) {
    case WT_CELL_KEY_SHORT:
    case WT_CELL_KEY_SHORT_PFX:
        return (WT_CELL_KEY);
    case WT_CELL_VALUE_SHORT:
        return (WT_CELL_VALUE);
    }

    switch (type = WT_CELL_TYPE(cell->__chunk[0])) {
    case WT_CELL_KEY_PFX:
        return (WT_CELL_KEY);
    case WT_CELL_KEY_OVFL_RM:
        return (WT_CELL_KEY_OVFL);
    case WT_CELL_VALUE_OVFL_RM:
        return (WT_CELL_VALUE_OVFL);
    }
    return (type);
}

/*
 * __txn_visible_id --
 *     Can the current transaction see the given ID?
 */
static inline bool
__txn_visible_id(WT_SESSION_IMPL *session, uint64_t id)
{
    WT_TXN *txn;
    bool found;

    txn = session->txn;

    /* Changes with no associated transaction are always visible. */
    if (id == WT_TXN_NONE)
        return (true);

    /* Nobody sees the results of aborted transactions. */
    if (id == WT_TXN_ABORTED)
        return (false);

    /* Transactions see their own changes. */
    if (id == txn->id)
        return (true);

    /* Read-uncommitted transactions see all other changes. */
    if (txn->isolation == WT_ISO_READ_UNCOMMITTED)
        return (true);

    RET_MSG(false, "__txn_visible_id: We are read-uncommitted, why are we here?!");
    // NOTE: We are read-uncommitted and should never do the rest.
    // /* Otherwise, we should be called with a snapshot. */
    // WT_ASSERT(session, F_ISSET(txn, WT_TXN_HAS_SNAPSHOT) || session->dhandle->checkpoint != NULL);

    // /*
    //  * WT_ISO_SNAPSHOT, WT_ISO_READ_COMMITTED: the ID is visible if it is not the result of a
    //  * concurrent transaction, that is, if was committed before the snapshot was taken.
    //  *
    //  * The order here is important: anything newer than the maximum ID we saw when taking the
    //  * snapshot should be invisible, even if the snapshot is empty.
    //  */
    // if (WT_TXNID_LE(txn->snap_max, id))
    //     return (false);
    // if (txn->snapshot_count == 0 || WT_TXNID_LT(id, txn->snap_min))
    //     return (true);

    // WT_BINARY_SEARCH(id, txn->snapshot, txn->snapshot_count, found);
    // return (!found);
}


/*
 * __wt_txn_visible --
 *     Can the current transaction see the given ID / timestamp?
 */
static inline bool
__wt_txn_visible(WT_SESSION_IMPL *session, uint64_t id, wt_timestamp_t timestamp)
{
    WT_TXN *txn;
    WT_TXN_SHARED *txn_shared;

    txn = session->txn;
    txn_shared = WT_SESSION_TXN_SHARED(session);

    if (!__txn_visible_id(session, id))
        return (false);

    /* Transactions read their writes, regardless of timestamps. */
    if (F_ISSET(session->txn, WT_TXN_HAS_ID) && id == session->txn->id)
        return (true);

    /* Timestamp check. */
    if (!F_ISSET(txn, WT_TXN_SHARED_TS_READ) || timestamp == WT_TS_NONE)
        return (true);

    return (timestamp <= txn_shared->read_timestamp);
}


/*
 * __wt_txn_upd_visible_type --
 *     Visible type of given update for the current transaction.
 */
static inline WT_VISIBLE_TYPE
__wt_txn_upd_visible_type(WT_SESSION_IMPL *session, WT_UPDATE *upd)
{
    uint8_t prepare_state, previous_state;
    bool upd_visible;

    for (int i = 0; i < 1; i++) {
        /* Prepare state change is in progress, yield and try again. */
        WT_ORDERED_READ(prepare_state, upd->prepare_state);
        if (prepare_state == WT_PREPARE_LOCKED)
            continue;

        if (WT_IS_HS(S2BT(session)) && upd->txnid != WT_TXN_ABORTED &&
          upd->type == WT_UPDATE_STANDARD)
            RET_MSG(-1, "__wt_txn_upd_visible_type: invalid path");
          // NOTE: Should never enter this!
            /* Entries in the history store are always visible. */
            // return (WT_VISIBLE_TRUE);

        upd_visible = __wt_txn_visible(session, upd->txnid, upd->start_ts);

        /*
         * The visibility check is only valid if the update does not change state. If the state does
         * change, recheck visibility.
         */
        previous_state = prepare_state;
        WT_ORDERED_READ(prepare_state, upd->prepare_state);
        if (previous_state == prepare_state)
            break;

        // WT_STAT_CONN_INCR(session, prepared_transition_blocked_page);
        RET(WT_VISIBLE_FALSE, "__wt_txn_upd_visible_type: Why did this not immediately succeed?");
    }

    if (!upd_visible)
        return (WT_VISIBLE_FALSE);

    if (prepare_state == WT_PREPARE_INPROGRESS)
        return (WT_VISIBLE_PREPARE);

    return (WT_VISIBLE_TRUE);
}

/*
 * __wt_upd_value_assign --
 *     Point an update value at a given update. We're specifically not getting the value to own the
 *     memory since this exists in an update list somewhere.
 */
static inline void
__wt_upd_value_assign(WT_UPDATE_VALUE *upd_value, WT_UPDATE *upd)
{
    if (!upd_value->skip_buf) {
        upd_value->buf.data = upd->data;
        upd_value->buf.size = upd->size;
    }
    if (upd->type == WT_UPDATE_TOMBSTONE) {
        upd_value->tw.durable_stop_ts = upd->durable_ts;
        upd_value->tw.stop_ts = upd->start_ts;
        upd_value->tw.stop_txn = upd->txnid;
        upd_value->tw.prepare =
          upd->prepare_state == WT_PREPARE_INPROGRESS || upd->prepare_state == WT_PREPARE_LOCKED;
    } else {
        upd_value->tw.durable_start_ts = upd->durable_ts;
        upd_value->tw.start_ts = upd->start_ts;
        upd_value->tw.start_txn = upd->txnid;
        upd_value->tw.prepare =
          upd->prepare_state == WT_PREPARE_INPROGRESS || upd->prepare_state == WT_PREPARE_LOCKED;
    }
    upd_value->type = upd->type;
}


/*
 * __wt_txn_read_upd_list --
 *     Get the first visible update in a list (or NULL if none are visible).
 */
static inline int
__wt_txn_read_upd_list(
  WT_SESSION_IMPL *session, WT_CURSOR_BTREE *cbt, WT_UPDATE *upd, WT_UPDATE **prepare_updp)
{
    WT_VISIBLE_TYPE upd_visible;
    uint8_t type;

    if (prepare_updp != NULL)
        *prepare_updp = NULL;
    __wt_upd_value_clear(cbt->upd_value);

    for (; upd != NULL; upd = upd->next) {
        WT_ORDERED_READ(type, upd->type);
        /* Skip reserved place-holders, they're never visible. */
        if (type == WT_UPDATE_RESERVE)
            continue;

        /*
         * If the cursor is configured to ignore tombstones, copy the timestamps from the tombstones
         * to the stop time window of the update value being returned to the caller. Caller can
         * process the stop time window to decide if there was a tombstone on the update chain. If
         * the time window already has a stop time set then we must've seen a tombstone prior to
         * ours in the update list, and therefore don't need to do this again.
         */
        if (type == WT_UPDATE_TOMBSTONE && F_ISSET(&cbt->iface, WT_CURSTD_IGNORE_TOMBSTONE) &&
          !WT_TIME_WINDOW_HAS_STOP(&cbt->upd_value->tw)) {
            cbt->upd_value->tw.durable_stop_ts = upd->durable_ts;
            cbt->upd_value->tw.stop_ts = upd->start_ts;
            cbt->upd_value->tw.stop_txn = upd->txnid;
            cbt->upd_value->tw.prepare = upd->prepare_state == WT_PREPARE_INPROGRESS ||
              upd->prepare_state == WT_PREPARE_LOCKED;
            continue;
        }

        upd_visible = __wt_txn_upd_visible_type(session, upd);

        if (upd_visible == WT_VISIBLE_TRUE)
            break;

        if (upd_visible == WT_VISIBLE_PREPARE) {
            /* Ignore the prepared update, if transaction configuration says so. */
            if (F_ISSET(session->txn, WT_TXN_IGNORE_PREPARE)) {
                /*
                 * Save the prepared update to help us detect if we race with prepared commit or
                 * rollback.
                 */
                if (prepare_updp != NULL && *prepare_updp == NULL &&
                  F_ISSET(upd, WT_UPDATE_PREPARE_RESTORED_FROM_DS))
                    *prepare_updp = upd;
                continue;
            }
            return (WT_PREPARE_CONFLICT);
        }
    }

    if (upd == NULL)
        return (0);

    /*
     * Now assign to the update value. If it's not a modify, we're free to simply point the value at
     * the update's memory without owning it. If it is a modify, we need to reconstruct the full
     * update now and make the value own the buffer.
     *
     * If the caller has specifically asked us to skip assigning the buffer, we shouldn't bother
     * reconstructing the modify.
     */
    if (upd->type != WT_UPDATE_MODIFY || cbt->upd_value->skip_buf)
        __wt_upd_value_assign(cbt->upd_value, upd);
    else
        RET_MSG(-1, "__wt_txn_read_upd_list: Why do we have partial updates?");
        // NOTE: We should never have partial updates!
        // WT_RET(__wt_modify_reconstruct_from_upd_list(session, cbt, upd, cbt->upd_value));
    return (0);
}


/*
 * __wt_txn_read --
 *     Get the first visible update in a chain. This function will first check the update list
 *     supplied as a function argument. If there is no visible update, it will check the onpage
 *     value for the given key. Finally, if the onpage value is not visible to the reader, the
 *     function will search the history store for a visible update.
 */
static inline int
__wt_txn_read(WT_SESSION_IMPL *session, WT_CURSOR_BTREE *cbt, WT_ITEM *key, uint64_t recno,
  WT_UPDATE *upd, WT_CELL_UNPACK_KV *vpack)
{
    WT_TIME_WINDOW tw;
    WT_UPDATE *prepare_upd;
    bool have_stop_tw;
    prepare_upd = NULL;

    WT_RET(__wt_txn_read_upd_list(session, cbt, upd, &prepare_upd));
    if (WT_UPDATE_DATA_VALUE(cbt->upd_value) ||
      (cbt->upd_value->type == WT_UPDATE_MODIFY && cbt->upd_value->skip_buf))
        return (0);
    WT_ASSERT(session, cbt->upd_value->type == WT_UPDATE_INVALID);

    /* If there is no ondisk value, there can't be anything in the history store either. */
    if (cbt->ref->page->dsk == NULL || cbt->slot == UINT32_MAX) {
        cbt->upd_value->type = WT_UPDATE_TOMBSTONE;
        return (0);
    }

    /*
     * When we inspected the update list we may have seen a tombstone leaving us with a valid stop
     * time window, we don't want to overwrite this stop time window.
     */
    have_stop_tw = WT_TIME_WINDOW_HAS_STOP(&cbt->upd_value->tw);

    /* Check the ondisk value. */
    if (vpack == NULL) {
        WT_TIME_WINDOW_INIT(&tw);
        WT_RET(__wt_value_return_buf(cbt, cbt->ref, &cbt->upd_value->buf, &tw));
    } else {
        WT_TIME_WINDOW_COPY(&tw, &vpack->tw);
        cbt->upd_value->buf.data = vpack->data;
        cbt->upd_value->buf.size = vpack->size;
    }

    /*
     * If the stop time point is set, that means that there is a tombstone at that time. If it is
     * not prepared and it is visible to our txn it means we've just spotted a tombstone and should
     * return "not found", except scanning the history store during rollback to stable and when we
     * are told to ignore non-globally visible tombstones.
     */
    if (!have_stop_tw && __wt_txn_tw_stop_visible(session, &tw) &&
      !F_ISSET(&cbt->iface, WT_CURSTD_IGNORE_TOMBSTONE)) {
        cbt->upd_value->buf.data = NULL;
        cbt->upd_value->buf.size = 0;
        cbt->upd_value->tw.durable_stop_ts = tw.durable_stop_ts;
        cbt->upd_value->tw.stop_ts = tw.stop_ts;
        cbt->upd_value->tw.stop_txn = tw.stop_txn;
        cbt->upd_value->tw.prepare = tw.prepare;
        cbt->upd_value->type = WT_UPDATE_TOMBSTONE;
        return (0);
    }

    /* Store the stop time pair of the history store record that is returning. */
    if (!have_stop_tw && WT_TIME_WINDOW_HAS_STOP(&tw) && WT_IS_HS(S2BT(session))) {
        cbt->upd_value->tw.durable_stop_ts = tw.durable_stop_ts;
        cbt->upd_value->tw.stop_ts = tw.stop_ts;
        cbt->upd_value->tw.stop_txn = tw.stop_txn;
        cbt->upd_value->tw.prepare = tw.prepare;
    }

    /* If the start time point is visible then we need to return the ondisk value. */
    if (WT_IS_HS(S2BT(session)) || __wt_txn_tw_start_visible(session, &tw)) {
        if (cbt->upd_value->skip_buf) {
            cbt->upd_value->buf.data = NULL;
            cbt->upd_value->buf.size = 0;
        }
        cbt->upd_value->tw.durable_start_ts = tw.durable_start_ts;
        cbt->upd_value->tw.start_ts = tw.start_ts;
        cbt->upd_value->tw.start_txn = tw.start_txn;
        cbt->upd_value->tw.prepare = tw.prepare;
        cbt->upd_value->type = WT_UPDATE_STANDARD;
        return (0);
    }

    /* If there's no visible update in the update chain or ondisk, check the history store file. */
    if (F_ISSET(S2C(session), WT_CONN_HS_OPEN) && !F_ISSET(S2BT(session), WT_BTREE_HS))
        WT_RET_NOTFOUND_OK(__wt_hs_find_upd(session, key, cbt->iface.value_format, recno,
          cbt->upd_value, false, &cbt->upd_value->buf));

    /*
     * Retry if we race with prepared commit or rollback. If we race with prepared rollback, the
     * value the reader should read may have been removed from the history store and appended to the
     * data store. If we race with prepared commit, imagine a case we read with timestamp 50 and we
     * have a prepared update with timestamp 30 and a history store record with timestamp 20,
     * committing the prepared update will cause the stop timestamp of the history store record
     * being updated to 30 and the reader not seeing it.
     */
    if (prepare_upd != NULL) {
        WT_ASSERT(session, F_ISSET(prepare_upd, WT_UPDATE_PREPARE_RESTORED_FROM_DS));
        if (prepare_upd->txnid == WT_TXN_ABORTED ||
          prepare_upd->prepare_state == WT_PREPARE_RESOLVED)
            return (WT_RESTART);
    }

    /* Return invalid not tombstone if nothing is found in history store. */
    WT_ASSERT(session, cbt->upd_value->type != WT_UPDATE_TOMBSTONE);
    return (0);
}



/*
 * __wt_cursor_valid --
 *     Return if the cursor references an valid key/value pair.
 */
int
__wt_cursor_valid(WT_CURSOR_BTREE *cbt, WT_ITEM *key, uint64_t recno, bool *valid)
{
    WT_BTREE *btree;
    WT_CELL *cell;
    WT_COL *cip;
    WT_PAGE *page;
    WT_SESSION_IMPL *session;

    *valid = false;

    btree = CUR2BT(cbt);
    page = cbt->ref->page;
    session = CUR2S(cbt);

    /*
     * We may be pointing to an insert object, and we may have a page with
     * existing entries.  Insert objects always have associated update
     * objects (the value).  Any update object may be deleted, or invisible
     * to us.  In the case of an on-page entry, there is by definition a
     * value that is visible to us, the original page cell.
     *
     * If we find a visible update structure, return our caller a reference
     * to it because we don't want to repeatedly search for the update, it
     * might suddenly become invisible (imagine a read-uncommitted session
     * with another session's aborted insert), and we don't want to handle
     * that potential error every time we look at the value.
     *
     * Unfortunately, the objects we might have and their relationships are
     * different for the underlying page types.
     *
     * In the case of row-store, an insert object implies ignoring any page
     * objects, no insert object can have the same key as an on-page object.
     * For row-store:
     *	if there's an insert object:
     *		if there's a visible update:
     *			exact match
     *		else
     *			no exact match
     *	else
     *		use the on-page object (which may have an associated
     *		update object that may or may not be visible to us).
     *
     * Column-store is more complicated because an insert object can have
     * the same key as an on-page object: updates to column-store rows
     * are insert/object pairs, and an invisible update isn't the end as
     * there may be an on-page object that is visible.  This changes the
     * logic to:
     *	if there's an insert object:
     *		if there's a visible update:
     *			exact match
     *		else if the on-page object's key matches the insert key
     *			use the on-page object
     *	else
     *		use the on-page object
     *
     * First, check for an insert object with a visible update (a visible
     * update that's been deleted is not a valid key/value pair).
     */
    // TODO: Add skiplist support
    if (cbt->ins != NULL) {
        RET_MSG(-1, "__wt_cursor_valid: Skiplist support not added yet!");
        // WT_RET(__wt_txn_read_upd_list(session, cbt, cbt->ins->upd, NULL));
        // if (cbt->upd_value->type != WT_UPDATE_INVALID) {
        //     if (cbt->upd_value->type == WT_UPDATE_TOMBSTONE)
        //         return (0);
        //     *valid = true;
        //     return (0);
        // }
    }

    /*
     * Clean out any stale value here. Calling a transaction read helper automatically clears this
     * but we have some code paths that don't do this (fixed length column store is one example).
     */
    __wt_upd_value_clear(cbt->upd_value);

    /*
     * If we don't have an insert object, or in the case of column-store, there's an insert object
     * but no update was visible to us and the key on the page is the same as the insert object's
     * key, and the slot as set by the search function is valid, we can use the original page
     * information.
     */
    switch (btree->type) {
    case BTREE_COL_FIX:
        // NOTE: Bloom filters not yet implemented.
        RET_MSG(-1, "__wt_cursor_valid: Bloom filters not yet implemented");
        /*
         * If search returned an insert object, there may or may not be a matching on-page object,
         * we have to check. Fixed-length column-store pages don't have slots, but map one-to-one to
         * keys, check for retrieval past the end of the page.
         */
        if (cbt->recno >= cbt->ref->ref_recno + page->entries)
            return (0);

        *valid = true;
        /*
         * An update would have appeared as an "insert" object; no further checks to do.
         */
        break;
    case BTREE_COL_VAR:
        // NOTE: We'll never enter this!
        RET_MSG(-1, "__wt_cursor_valid: BTREE_COL_VAR path!");

        // /* The search function doesn't check for empty pages. */
        // if (page->entries == 0)
        //     return (0);
        // /*
        //  * In case of prepare conflict, the slot might not have a valid value, if the update in the
        //  * insert list of a new page scanned is in prepared state.
        //  */
        // // WT_ASSERT(session, cbt->slot == UINT32_MAX || cbt->slot < page->entries);

        // /*
        //  * Column-store updates are stored as "insert" objects. If search returned an insert object
        //  * we can't return, the returned on-page object must be checked for a match.
        //  */
        // if (cbt->ins != NULL && !F_ISSET(cbt, WT_CBT_VAR_ONPAGE_MATCH))
        //     return (0);

        // /*
        //  * Although updates would have appeared as an "insert" objects, variable-length column store
        //  * deletes are written into the backing store; check the cell for a record already deleted
        //  * when read.
        //  */
        // cip = &page->pg_var[cbt->slot];
        // cell = WT_COL_PTR(page, cip);
        // if (__wt_cell_type(cell) == WT_CELL_DEL)
        //     return (0);

        // /*
        //  * Check for an update ondisk or in the history store. For column store, an insert object
        //  * can have the same key as an on-page or history store object.
        //  */
        // WT_RET(__wt_txn_read(session, cbt, key, recno, NULL, NULL));
        // if (cbt->upd_value->type != WT_UPDATE_INVALID) {
        //     if (cbt->upd_value->type == WT_UPDATE_TOMBSTONE)
        //         return (0);
        //     *valid = true;
        // }
        break;
    case BTREE_ROW:
        /* The search function doesn't check for empty pages. */
        if (page->entries == 0)
            return (0);
        /*
         * In case of prepare conflict, the slot might not have a valid value, if the update in the
         * insert list of a new page scanned is in prepared state.
         */
        // WT_ASSERT(session, cbt->slot == UINT32_MAX || cbt->slot < page->entries);

        /*
         * See above: for row-store, no insert object can have the same key as an on-page object,
         * we're done.
         */
        // TODO: Skiplist support
        if (cbt->ins != NULL) RET_MSG(-1, "__wt_cursor_valid")
            // return (0);

        /* Check for an update. */
        WT_RET(__wt_txn_read(session, cbt, key, WT_RECNO_OOB,
          (page->modify != NULL && page->modify->mod_row_update != NULL) ?
            page->modify->mod_row_update[cbt->slot] :
            NULL,
          NULL));
        if (cbt->upd_value->type != WT_UPDATE_INVALID) {
            if (cbt->upd_value->type == WT_UPDATE_TOMBSTONE)
                return (0);
            *valid = true;
        }
        break;
    }
    return (0);
}



/*
 * __cursor_fix_implicit --
 *     Return if search went past the end of the tree.
 */
static inline bool
__cursor_fix_implicit(WT_BTREE *btree, WT_CURSOR_BTREE *cbt)
{
    /*
     * When there's no exact match, column-store search returns the key nearest the searched-for key
     * (continuing past keys smaller than the searched-for key to return the next-largest key).
     * Therefore, if the returned comparison is -1, the searched-for key was larger than any row on
     * the page's standard information or column-store insert list.
     *
     * If the returned comparison is NOT -1, there was a row equal to or larger than the
     * searched-for key, and we implicitly create missing rows.
     */
    return (btree->type == BTREE_COL_FIX && cbt->compare != -1);
}


/*
 * __cursor_kv_return --
 *     Return a page referenced key/value pair to the application.
 */
static inline int
__cursor_kv_return(WT_CURSOR_BTREE *cbt, WT_UPDATE_VALUE *upd_value)
{
    WT_RET(__wt_key_return(cbt));
    WT_RET(__wt_value_return(cbt, upd_value));

    return (0);
}


/*
 * __wt_cursor_kv_not_set --
 *     Standard error message for key/values not set.
 */
int
__wt_cursor_kv_not_set(WT_CURSOR *cursor, bool key) WT_GCC_FUNC_ATTRIBUTE((cold))
{
    WT_SESSION_IMPL *session;

    session = CUR2S(cursor);

    WT_RET_MSG(session, cursor->saved_err == 0 ? EINVAL : cursor->saved_err, "requires %s be set",
      key ? "key" : "value");
}

/*
 * __wt_cursor_get_valuev --
 *     WT_CURSOR->get_value worker implementation.
 */
int
__wt_cursor_get_valuev(WT_CURSOR *cursor, va_list ap)
{
    WT_DECL_RET;
    WT_ITEM *value;
    WT_SESSION_IMPL *session;
    const char *fmt;

    CURSOR_API_CALL(cursor, session, get_value, NULL);

    if (!F_ISSET(cursor, WT_CURSTD_VALUE_EXT | WT_CURSTD_VALUE_INT))
        WT_ERR(__wt_cursor_kv_not_set(cursor, false));

    // NOTE: No debug mode!
    // /* Force an allocated copy when using cursor copy debug. */
    // if (FLD_ISSET(S2C(session)->debug_flags, WT_CONN_DEBUG_CURSOR_COPY))
    //     WT_ERR(__wt_buf_grow(session, &cursor->value, cursor->value.size));

    /* Fast path some common cases. */
    fmt = cursor->value_format;
    if (F_ISSET(cursor, WT_CURSOR_RAW_OK) || WT_STREQ(fmt, "u")) {
        value = va_arg(ap, WT_ITEM *);
        value->data = cursor->value.data;
        value->size = cursor->value.size;
    } else if (WT_STREQ(fmt, "S"))
        *va_arg(ap, const char **) = cursor->value.data;
    else if (WT_STREQ(fmt, "t") || (__wt_isdigit((u_char)fmt[0]) && WT_STREQ(fmt + 1, "t")))
        *va_arg(ap, uint8_t *) = *(uint8_t *)cursor->value.data;
    else
        // NOTE: This should never happen!
        // ret = __wt_struct_unpackv(session, cursor->value.data, cursor->value.size, fmt, ap);
err:
    API_END_RET(session, ret);
}



/*
 * __wt_cursor_get_value --
 *     WT_CURSOR->get_value default implementation.
 */
int
__wt_cursor_get_value(WT_CURSOR *cursor, ...)
{
    WT_DECL_RET;
    va_list ap;

    va_start(ap, cursor);
    ret = __wt_cursor_get_valuev(cursor, ap);
    va_end(ap);
    return (ret);
}

/*
 * __wt_cursor_get_keyv --
 *     WT_CURSOR->get_key worker function.
 */
int
__wt_cursor_get_keyv(WT_CURSOR *cursor, uint32_t flags, va_list ap)
{
    WT_DECL_RET;
    WT_ITEM *key;
    WT_SESSION_IMPL *session;
    size_t size;
    const char *fmt;

    CURSOR_API_CALL(cursor, session, get_key, NULL);
    if (!F_ISSET(cursor, WT_CURSTD_KEY_SET))
        WT_ERR(__wt_cursor_kv_not_set(cursor, true));

    // NOTE: No debug mode!
    // /* Force an allocated copy when using cursor copy debug. */
    // if (FLD_ISSET(S2C(session)->debug_flags, WT_CONN_DEBUG_CURSOR_COPY))
    //     WT_ERR(__wt_buf_grow(session, &cursor->key, cursor->key.size));

    if (WT_CURSOR_RECNO(cursor)) {
        if (LF_ISSET(WT_CURSTD_RAW)) {
            // We should never enter this
            RET_MSG(-1, "__wt_cursor_get_keyv: WT_CURSTD_RAW!");
            // key = va_arg(ap, WT_ITEM *);
            // key->data = cursor->raw_recno_buf;
            // WT_ERR(__wt_struct_size(session, &size, "q", cursor->recno));
            // key->size = size;
            // ret = __wt_struct_pack(
            //   session, cursor->raw_recno_buf, sizeof(cursor->raw_recno_buf), "q", cursor->recno);
        } else
            *va_arg(ap, uint64_t *) = cursor->recno;
    } else {
        /* Fast path some common cases. */
        fmt = cursor->key_format;
        if (LF_ISSET(WT_CURSOR_RAW_OK) || WT_STREQ(fmt, "u")) {
            key = va_arg(ap, WT_ITEM *);
            key->data = cursor->key.data;
            key->size = cursor->key.size;
        } else if (WT_STREQ(fmt, "S"))
            *va_arg(ap, const char **) = cursor->key.data;
        else
            RET_MSG(-1, "__wt_cursor_get_keyv: unexpected path");
            // NOTE: Unused
            // ret = __wt_struct_unpackv(session, cursor->key.data, cursor->key.size, fmt, ap);
    }

err:
    API_END_RET(session, ret);
}



/*
 * __wt_cursor_get_key --
 *     WT_CURSOR->get_key default implementation.
 */
int
__wt_cursor_get_key(WT_CURSOR *cursor, ...)
{
    WT_DECL_RET;
    va_list ap;

    va_start(ap, cursor);
    ret = __wt_cursor_get_keyv(cursor, cursor->flags, ap);
    va_end(ap);
    return (ret);
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
            str = va_arg(ap, const char *);
            sz = strlen(str) + 1;
            buf->data = (void *)str;
        } else {
            // We should never enter this!
            RET_MSG(-1, "__wt_cursor_set_keyv: custom struct!");
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
 * __wt_row_leaf_key_info --
 *     Return a row-store leaf page key referenced by a WT_ROW if it can be had without unpacking a
 *     cell, and information about the cell, if the key isn't cheaply available.
 */
static inline bool
__wt_row_leaf_key_info(
  WT_PAGE *page, void *copy, WT_IKEY **ikeyp, WT_CELL **cellp, void *datap, size_t *sizep)
{
    WT_IKEY *ikey;
    uintptr_t v;

    v = (uintptr_t)copy;

/*
 * A row-store leaf page key is in one of two places: if instantiated,
 * the WT_ROW pointer references a WT_IKEY structure, otherwise, it
 * references an on-page offset.  Further, on-page keys are in one of
 * two states: if the key is a simple key (not an overflow key, prefix
 * compressed or Huffman encoded, all of which are likely), the key's
 * offset/size is encoded in the pointer.  Otherwise, the offset is to
 * the key's on-page cell.
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
 * In this specific case, we use bit 0x01 to mark an on-page cell, bit
 * 0x02 to mark an on-page key, 0x03 to mark an on-page key/value pair,
 * otherwise it's a WT_IKEY reference. The bit pattern for on-page cells
 * is:
 *	29 bits		page offset of the key's cell,
 *	 2 bits		flags
 *
 * The bit pattern for on-page keys is:
 *	32 bits		key length,
 *	29 bits		page offset of the key's bytes,
 *	 2 bits		flags
 *
 * But, while that allows us to skip decoding simple key cells, we also
 * want to skip decoding the value cell in the case where the value cell
 * is also simple/short.  We use bit 0x03 to mark an encoded on-page key
 * and value pair.  The bit pattern for on-page key/value pairs is:
 *	 9 bits		key length,
 *	13 bits		value length,
 *	20 bits		page offset of the key's bytes,
 *	20 bits		page offset of the value's bytes,
 *	 2 bits		flags
 *
 * These bit patterns are in-memory only, of course, so can be modified
 * (we could even tune for specific workloads).  Generally, the fields
 * are larger than the anticipated values being stored (512B keys, 8KB
 * values, 1MB pages), hopefully that won't be necessary.
 *
 * This function returns a list of things about the key (instantiation
 * reference, cell reference and key/length pair).  Our callers know
 * the order in which we look things up and the information returned;
 * for example, the cell will never be returned if we are working with
 * an on-page key.
 */
#define WT_CELL_FLAG 0x01
#define WT_CELL_ENCODE_OFFSET(v) ((uintptr_t)(v) << 2)
#define WT_CELL_DECODE_OFFSET(v) (((v)&0xFFFFFFFF) >> 2)

#define WT_K_FLAG 0x02
#define WT_K_ENCODE_KEY_LEN(v) ((uintptr_t)(v) << 32)
#define WT_K_DECODE_KEY_LEN(v) ((v) >> 32)
#define WT_K_ENCODE_KEY_OFFSET(v) ((uintptr_t)(v) << 2)
#define WT_K_DECODE_KEY_OFFSET(v) (((v)&0xFFFFFFFF) >> 2)

#define WT_KV_FLAG 0x03
#define WT_KV_ENCODE_KEY_LEN(v) ((uintptr_t)(v) << 55)
#define WT_KV_DECODE_KEY_LEN(v) ((v) >> 55)
#define WT_KV_MAX_KEY_LEN (0x200 - 1)
#define WT_KV_ENCODE_VALUE_LEN(v) ((uintptr_t)(v) << 42)
#define WT_KV_DECODE_VALUE_LEN(v) (((v)&0x007FFC0000000000) >> 42)
#define WT_KV_MAX_VALUE_LEN (0x2000 - 1)
#define WT_KV_ENCODE_KEY_OFFSET(v) ((uintptr_t)(v) << 22)
#define WT_KV_DECODE_KEY_OFFSET(v) (((v)&0x000003FFFFC00000) >> 22)
#define WT_KV_MAX_KEY_OFFSET (0x100000 - 1)
#define WT_KV_ENCODE_VALUE_OFFSET(v) ((uintptr_t)(v) << 2)
#define WT_KV_DECODE_VALUE_OFFSET(v) (((v)&0x00000000003FFFFC) >> 2)
#define WT_KV_MAX_VALUE_OFFSET (0x100000 - 1)
    switch (v & 0x03) {
    case WT_CELL_FLAG:
        /* On-page cell: no instantiated key. */
        if (ikeyp != NULL)
            *ikeyp = NULL;
        if (cellp != NULL)
            *cellp = WT_PAGE_REF_OFFSET(page, WT_CELL_DECODE_OFFSET(v));
        return (false);
    case WT_K_FLAG:
        /* Encoded key: no instantiated key, no cell. */
        if (cellp != NULL)
            *cellp = NULL;
        if (ikeyp != NULL)
            *ikeyp = NULL;
        if (datap != NULL) {
            *(void **)datap = WT_PAGE_REF_OFFSET(page, WT_K_DECODE_KEY_OFFSET(v));
            *sizep = WT_K_DECODE_KEY_LEN(v);
            return (true);
        }
        return (false);
    case WT_KV_FLAG:
        /* Encoded key/value pair: no instantiated key, no cell. */
        if (cellp != NULL)
            *cellp = NULL;
        if (ikeyp != NULL)
            *ikeyp = NULL;
        if (datap != NULL) {
            *(void **)datap = WT_PAGE_REF_OFFSET(page, WT_KV_DECODE_KEY_OFFSET(v));
            *sizep = WT_KV_DECODE_KEY_LEN(v);
            return (true);
        }
        return (false);
    }

    /* Instantiated key. */
    ikey = copy;
    if (ikeyp != NULL)
        *ikeyp = copy;
    if (cellp != NULL)
        *cellp = WT_PAGE_REF_OFFSET(page, ikey->cell_offset);
    if (datap != NULL) {
        *(void **)datap = WT_IKEY_DATA(ikey);
        *sizep = ikey->size;
        return (true);
    }
    return (false);
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
        // NOTE: We should never enter this!
        RET_MSG(-1, "__wt_row_search: insert descend rigth invalid code path");
        // cbt->append_tree = 1;

        // if (page->entries == 0) {
        //     cbt->slot = WT_ROW_SLOT(page, page->pg_row);

        //     F_SET(cbt, WT_CBT_SEARCH_SMALLEST);
        //     ins_head = WT_ROW_INSERT_SMALLEST(page);
        // } else {
        //     cbt->slot = WT_ROW_SLOT(page, page->pg_row + (page->entries - 1));

        //     ins_head = WT_ROW_INSERT_SLOT(page, cbt->slot);
        // }

        // WT_ERR(__search_insert_append(session, cbt, ins_head, srch_key, &done));
        // if (done)
        //     return (0);
    }

    /*
     * Binary search of an leaf page. There are three versions (keys with no application-specified
     * collation order, in long and short versions, and keys with an application-specified collation
     * order), because doing the tests and error handling inside the loop costs about 5%.
     */
    base = 0;
    limit = page->entries;
    if (collator == NULL && srch_key->size <= WT_COMPARE_SHORT_MAXLEN)
        RET_MSG("__wt_row_search: leaf wrong search code path 1");
        // for (; limit != 0; limit >>= 1) {
        //     indx = base + (limit >> 1);
        //     rip = page->pg_row + indx;
        //     WT_ERR(__wt_row_leaf_key(session, page, rip, item, true));

        //     cmp = __wt_lex_compare_short(srch_key, item);
        //     if (cmp > 0) {
        //         base = indx + 1;
        //         --limit;
        //     } else if (cmp == 0)
        //         goto leaf_match;
        // }
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
        RET_MSG("__wt_row_search: leaf wrong search code path 3");
        // for (; limit != 0; limit >>= 1) {
        //     indx = base + (limit >> 1);
        //     rip = page->pg_row + indx;
        //     WT_ERR(__wt_row_leaf_key(session, page, rip, item, true));

        //     WT_ERR(__wt_compare(session, collator, srch_key, item, &cmp));
        //     if (cmp > 0) {
        //         base = indx + 1;
        //         --limit;
        //     } else if (cmp == 0)
        //         goto leaf_match;
        // }

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

    RET_MSG(-1, "skiplists not implemented yet!");

    /*
     * Test for an append first when inserting onto an insert list, try to catch cursors repeatedly
     * inserting at a single point.
     */
    // NOTE: Skiplists not implemented yet!
    // if (insert) {
    //     WT_ERR(__search_insert_append(session, cbt, ins_head, srch_key, &done));
    //     if (done)
    //         return (0);
    // }
    // WT_ERR(__wt_search_insert(session, cbt, ins_head, srch_key));

    // return (0);

err:
    WT_TRET(__wt_page_release(session, current, 0));
    return (ret);
}



/*
 * __wt_row_leaf_key --
 *     Set a buffer to reference a row-store leaf page key as cheaply as possible.
 */
static inline int
__wt_row_leaf_key(
  WT_SESSION_IMPL *session, WT_PAGE *page, WT_ROW *rip, WT_ITEM *key, bool instantiate)
{
    void *copy;

    /*
     * A front-end for __wt_row_leaf_key_work, here to inline fast paths.
     *
     * The row-store key can change underfoot; explicitly take a copy.
     */
    copy = WT_ROW_KEY_COPY(rip);

    /*
     * All we handle here are on-page keys (which should be a common case), and instantiated keys
     * (which start out rare, but become more common as a leaf page is searched, instantiating
     * prefix-compressed keys).
     */
    if (__wt_row_leaf_key_info(page, copy, NULL, NULL, &key->data, &key->size))
        return (0);

    /*
     * The alternative is an on-page cell with some kind of compressed or overflow key that's never
     * been instantiated. Call the underlying worker function to figure it out.
     */
    // NOTE: We don't use prefix compression!
    RET_MSG(-1, "__wt_row_leaf_key: Prefix compression path entered!");
    // return (__wt_row_leaf_key_work(session, page, rip, key, instantiate));
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
            // NOTE: Add when adding Bloom filter support.
            RET_MSG(-1, "__wt_btcur_search: Bloom filter support not implemented yet");
            // WT_ERR(__cursor_col_search(cbt, NULL, NULL));
            // if (cbt->compare == 0)
            //     WT_ERR(__wt_cursor_valid(cbt, NULL, cbt->recno, &valid));
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

/*
 * __curfile_search --
 *     WT_CURSOR->search method for the btree cursor type.
 */
static int
__curfile_search(WT_CURSOR *cursor)
{
    WT_CURSOR_BTREE *cbt;
    WT_DECL_RET;
    WT_SESSION_IMPL *session;
    uint64_t time_start, time_stop;

    cbt = (WT_CURSOR_BTREE *)cursor;
    // NOTE: Records last operation plus some timing stuff. Don't need it.
    // CURSOR_API_CALL(cursor, session, search, CUR2BT(cbt));
    // NOTE: Debugging mode. Skip
    // WT_ERR(__cursor_copy_release(cursor));
    // NOTE: We set the key before, don't check here too.
    // WT_ERR(__cursor_checkkey(cursor));

    // time_start = __wt_clock(session);
    WT_ERR(__wt_btcur_search(cbt));
    // time_stop = __wt_clock(session);
    // __wt_stat_usecs_hist_incr_opread(session, WT_CLOCKDIFF_US(time_stop, time_start));

    /* Search maintains a position, key and value. */
    WT_ASSERT(session, F_ISSET(cbt, WT_CBT_ACTIVE) &&
        F_MASK(cursor, WT_CURSTD_KEY_SET) == WT_CURSTD_KEY_INT &&
        F_MASK(cursor, WT_CURSTD_VALUE_SET) == WT_CURSTD_VALUE_INT);

err:
    // NOTE: Records last operation plus some timing stuff. Don't need it.
    // API_END_RET(session, ret);
}


/*
 * __clsm_lookup --
 *     Position an LSM cursor.
 */
static int
__clsm_lookup(WT_CURSOR_LSM *clsm, WT_ITEM *value)
{
    WT_BLOOM *bloom;
    WT_BLOOM_HASH bhash;
    WT_CURSOR *c, *cursor;
    WT_DECL_RET;
    WT_SESSION_IMPL *session;
    u_int i;
    bool have_hash;

    c = NULL;
    cursor = &clsm->iface;
    have_hash = false;
    session = CUR2S(cursor);

    WT_FORALL_CURSORS(clsm, c, i)
    {
        // NOTE: Skip bloom filters for now!
        /* If there is a Bloom filter, see if we can skip the read. */
        // bloom = NULL;
        // if ((bloom = clsm->chunks[i]->bloom) != NULL) {
        //     if (!have_hash) {
        //         __wt_bloom_hash(bloom, &cursor->key, &bhash);
        //         have_hash = true;
        //     }

        //     WT_ERR_NOTFOUND_OK(__wt_bloom_hash_get(bloom, &bhash), true);
        //     if (ret == WT_NOTFOUND) {
        //         WT_LSM_TREE_STAT_INCR(session, clsm->lsm_tree->bloom_miss);
        //         continue;
        //     }
        //     if (ret == 0)
        //         WT_LSM_TREE_STAT_INCR(session, clsm->lsm_tree->bloom_hit);
        // }

        // Original code:
        // c->set_key(c, &cursor->key);
        __wt_cursor_set_key(c, &cursor->key);
        // Original code:
        // if ((ret = c->search(c)) == 0) {
        if ((ret = __curfile_search(c)) == 0) {
            // Fill buffer with the result!
            // We saw the result was stored in cbt->slot.

            // Original code:
            // WT_ERR(c->get_key(c, &cursor->key));
            WT_ERR(__wt_cursor_get_key(c, &cursor->key));

            // Original code:
            // WT_ERR(c->get_value(c, value));
            WT_ERR(__wt_cursor_get_value(c, value));
            if (__clsm_deleted(clsm, value))
                ret = WT_NOTFOUND;
            goto done;
        }
        WT_ERR_NOTFOUND_OK(ret, false);
        F_CLR(c, WT_CURSTD_KEY_SET);

        // NOTE: We don't care about stats.
        /* Update stats: the active chunk can't have a bloom filter. */
        // if (bloom != NULL)
        //     WT_LSM_TREE_STAT_INCR(session, clsm->lsm_tree->bloom_false_positive);
        // else if (clsm->primary_chunk == NULL || i != clsm->nchunks)
        //     WT_LSM_TREE_STAT_INCR(session, clsm->lsm_tree->lsm_lookup_no_bloom);
    }
    WT_ERR(WT_NOTFOUND);

done:
err:
    if (ret == 0) {
        F_CLR(cursor, WT_CURSTD_KEY_SET | WT_CURSTD_VALUE_SET);
        F_SET(cursor, WT_CURSTD_KEY_INT);
        clsm->current = c;
        if (value == &cursor->value)
            F_SET(cursor, WT_CURSTD_VALUE_INT);
    } else if (c != NULL)
        WT_TRET(c->reset(c));

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
// - strlen
// - strcmp

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
    WT_DECL_RET;
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
        WT_RET(__wt_btcur_search(cbt));

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
