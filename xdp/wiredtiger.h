/*-
 * Copyright (c) 2014-2020 MongoDB, Inc.
 * Copyright (c) 2008-2014 WiredTiger, Inc.
 *	All rights reserved.
 *
 * See the file LICENSE for redistribution information.
 */

#ifndef	__WIREDTIGER_H_
#define	__WIREDTIGER_H_

#if defined(__cplusplus)
extern "C" {
#endif

/*******************************************
 * Version information
 *******************************************/
#define	WIREDTIGER_VERSION_MAJOR	10
#define	WIREDTIGER_VERSION_MINOR	0
#define	WIREDTIGER_VERSION_PATCH	0
#define	WIREDTIGER_VERSION_STRING	"WiredTiger 10.0.0: (March 18, 2020)"

/*******************************************
 * Required includes
 *******************************************/

// #include <sys/types.h>
// #include <inttypes.h>
// #include <stdarg.h>
// #include <stdbool.h>
// #include <stdint.h>
// #include <stdio.h>

/*******************************************
 * Portable type names
 *******************************************/
typedef off_t wt_off_t;



#if defined(DOXYGEN) || defined(SWIG)
#define	__F(func) func
#else
/* NOLINTNEXTLINE(misc-macro-parentheses) */
#define	__F(func) (*func)
#endif

/*
 * We support configuring WiredTiger with the gcc/clang -fvisibility=hidden
 * flags, but that requires public APIs be specifically marked.
 */
#if defined(DOXYGEN) || defined(SWIG) || !defined(__GNUC__)
#define	WT_ATTRIBUTE_LIBRARY_VISIBLE
#else
#define	WT_ATTRIBUTE_LIBRARY_VISIBLE	__attribute__((visibility("default")))
#endif

/*!
 * @defgroup wt WiredTiger API
 * The functions, handles and methods applications use to access and manage
 * data with WiredTiger.
 *
 * @{
 */

/*******************************************
 * Public forward structure declarations
 *******************************************/
struct __wt_async_callback;
	typedef struct __wt_async_callback WT_ASYNC_CALLBACK;
struct __wt_async_op;	    typedef struct __wt_async_op WT_ASYNC_OP;
struct __wt_collator;	    typedef struct __wt_collator WT_COLLATOR;
struct __wt_compressor;	    typedef struct __wt_compressor WT_COMPRESSOR;
struct __wt_config_item;    typedef struct __wt_config_item WT_CONFIG_ITEM;
struct __wt_config_parser;
	typedef struct __wt_config_parser WT_CONFIG_PARSER;
struct __wt_connection;	    typedef struct __wt_connection WT_CONNECTION;
struct __wt_cursor;	    typedef struct __wt_cursor WT_CURSOR;
struct __wt_data_source;    typedef struct __wt_data_source WT_DATA_SOURCE;
struct __wt_encryptor;	    typedef struct __wt_encryptor WT_ENCRYPTOR;
struct __wt_event_handler;  typedef struct __wt_event_handler WT_EVENT_HANDLER;
struct __wt_extension_api;  typedef struct __wt_extension_api WT_EXTENSION_API;
struct __wt_extractor;	    typedef struct __wt_extractor WT_EXTRACTOR;
struct __wt_file_handle;    typedef struct __wt_file_handle WT_FILE_HANDLE;
struct __wt_file_system;    typedef struct __wt_file_system WT_FILE_SYSTEM;
struct __wt_item;	    typedef struct __wt_item WT_ITEM;
struct __wt_modify;	    typedef struct __wt_modify WT_MODIFY;
struct __wt_session;	    typedef struct __wt_session WT_SESSION;

#if defined(SWIGJAVA)
#define	WT_HANDLE_NULLABLE(typename)	typename##_NULLABLE
#define	WT_HANDLE_CLOSED(typename)	typename##_CLOSED
typedef WT_CURSOR			WT_CURSOR_NULLABLE;
typedef WT_CURSOR			WT_CURSOR_CLOSED;
typedef WT_SESSION			WT_SESSION_CLOSED;
typedef WT_CONNECTION			WT_CONNECTION_CLOSED;
#elif !defined(DOXYGEN)
#define	WT_HANDLE_NULLABLE(typename)	typename
#define	WT_HANDLE_CLOSED(typename)	typename
#endif

/*!
 * A raw item of data to be managed, including a pointer to the data and a
 * length.
 *
 * WT_ITEM structures do not need to be cleared before use.
 */
struct __wt_item {
	/*!
	 * The memory reference of the data item.
	 *
	 * For items returned by a WT_CURSOR, the pointer is only valid until
	 * the next operation on that cursor.  Applications that need to keep
	 * an item across multiple cursor operations must make a copy.
	 */
	const void *data;

	/*!
	 * The number of bytes in the data item.
	 *
	 * The maximum length of a single column stored in a table is not fixed
	 * (as it partially depends on the underlying file configuration), but
	 * is always a small number of bytes less than 4GB.
	 */
	size_t size;

#ifndef DOXYGEN
	/*! Managed memory chunk (internal use). */
	void *mem;

	/*! Managed memory size (internal use). */
	size_t memsize;

	/*! Object flags (internal use). */
/* AUTOMATIC FLAG VALUE GENERATION START */
#define	WT_ITEM_ALIGNED	0x1u
#define	WT_ITEM_INUSE	0x2u
/* AUTOMATIC FLAG VALUE GENERATION STOP */
	uint32_t flags;
#endif
};

/*!
 * A set of modifications for a value, including a pointer to new data and a
 * length, plus a target offset in the value and an optional length of data
 * in the value to be replaced.
 *
 * WT_MODIFY structures do not need to be cleared before use.
 */
struct __wt_modify {
	/*!
	 * New data. The size of the new data may be zero when no new data is
	 * provided.
	 */
	WT_ITEM data;

	/*!
	 * The zero-based byte offset in the value where the new data is placed.
	 *
	 * If the offset is past the end of the value, padding bytes are
	 * appended to the value up to the specified offset. If the value is a
	 * string (value format \c S), the padding byte is a space. If the value
	 * is a raw byte array accessed using a WT_ITEM structure (value format
	 * \c u), the padding byte is a nul.
	 */
	 size_t offset;

	/*!
	 * The number of bytes in the value to be replaced.
	 *
	 * If the size is zero, no bytes from the value are replaced and the new
	 * data is inserted.
	 *
	 * If the offset is past the end of the value, the size is ignored.
	 *
	 * If the offset plus the size overlaps the end of the previous value,
	 * bytes from the offset to the end of the value are replaced and any
	 * remaining new data is appended.
	 */
	 size_t size;
};

/*!
 * The maximum packed size of a 64-bit integer.  The ::wiredtiger_struct_pack
 * function will pack single long integers into at most this many bytes.
 */
#define	WT_INTPACK64_MAXSIZE	((int)sizeof(int64_t) + 1)

/*!
 * The maximum packed size of a 32-bit integer.  The ::wiredtiger_struct_pack
 * function will pack single integers into at most this many bytes.
 */
#define	WT_INTPACK32_MAXSIZE	((int)sizeof(int32_t) + 1)

/*!
 * A WT_CURSOR handle is the interface to a cursor.
 *
 * Cursors allow data to be searched, iterated and modified, implementing the
 * CRUD (create, read, update and delete) operations.  Cursors are opened in
 * the context of a session.  If a transaction is started, cursors operate in
 * the context of the transaction until the transaction is resolved.
 *
 * Raw data is represented by key/value pairs of WT_ITEM structures, but
 * cursors can also provide access to fields within the key and value if the
 * formats are described in the WT_SESSION::create method.
 *
 * In the common case, a cursor is used to access records in a table.  However,
 * cursors can be used on subsets of tables (such as a single column or a
 * projection of multiple columns), as an interface to statistics, configuration
 * data or application-specific data sources.  See WT_SESSION::open_cursor for
 * more information.
 *
 * <b>Thread safety:</b> A WT_CURSOR handle is not usually shared between
 * threads, see @ref threads for more information.
 */
struct __wt_cursor {
	WT_SESSION *session;	/*!< The session handle for this cursor. */

	/*!
	 * The name of the data source for the cursor, matches the \c uri
	 * parameter to WT_SESSION::open_cursor used to open the cursor.
	 */
	const char *uri;

	/*!
	 * The format of the data packed into key items.  See @ref packing for
	 * details.  If not set, a default value of "u" is assumed, and
	 * applications must use WT_ITEM structures to manipulate untyped byte
	 * arrays.
	 */
	const char *key_format;

	/*!
	 * The format of the data packed into value items.  See @ref packing
	 * for details.  If not set, a default value of "u" is assumed, and
	 * applications must use WT_ITEM structures to manipulate untyped byte
	 * arrays.
	 */
	const char *value_format;

	/*!
	 * @name Data access
	 * @{
	 */
	/*!
	 * Get the key for the current record.
	 *
	 * @snippet ex_all.c Get the cursor's string key
	 *
	 * @snippet ex_all.c Get the cursor's record number key
	 *
	 * @param cursor the cursor handle
	 * @param ... pointers to hold key fields corresponding to
	 * WT_CURSOR::key_format.
	 * The API does not validate the argument types passed in, the caller is
	 * responsible for passing the correct argument types according to
	 * WT_CURSOR::key_format.
	 * @errors
	 */
	int __F(get_key)(WT_CURSOR *cursor, ...);

	/*!
	 * Get the value for the current record.
	 *
	 * @snippet ex_all.c Get the cursor's string value
	 *
	 * @snippet ex_all.c Get the cursor's raw value
	 *
	 * @param cursor the cursor handle
	 * @param ... pointers to hold value fields corresponding to
	 * WT_CURSOR::value_format.
	 * The API does not validate the argument types passed in, the caller is
	 * responsible for passing the correct argument types according to
	 * WT_CURSOR::value_format.
	 * @errors
	 */
	int __F(get_value)(WT_CURSOR *cursor, ...);

	/*!
	 * Set the key for the next operation.
	 *
	 * @snippet ex_all.c Set the cursor's string key
	 *
	 * @snippet ex_all.c Set the cursor's record number key
	 *
	 * @param cursor the cursor handle
	 * @param ... key fields corresponding to WT_CURSOR::key_format.
	 *
	 * If an error occurs during this operation, a flag will be set in the
	 * cursor, and the next operation to access the key will fail.  This
	 * simplifies error handling in applications.
	 */
	void __F(set_key)(WT_CURSOR *cursor, ...);

	/*!
	 * Set the value for the next operation.
	 *
	 * @snippet ex_all.c Set the cursor's string value
	 *
	 * @snippet ex_all.c Set the cursor's raw value
	 *
	 * @param cursor the cursor handle
	 * @param ... value fields corresponding to WT_CURSOR::value_format.
	 *
	 * If an error occurs during this operation, a flag will be set in the
	 * cursor, and the next operation to access the value will fail.  This
	 * simplifies error handling in applications.
	 */
	void __F(set_value)(WT_CURSOR *cursor, ...);
	/*! @} */

	/*!
	 * @name Cursor positioning
	 * @{
	 */
	/*!
	 * Return the ordering relationship between two cursors: both cursors
	 * must have the same data source and have valid keys. (When testing
	 * only for equality, WT_CURSOR::equals may be faster.)
	 *
	 * @snippet ex_all.c Cursor comparison
	 *
	 * @param cursor the cursor handle
	 * @param other another cursor handle
	 * @param comparep the status of the comparison: < 0 if
	 * <code>cursor</code> refers to a key that appears before
	 * <code>other</code>, 0 if the cursors refer to the same key,
	 * and > 0 if <code>cursor</code> refers to a key that appears after
	 * <code>other</code>.
	 * @errors
	 */
	int __F(compare)(WT_CURSOR *cursor, WT_CURSOR *other, int *comparep);

	/*!
	 * Return the ordering relationship between two cursors, testing only
	 * for equality: both cursors must have the same data source and have
	 * valid keys.
	 *
	 * @snippet ex_all.c Cursor equality
	 *
	 * @param cursor the cursor handle
	 * @param other another cursor handle
	 * @param[out] equalp the status of the comparison: 1 if the cursors
	 * refer to the same key, otherwise 0.
	 * @errors
	 */
	int __F(equals)(WT_CURSOR *cursor, WT_CURSOR *other, int *equalp);

	/*!
	 * Return the next record.
	 *
	 * @snippet ex_all.c Return the next record
	 *
	 * @param cursor the cursor handle
	 * @errors
	 */
	int __F(next)(WT_CURSOR *cursor);

	/*!
	 * Return the previous record.
	 *
	 * @snippet ex_all.c Return the previous record
	 *
	 * @param cursor the cursor handle
	 * @errors
	 */
	int __F(prev)(WT_CURSOR *cursor);

	/*!
	 * Reset the cursor. Any resources held by the cursor are released,
	 * and the cursor's key and position are no longer valid. Subsequent
	 * iterations with WT_CURSOR::next will move to the first record, or
	 * with WT_CURSOR::prev will move to the last record.
	 *
	 * In the case of a statistics cursor, resetting the cursor refreshes
	 * the statistics information returned. Resetting a session statistics
	 * cursor resets all the session statistics values to zero.
	 *
	 * @snippet ex_all.c Reset the cursor
	 *
	 * @param cursor the cursor handle
	 * @errors
	 */
	int __F(reset)(WT_CURSOR *cursor);

	/*!
	 * Return the record matching the key. The key must first be set.
	 *
	 * @snippet ex_all.c Search for an exact match
	 *
	 * On success, the cursor ends positioned at the returned record; to
	 * minimize cursor resources, the WT_CURSOR::reset method should be
	 * called as soon as the record has been retrieved and the cursor no
	 * longer needs that position.
	 *
	 * @param cursor the cursor handle
	 * @errors
	 */
	int __F(search)(WT_CURSOR *cursor);

	/*!
	 * Return the record matching the key if it exists, or an adjacent
	 * record.  An adjacent record is either the smallest record larger
	 * than the key or the largest record smaller than the key (in other
	 * words, a logically adjacent key).
	 *
	 * The key must first be set.
	 *
	 * An example of a search for an exact or adjacent match:
	 *
	 * @snippet ex_all.c Search for an exact or adjacent match
	 *
	 * An example of a forward scan through the table, where all keys
	 * greater than or equal to a specified prefix are included in the
	 * scan:
	 *
	 * @snippet ex_all.c Forward scan greater than or equal
	 *
	 * An example of a backward scan through the table, where all keys
	 * less than a specified prefix are included in the scan:
	 *
	 * @snippet ex_all.c Backward scan less than
	 *
	 * On success, the cursor ends positioned at the returned record; to
	 * minimize cursor resources, the WT_CURSOR::reset method should be
	 * called as soon as the record has been retrieved and the cursor no
	 * longer needs that position.
	 *
	 * @param cursor the cursor handle
	 * @param exactp the status of the search: 0 if an exact match is
	 * found, < 0 if a smaller key is returned, > 0 if a larger key is
	 * returned
	 * @errors
	 */
	int __F(search_near)(WT_CURSOR *cursor, int *exactp);
	/*! @} */

	/*!
	 * @name Data modification
	 * @{
	 */
	/*!
	 * Insert a record and optionally update an existing record.
	 *
	 * If the cursor was configured with "overwrite=true" (the default),
	 * both the key and value must be set; if the record already exists,
	 * the key's value will be updated, otherwise, the record will be
	 * inserted.
	 *
	 * @snippet ex_all.c Insert a new record or overwrite an existing record
	 *
	 * If the cursor was not configured with "overwrite=true", both the key
	 * and value must be set and the record must not already exist; the
	 * record will be inserted.
	 *
	 * @snippet ex_all.c Insert a new record and fail if the record exists
	 *
	 * If a cursor with record number keys was configured with
	 * "append=true" (not the default), the value must be set; a new record
	 * will be appended and the record number set as the cursor key value.
	 *
	 * @snippet ex_all.c Insert a new record and assign a record number
	 *
	 * The cursor ends with no position, and a subsequent call to the
	 * WT_CURSOR::next (WT_CURSOR::prev) method will iterate from the
	 * beginning (end) of the table.
	 *
	 * If the cursor does not have record number keys or was not configured
	 * with "append=true", the cursor ends with no key set and a subsequent
	 * call to the WT_CURSOR::get_key method will fail. The cursor ends with
	 * no value set and a subsequent call to the WT_CURSOR::get_value method
	 * will fail.
	 *
	 * Inserting a new record after the current maximum record in a
	 * fixed-length bit field column-store (that is, a store with an
	 * 'r' type key and 't' type value) may implicitly create the missing
	 * records as records with a value of 0.
	 *
	 * When loading a large amount of data into a new object, using
	 * a cursor with the \c bulk configuration string enabled and
	 * loading the data in sorted order will be much faster than doing
	 * out-of-order inserts.  See @ref tune_bulk_load for more information.
	 *
	 * The maximum length of a single column stored in a table is not fixed
	 * (as it partially depends on the underlying file configuration), but
	 * is always a small number of bytes less than 4GB.
	 *
	 * @param cursor the cursor handle
	 * @errors
	 * In particular, if \c overwrite=false is configured and a record with
	 * the specified key already exists, ::WT_DUPLICATE_KEY is returned.
	 * Also, if \c in_memory is configured for the database and the insert
	 * requires more than the configured cache size to complete,
	 * ::WT_CACHE_FULL is returned.
	 */
	int __F(insert)(WT_CURSOR *cursor);

	/*!
	 * Modify an existing record.
	 *
	 * Both the key and value must be set and the record must already exist;
	 * the record will be updated.
	 *
	 * Modifications are specified in WT_MODIFY structures. Modifications
	 * are applied in order and later modifications can update earlier ones.
	 *
	 * The modify method is only supported on strings (value format type
	 * \c S), or raw byte arrays accessed using a WT_ITEM structure (value
	 * format type \c u).
	 *
	 * The WT_CURSOR::modify method can only be called from within an
	 * explicit transaction configured at the snapshot isolation level.
	 *
	 * The WT_CURSOR::modify method stores a change record in cache and
	 * writes a change record to the log instead of the usual complete
	 * values. Note that WT_CURSOR::modify is generally slower than the
	 * WT_CURSOR::update method, and can result in slower reads because
	 * the complete value must be assembled during retrieval. The
	 * WT_CURSOR::modify method is intended for applications modifying
	 * large records where there is cache or I/O pressure, that is,
	 * applications that will benefit when data updates require less cache
	 * and they write less logging information.
	 *
	 * @snippet ex_all.c Modify an existing record
	 *
	 * On success, the cursor ends positioned at the modified record; to
	 * minimize cursor resources, the WT_CURSOR::reset method should be
	 * called as soon as the cursor no longer needs that position.
	 *
	 * The maximum length of a single column stored in a table is not fixed
	 * (as it partially depends on the underlying file configuration), but
	 * is always a small number of bytes less than 4GB.
	 *
	 * @param cursor the cursor handle
	 * @param entries an array of modification data structures
	 * @param nentries the number of modification data structures
	 * @errors
	 * In particular, if \c in_memory is configured for the database and
	 * the modify requires more than the configured cache size to complete,
	 * ::WT_CACHE_FULL is returned.
	 */
	int __F(modify)(WT_CURSOR *cursor, WT_MODIFY *entries, int nentries);

	/*!
	 * Update an existing record and optionally insert a record.
	 *
	 * If the cursor was configured with "overwrite=true" (the default),
	 * both the key and value must be set; if the record already exists, the
	 * key's value will be updated, otherwise, the record will be inserted.
	 *
	 * @snippet ex_all.c Update an existing record or insert a new record
	 *
	 * If the cursor was not configured with "overwrite=true", both the key
	 * and value must be set and the record must already exist; the
	 * record will be updated.
	 *
	 * @snippet ex_all.c Update an existing record and fail if DNE
	 *
	 * On success, the cursor ends positioned at the modified record; to
	 * minimize cursor resources, the WT_CURSOR::reset method should be
	 * called as soon as the cursor no longer needs that position. (The
	 * WT_CURSOR::insert method never keeps a cursor position and may be
	 * more efficient for that reason.)
	 *
	 * The maximum length of a single column stored in a table is not fixed
	 * (as it partially depends on the underlying file configuration), but
	 * is always a small number of bytes less than 4GB.
	 *
	 * @param cursor the cursor handle
	 * @errors
	 * In particular, if \c overwrite=false is configured and no record with
	 * the specified key exists, ::WT_NOTFOUND is returned.
	 * Also, if \c in_memory is configured for the database and the update
	 * requires more than the configured cache size to complete,
	 * ::WT_CACHE_FULL is returned.
	 */
	int __F(update)(WT_CURSOR *cursor);

	/*!
	 * Remove a record.
	 *
	 * If the cursor was configured with "overwrite=true" (the default),
	 * the key must be set; the key's record will be removed if it exists,
	 * no error will be returned if the record does not exist.
	 *
	 * @snippet ex_all.c Remove a record
	 *
	 * If the cursor was configured with "overwrite=false" (not the
	 * default), the key must be set and the key's record must exist; the
	 * record will be removed.
	 *
	 * Any cursor position does not change: if the cursor was positioned
	 * before the WT_CURSOR::remove call, the cursor remains positioned
	 * at the removed record; to minimize cursor resources, the
	 * WT_CURSOR::reset method should be called as soon as the cursor no
	 * longer needs that position. If the cursor was not positioned before
	 * the WT_CURSOR::remove call, the cursor ends with no position, and a
	 * subsequent call to the WT_CURSOR::next (WT_CURSOR::prev) method will
	 * iterate from the beginning (end) of the table.
	 *
	 * @snippet ex_all.c Remove a record and fail if DNE
	 *
	 * Removing a record in a fixed-length bit field column-store
	 * (that is, a store with an 'r' type key and 't' type value) is
	 * identical to setting the record's value to 0.
	 *
	 * @param cursor the cursor handle
	 * @errors
	 * In particular, if \c overwrite=false is configured and no record
	 * with the specified key exists, ::WT_NOTFOUND is returned.
	 */
	int __F(remove)(WT_CURSOR *cursor);

	/*!
	 * Reserve an existing record so a subsequent write is less likely to
	 * fail due to a conflict between concurrent operations.
	 *
	 * The key must first be set and the record must already exist.
	 *
	 * Note that reserve works by doing a special update operation that is
	 * not logged and does not change the value of the record. This update
	 * is aborted when the enclosing transaction ends regardless of whether
	 * it commits or rolls back. Given that, reserve can only be used to
	 * detect conflicts between transactions that execute concurrently. It
	 * cannot detect all logical conflicts between transactions. For that,
	 * some update to the record must be committed.
	 *
	 * @snippet ex_all.c Reserve a record
	 *
	 * On success, the cursor ends positioned at the specified record; to
	 * minimize cursor resources, the WT_CURSOR::reset method should be
	 * called as soon as the cursor no longer needs that position.
	 *
	 * @param cursor the cursor handle
	 * @errors
	 */
	int __F(reserve)(WT_CURSOR *cursor);
	/*! @} */

	/*!
	 * Close the cursor.
	 *
	 * This releases the resources associated with the cursor handle.
	 * Cursors are closed implicitly by ending the enclosing connection or
	 * closing the session in which they were opened.
	 *
	 * @snippet ex_all.c Close the cursor
	 *
	 * @param cursor the cursor handle
	 * @errors
	 */
	int __F(close)(WT_HANDLE_CLOSED(WT_CURSOR) *cursor);

	/*!
	 * Reconfigure the cursor.
	 *
	 * The cursor is reset.
	 *
	 * @snippet ex_all.c Reconfigure a cursor
	 *
	 * @param cursor the cursor handle
	 * @configstart{WT_CURSOR.reconfigure, see dist/api_data.py}
	 * @config{append, append the value as a new record\, creating a new record number key;
	 * valid only for cursors with record number keys., a boolean flag; default \c false.}
	 * @config{overwrite, configures whether the cursor's insert\, update and remove methods
	 * check the existing state of the record.  If \c overwrite is \c false\, WT_CURSOR::insert
	 * fails with ::WT_DUPLICATE_KEY if the record exists\, WT_CURSOR::update and
	 * WT_CURSOR::remove fail with ::WT_NOTFOUND if the record does not exist., a boolean flag;
	 * default \c true.}
	 * @configend
	 * @errors
	 */
	int __F(reconfigure)(WT_CURSOR *cursor, const char *config);

	/*
	 * Protected fields, only to be used by cursor implementations.
	 */
#if !defined(SWIG) && !defined(DOXYGEN)
	int __F(cache)(WT_CURSOR *cursor);	/* Cache the cursor */
						/* Reopen a cached cursor */
	int __F(reopen)(WT_CURSOR *cursor, bool check_only);

	uint64_t uri_hash;			/* Hash of URI */

	/*
	 * !!!
	 * Explicit representations of structures from queue.h.
	 * TAILQ_ENTRY(wt_cursor) q;
	 */
	struct {
		WT_CURSOR *tqe_next;
		WT_CURSOR **tqe_prev;
	} q;				/* Linked list of WT_CURSORs. */

	uint64_t recno;			/* Record number, normal and raw mode */
	uint8_t raw_recno_buf[WT_INTPACK64_MAXSIZE];

	void	*json_private;		/* JSON specific storage */
	void	*lang_private;		/* Language specific private storage */

	WT_ITEM key, value;
	int saved_err;			/* Saved error in set_{key,value}. */
	/*
	 * URI used internally, may differ from the URI provided by the
	 * user on open.
	 */
	const char *internal_uri;

/* AUTOMATIC FLAG VALUE GENERATION START */
#define	WT_CURSTD_APPEND		0x000001u
#define	WT_CURSTD_BULK			0x000002u
#define	WT_CURSTD_CACHEABLE		0x000004u
#define	WT_CURSTD_CACHED		0x000008u
#define	WT_CURSTD_DEAD			0x000010u
#define	WT_CURSTD_DEBUG_COPY_KEY	0x000020u
#define	WT_CURSTD_DEBUG_COPY_VALUE	0x000040u
#define	WT_CURSTD_DEBUG_RESET_EVICT	0x000080u
#define	WT_CURSTD_DUMP_HEX		0x000100u
#define	WT_CURSTD_DUMP_JSON		0x000200u
#define	WT_CURSTD_DUMP_PRETTY		0x000400u
#define	WT_CURSTD_DUMP_PRINT		0x000800u
#define	WT_CURSTD_IGNORE_TOMBSTONE	0x001000u
#define	WT_CURSTD_JOINED		0x002000u
#define	WT_CURSTD_KEY_EXT		0x004000u	/* Key points out of tree. */
#define	WT_CURSTD_KEY_INT		0x008000u	/* Key points into tree. */
#define	WT_CURSTD_META_INUSE		0x010000u
#define	WT_CURSTD_OPEN			0x020000u
#define	WT_CURSTD_OVERWRITE		0x040000u
#define	WT_CURSTD_RAW			0x080000u
#define	WT_CURSTD_RAW_SEARCH		0x100000u
#define	WT_CURSTD_UPDATE_LOCAL		0x200000u
#define	WT_CURSTD_VALUE_EXT		0x400000u	/* Value points out of tree. */
#define	WT_CURSTD_VALUE_INT		0x800000u	/* Value points into tree. */
/* AUTOMATIC FLAG VALUE GENERATION STOP */
#define	WT_CURSTD_KEY_SET	(WT_CURSTD_KEY_EXT | WT_CURSTD_KEY_INT)
#define	WT_CURSTD_VALUE_SET	(WT_CURSTD_VALUE_EXT | WT_CURSTD_VALUE_INT)
	uint32_t flags;
#endif
};

/*! Asynchronous operation types. */
typedef enum {
	WT_AOP_NONE=0,	/*!< No operation type set */
	WT_AOP_COMPACT, /*!< WT_ASYNC_OP::compact */
	WT_AOP_INSERT,	/*!< WT_ASYNC_OP::insert */
	WT_AOP_REMOVE,	/*!< WT_ASYNC_OP::remove */
	WT_AOP_SEARCH,	/*!< WT_ASYNC_OP::search */
	WT_AOP_UPDATE	/*!< WT_ASYNC_OP::update */
} WT_ASYNC_OPTYPE;

/*!
 * A WT_ASYNC_OP handle is the interface to an asynchronous operation.
 *
 * An asynchronous operation describes a data manipulation to be performed
 * asynchronously by a WiredTiger worker thread.  These operations implement
 * the CRUD (create, read, update and delete) operations.  Each operation
 * is a self-contained work unit.  The operation will be performed in the
 * context of the worker thread's session.  Each operation is performed
 * within the context of a transaction.  The application is notified of its
 * completion with a callback.  The transaction is resolved once the callback
 * returns.
 *
 * The table referenced in an operation must already exist.
 *
 * Raw data is represented by key/value pairs of WT_ITEM structures, but
 * operations can also provide access to fields within the key and value if
 * the formats are described in the WT_SESSION::create method.
 *
 * <b>Thread safety:</b> A WT_ASYNC_OP handle may not be shared between
 * threads, see @ref threads for more information.
 */
struct __wt_async_op {
	/*! The connection for this operation. */
	WT_CONNECTION *connection;

	/*!
	 * The format of the data packed into key items.  See @ref packing for
	 * details.  If not set, a default value of "u" is assumed, and
	 * applications must use WT_ITEM structures to manipulate untyped byte
	 * arrays.
	 */
	const char *key_format;

	/*!
	 * The format of the data packed into value items.  See @ref packing
	 * for details.  If not set, a default value of "u" is assumed, and
	 * applications must use WT_ITEM structures to manipulate untyped byte
	 * arrays.
	 */
	const char *value_format;

	/*
	 * Don't expose app_private to non-C language bindings - they have
	 * their own way to attach data to an operation.
	 */
#if !defined(SWIG)
	/*!
	 * A location for applications to store information that will be
	 * available in the callback from an async operation.
	 */
	void *app_private;
#endif

	/*!
	 * @name Data access
	 * @{
	 */
	/*!
	 * Invoke the underlying WT_CURSOR::get_key method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 * @returns as described for WT_CURSOR::get_key
	 */
	int __F(get_key)(WT_ASYNC_OP *op, ...);

	/*!
	 * Invoke the underlying WT_CURSOR::get_value method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 * @returns as described for WT_CURSOR::get_value
	 */
	int __F(get_value)(WT_ASYNC_OP *op, ...);

	/*!
	 * Invoke the underlying WT_CURSOR::set_key method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 */
	void __F(set_key)(WT_ASYNC_OP *op, ...);

	/*!
	 * Invoke the underlying WT_CURSOR::set_value method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 */
	void __F(set_value)(WT_ASYNC_OP *op, ...);
	/*! @} */

	/*!
	 * @name Positioning
	 * @{
	 */
	/*!
	 * Invoke the underlying WT_CURSOR::search method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 * @returns via the callback as described for WT_CURSOR::search
	 */
	int __F(search)(WT_ASYNC_OP *op);
	/*! @} */

	/*!
	 * @name Data modification
	 * @{
	 */
	/*!
	 * Invoke the underlying WT_CURSOR::insert method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 * @returns via the callback as described for WT_CURSOR::insert
	 */
	int __F(insert)(WT_ASYNC_OP *op);

	/*!
	 * Invoke the underlying WT_CURSOR::update method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 * @returns via the callback as described for WT_CURSOR::update
	 */
	int __F(update)(WT_ASYNC_OP *op);

	/*!
	 * Invoke the underlying WT_CURSOR::remove method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 * @returns via the callback as described for WT_CURSOR::remove
	 */
	int __F(remove)(WT_ASYNC_OP *op);
	/*! @} */

	/*!
	 * @name Table operations
	 * @{
	 */
	/*!
	 * Invoke the underlying WT_SESSION::compact method; see that method
	 * for configuration, return and error values.
	 *
	 * @param op the operation handle
	 * @returns via the callback as described for WT_SESSION::compact
	 */
	int __F(compact)(WT_ASYNC_OP *op);
	/*! @} */

	/*!
	 * Get the unique identifier for this operation.
	 *
	 * @snippet ex_async.c async get identifier
	 *
	 * @param op the operation handle
	 * @returns the id of the operation
	 */
	uint64_t __F(get_id)(WT_ASYNC_OP *op);

	/*!
	 * Get the type for this operation.
	 *
	 * @snippet ex_async.c async get type
	 *
	 * @param op the operation handle
	 * @returns the ::WT_ASYNC_OPTYPE of the operation
	 */
	WT_ASYNC_OPTYPE __F(get_type)(WT_ASYNC_OP *op);

	/*
	 * Protected fields, only to be used by internal implementation.
	 * Everything we need for maintaining the key/value is part of
	 * a cursor.  So, include one here so that we can use the cursor
	 * functions to manage them.
	 */
#if !defined(SWIG) && !defined(DOXYGEN)
	WT_CURSOR	c;
#endif
};

/*!
 * All data operations are performed in the context of a WT_SESSION.  This
 * encapsulates the thread and transactional context of the operation.
 *
 * <b>Thread safety:</b> A WT_SESSION handle is not usually shared between
 * threads, see @ref threads for more information.
 */
struct __wt_session {
	/*! The connection for this session. */
	WT_CONNECTION *connection;

	/*
	 * Don't expose app_private to non-C language bindings - they have
	 * their own way to attach data to an operation.
	 */
#if !defined(SWIG)
	/*!
	 * A location for applications to store information that will be
	 * available in callbacks taking a WT_SESSION handle.
	 */
	void *app_private;
#endif

	/*!
	 * Close the session handle.
	 *
	 * This will release the resources associated with the session handle,
	 * including rolling back any active transactions and closing any
	 * cursors that remain open in the session.
	 *
	 * @snippet ex_all.c Close a session
	 *
	 * @param session the session handle
	 * @configempty{WT_SESSION.close, see dist/api_data.py}
	 * @errors
	 */
	int __F(close)(WT_HANDLE_CLOSED(WT_SESSION) *session,
	    const char *config);

	/*!
	 * Reconfigure a session handle.
	 *
	 * @snippet ex_all.c Reconfigure a session
	 *
	 * WT_SESSION::reconfigure will fail if a transaction is in progress
	 * in the session.
	 *
	 * All cursors are reset.
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.reconfigure, see dist/api_data.py}
	 * @config{cache_cursors, enable caching of cursors for reuse.  Any calls to
	 * WT_CURSOR::close for a cursor created in this session will mark the cursor as cached and
	 * keep it available to be reused for later calls to WT_SESSION::open_cursor.  Cached
	 * cursors may be eventually closed.  This value is inherited from ::wiredtiger_open \c
	 * cache_cursors., a boolean flag; default \c true.}
	 * @config{ignore_cache_size, when set\, operations performed by this session ignore the
	 * cache size and are not blocked when the cache is full.  Note that use of this option for
	 * operations that create cache pressure can starve ordinary sessions that obey the cache
	 * size., a boolean flag; default \c false.}
	 * @config{isolation, the default isolation level for operations in this session., a
	 * string\, chosen from the following options: \c "read-uncommitted"\, \c "read-committed"\,
	 * \c "snapshot"; default \c read-committed.}
	 * @configend
	 * @errors
	 */
	int __F(reconfigure)(WT_SESSION *session, const char *config);

	/*!
	 * Return information about an error as a string.
	 *
	 * @snippet ex_all.c Display an error thread safe
	 *
	 * @param session the session handle
	 * @param error a return value from a WiredTiger, ISO C, or POSIX
	 * standard API
	 * @returns a string representation of the error
	 */
	const char *__F(strerror)(WT_SESSION *session, int error);

	/*!
	 * @name Cursor handles
	 * @{
	 */

	/*!
	 * Open a new cursor on a data source or duplicate an existing cursor.
	 *
	 * @snippet ex_all.c Open a cursor
	 *
	 * An existing cursor can be duplicated by passing it as the \c to_dup
	 * parameter and setting the \c uri parameter to \c NULL:
	 *
	 * @snippet ex_all.c Duplicate a cursor
	 *
	 * Cursors being duplicated must have a key set, and successfully
	 * duplicated cursors are positioned at the same place in the data
	 * source as the original.
	 *
	 * Cursor handles should be discarded by calling WT_CURSOR::close.
	 *
	 * Cursors capable of supporting transactional operations operate in the
	 * context of the current transaction, if any.
	 *
	 * WT_SESSION::rollback_transaction implicitly resets all cursors.
	 *
	 * Cursors are relatively light-weight objects but may hold references
	 * to heavier-weight objects; applications should re-use cursors when
	 * possible, but instantiating new cursors is not so expensive that
	 * applications need to cache cursors at all cost.
	 *
	 * @param session the session handle
	 * @param uri the data source on which the cursor operates; cursors
	 *  are usually opened on tables, however, cursors can be opened on
	 *  any data source, regardless of whether it is ultimately stored
	 *  in a table.  Some cursor types may have limited functionality
	 *  (for example, they may be read-only or not support transactional
	 *  updates).  See @ref data_sources for more information.
	 *  <br>
	 *  @copydoc doc_cursor_types
	 * @param to_dup a cursor to duplicate or gather statistics on
	 * @configstart{WT_SESSION.open_cursor, see dist/api_data.py}
	 * @config{append, append the value as a new record\, creating a new record number key;
	 * valid only for cursors with record number keys., a boolean flag; default \c false.}
	 * @config{bulk, configure the cursor for bulk-loading\, a fast\, initial load path (see
	 * @ref tune_bulk_load for more information). Bulk-load may only be used for newly created
	 * objects and applications should use the WT_CURSOR::insert method to insert rows.  When
	 * bulk-loading\, rows must be loaded in sorted order.  The value is usually a true/false
	 * flag; when bulk-loading fixed-length column store objects\, the special value \c bitmap
	 * allows chunks of a memory resident bitmap to be loaded directly into a file by passing a
	 * \c WT_ITEM to WT_CURSOR::set_value where the \c size field indicates the number of
	 * records in the bitmap (as specified by the object's \c value_format configuration).
	 * Bulk-loaded bitmap values must end on a byte boundary relative to the bit count (except
	 * for the last set of values loaded)., a string; default \c false.}
	 * @config{checkpoint, the name of a checkpoint to open (the reserved name
	 * "WiredTigerCheckpoint" opens the most recent internal checkpoint taken for the object).
	 * The cursor does not support data modification., a string; default empty.}
	 * @config{dump, configure the cursor for dump format inputs and outputs: "hex" selects a
	 * simple hexadecimal format\, "json" selects a JSON format with each record formatted as
	 * fields named by column names if available\, "pretty" selects a human-readable format
	 * (making it incompatible with the "load") and "print" selects a format where only
	 * non-printing characters are hexadecimal encoded.  These formats are compatible with the
	 * @ref util_dump and @ref util_load commands., a string\, chosen from the following
	 * options: \c "hex"\, \c "json"\, \c "pretty"\, \c "print"; default empty.}
	 * @config{incremental = (, configure the cursor for block incremental backup usage.  These
	 * formats are only compatible with the backup data source; see @ref backup., a set of
	 * related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled,
	 * whether to configure this backup as the starting point for a subsequent incremental
	 * backup., a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;file, the
	 * file name when opening a duplicate incremental backup cursor.  That duplicate cursor will
	 * return the block modifications relevant to the given file name., a string; default
	 * empty.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;force_stop, causes all block incremental backup
	 * information to be released.  This is on an open_cursor call and the resources will be
	 * released when this cursor is closed.  No other operations should be done on this open
	 * cursor., a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;granularity,
	 * this setting manages the granularity of how WiredTiger maintains modification maps
	 * internally.  The larger the granularity\, the smaller amount of information WiredTiger
	 * need to maintain., an integer between 4KB and 2GB; default \c 16MB.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;src_id, a string that identifies a previous checkpoint
	 * backup source as the source of this incremental backup.  This identifier must have
	 * already been created by use of the 'this_id' configuration in an earlier backup.  A
	 * source id is required to begin an incremental backup., a string; default empty.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;this_id, a string that identifies the current system
	 * state as a future backup source for an incremental backup via 'src_id'. This identifier
	 * is required when opening an incremental backup cursor and an error will be returned if
	 * one is not provided., a string; default empty.}
	 * @config{ ),,}
	 * @config{next_random, configure the cursor to return a pseudo-random record from the
	 * object when the WT_CURSOR::next method is called; valid only for row-store cursors.  See
	 * @ref cursor_random for details., a boolean flag; default \c false.}
	 * @config{next_random_sample_size, cursors configured by \c next_random to return
	 * pseudo-random records from the object randomly select from the entire object\, by
	 * default.  Setting \c next_random_sample_size to a non-zero value sets the number of
	 * samples the application expects to take using the \c next_random cursor.  A cursor
	 * configured with both \c next_random and \c next_random_sample_size attempts to divide the
	 * object into \c next_random_sample_size equal-sized pieces\, and each retrieval returns a
	 * record from one of those pieces.  See @ref cursor_random for details., a string; default
	 * \c 0.}
	 * @config{overwrite, configures whether the cursor's insert\, update and remove methods
	 * check the existing state of the record.  If \c overwrite is \c false\, WT_CURSOR::insert
	 * fails with ::WT_DUPLICATE_KEY if the record exists\, WT_CURSOR::update and
	 * WT_CURSOR::remove fail with ::WT_NOTFOUND if the record does not exist., a boolean flag;
	 * default \c true.}
	 * @config{raw, ignore the encodings for the key and value\, manage data as if the formats
	 * were \c "u". See @ref cursor_raw for details., a boolean flag; default \c false.}
	 * @config{read_once, results that are brought into cache from disk by this cursor will be
	 * given less priority in the cache., a boolean flag; default \c false.}
	 * @config{readonly, only query operations are supported by this cursor.  An error is
	 * returned if a modification is attempted using the cursor.  The default is false for all
	 * cursor types except for log and metadata cursors., a boolean flag; default \c false.}
	 * @config{statistics, Specify the statistics to be gathered.  Choosing "all" gathers
	 * statistics regardless of cost and may include traversing on-disk files; "fast" gathers a
	 * subset of relatively inexpensive statistics.  The selection must agree with the database
	 * \c statistics configuration specified to ::wiredtiger_open or WT_CONNECTION::reconfigure.
	 * For example\, "all" or "fast" can be configured when the database is configured with
	 * "all"\, but the cursor open will fail if "all" is specified when the database is
	 * configured with "fast"\, and the cursor open will fail in all cases when the database is
	 * configured with "none". If "size" is configured\, only the underlying size of the object
	 * on disk is filled in and the object is not opened.  If \c statistics is not configured\,
	 * the default configuration is the database configuration.  The "clear" configuration
	 * resets statistics after gathering them\, where appropriate (for example\, a cache size
	 * statistic is not cleared\, while the count of cursor insert operations will be cleared).
	 * See @ref statistics for more information., a list\, with values chosen from the following
	 * options: \c "all"\, \c "cache_walk"\, \c "fast"\, \c "clear"\, \c "size"\, \c
	 * "tree_walk"; default empty.}
	 * @config{target, if non-empty\, backup the list of objects; valid only for a backup data
	 * source., a list of strings; default empty.}
	 * @configend
	 * @param[out] cursorp a pointer to the newly opened cursor
	 * @errors
	 */
	int __F(open_cursor)(WT_SESSION *session,
	    const char *uri, WT_HANDLE_NULLABLE(WT_CURSOR) *to_dup,
	    const char *config, WT_CURSOR **cursorp);
	/*! @} */

	/*!
	 * @name Table operations
	 * @{
	 */
	/*!
	 * Alter a table.
	 *
	 * This will allow modification of some table settings after
	 * creation.
	 *
	 * @exclusive
	 *
	 * @snippet ex_all.c Alter a table
	 *
	 * @param session the session handle
	 * @param name the URI of the object to alter, such as \c "table:stock"
	 * @configstart{WT_SESSION.alter, see dist/api_data.py}
	 * @config{access_pattern_hint, It is recommended that workloads that consist primarily of
	 * updates and/or point queries specify \c random.  Workloads that do many cursor scans
	 * through large ranges of data specify \c sequential and other workloads specify \c none.
	 * The option leads to an advisory call to an appropriate operating system API where
	 * available., a string\, chosen from the following options: \c "none"\, \c "random"\, \c
	 * "sequential"; default \c none.}
	 * @config{app_metadata, application-owned metadata for this object., a string; default
	 * empty.}
	 * @config{cache_resident, do not ever evict the object's pages from cache.  Not compatible
	 * with LSM tables; see @ref tuning_cache_resident for more information., a boolean flag;
	 * default \c false.}
	 * @config{log = (, the transaction log configuration for this object.  Only valid if log is
	 * enabled in ::wiredtiger_open., a set of related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, if false\, this object has checkpoint-level
	 * durability., a boolean flag; default \c true.}
	 * @config{ ),,}
	 * @config{os_cache_dirty_max, maximum dirty system buffer cache usage\, in bytes.  If
	 * non-zero\, schedule writes for dirty blocks belonging to this object in the system buffer
	 * cache after that many bytes from this object are written into the buffer cache., an
	 * integer greater than or equal to 0; default \c 0.}
	 * @config{os_cache_max, maximum system buffer cache usage\, in bytes.  If non-zero\, evict
	 * object blocks from the system buffer cache after that many bytes from this object are
	 * read or written into the buffer cache., an integer greater than or equal to 0; default \c
	 * 0.}
	 * @configend
	 * @errors
	 */
	int __F(alter)(WT_SESSION *session,
	    const char *name, const char *config);

	/*!
	 * Create a table, column group, index or file.
	 *
	 * @not_transactional
	 *
	 * @snippet ex_all.c Create a table
	 *
	 * @param session the session handle
	 * @param name the URI of the object to create, such as
	 * \c "table:stock". For a description of URI formats
	 * see @ref data_sources.
	 * @configstart{WT_SESSION.create, see dist/api_data.py}
	 * @config{access_pattern_hint, It is recommended that workloads that consist primarily of
	 * updates and/or point queries specify \c random.  Workloads that do many cursor scans
	 * through large ranges of data specify \c sequential and other workloads specify \c none.
	 * The option leads to an advisory call to an appropriate operating system API where
	 * available., a string\, chosen from the following options: \c "none"\, \c "random"\, \c
	 * "sequential"; default \c none.}
	 * @config{allocation_size, the file unit allocation size\, in bytes\, must a power-of-two;
	 * smaller values decrease the file space required by overflow items\, and the default value
	 * of 4KB is a good choice absent requirements from the operating system or storage device.,
	 * an integer between 512B and 128MB; default \c 4KB.}
	 * @config{app_metadata, application-owned metadata for this object., a string; default
	 * empty.}
	 * @config{block_allocation, configure block allocation.  Permitted values are \c "first" or
	 * \c "best"; the \c "first" configuration uses a first-available algorithm during block
	 * allocation\, the \c "best" configuration uses a best-fit algorithm., a string\, chosen
	 * from the following options: \c "first"\, \c "best"; default \c best.}
	 * @config{block_compressor, configure a compressor for file blocks.  Permitted values are
	 * \c "none" or custom compression engine name created with WT_CONNECTION::add_compressor.
	 * If WiredTiger has builtin support for \c "lz4"\, \c "snappy"\, \c "zlib" or \c "zstd"
	 * compression\, these names are also available.  See @ref compression for more
	 * information., a string; default \c none.}
	 * @config{cache_resident, do not ever evict the object's pages from cache.  Not compatible
	 * with LSM tables; see @ref tuning_cache_resident for more information., a boolean flag;
	 * default \c false.}
	 * @config{checksum, configure block checksums; permitted values are <code>on</code>
	 * (checksum all blocks)\, <code>off</code> (checksum no blocks) and
	 * <code>uncompresssed</code> (checksum only blocks which are not compressed for any
	 * reason). The \c uncompressed setting is for applications which can rely on decompression
	 * to fail if a block has been corrupted., a string\, chosen from the following options: \c
	 * "on"\, \c "off"\, \c "uncompressed"; default \c uncompressed.}
	 * @config{colgroups, comma-separated list of names of column groups.  Each column group is
	 * stored separately\, keyed by the primary key of the table.  If no column groups are
	 * specified\, all columns are stored together in a single file.  All value columns in the
	 * table must appear in at least one column group.  Each column group must be created with a
	 * separate call to WT_SESSION::create., a list of strings; default empty.}
	 * @config{collator, configure custom collation for keys.  Permitted values are \c "none" or
	 * a custom collator name created with WT_CONNECTION::add_collator., a string; default \c
	 * none.}
	 * @config{columns, list of the column names.  Comma-separated list of the form
	 * <code>(column[\,...])</code>. For tables\, the number of entries must match the total
	 * number of values in \c key_format and \c value_format.  For colgroups and indices\, all
	 * column names must appear in the list of columns for the table., a list of strings;
	 * default empty.}
	 * @config{dictionary, the maximum number of unique values remembered in the Btree row-store
	 * leaf page value dictionary; see @ref file_formats_compression for more information., an
	 * integer greater than or equal to 0; default \c 0.}
	 * @config{encryption = (, configure an encryptor for file blocks.  When a table is
	 * created\, its encryptor is not implicitly used for any related indices or column groups.,
	 * a set of related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
	 * keyid, An identifier that identifies a unique instance of the encryptor.  It is stored in
	 * clear text\, and thus is available when the wiredtiger database is reopened.  On the
	 * first use of a (name\, keyid) combination\, the WT_ENCRYPTOR::customize function is
	 * called with the keyid as an argument., a string; default empty.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;name, Permitted values are \c "none" or custom encryption
	 * engine name created with WT_CONNECTION::add_encryptor.  See @ref encryption for more
	 * information., a string; default \c none.}
	 * @config{ ),,}
	 * @config{exclusive, fail if the object exists.  When false (the default)\, if the object
	 * exists\, check that its settings match the specified configuration., a boolean flag;
	 * default \c false.}
	 * @config{extractor, configure custom extractor for indices.  Permitted values are \c
	 * "none" or an extractor name created with WT_CONNECTION::add_extractor., a string; default
	 * \c none.}
	 * @config{format, the file format., a string\, chosen from the following options: \c
	 * "btree"; default \c btree.}
	 * @config{huffman_key, configure Huffman encoding for keys.  Permitted values are \c
	 * "none"\, \c "english"\, \c "utf8<file>" or \c "utf16<file>". See @ref huffman for more
	 * information., a string; default \c none.}
	 * @config{huffman_value, configure Huffman encoding for values.  Permitted values are \c
	 * "none"\, \c "english"\, \c "utf8<file>" or \c "utf16<file>". See @ref huffman for more
	 * information., a string; default \c none.}
	 * @config{ignore_in_memory_cache_size, allow update and insert operations to proceed even
	 * if the cache is already at capacity.  Only valid in conjunction with in-memory databases.
	 * Should be used with caution - this configuration allows WiredTiger to consume memory over
	 * the configured cache limit., a boolean flag; default \c false.}
	 * @config{immutable, configure the index to be immutable - that is an index is not changed
	 * by any update to a record in the table., a boolean flag; default \c false.}
	 * @config{internal_key_max, the largest key stored in an internal node\, in bytes.  If
	 * set\, keys larger than the specified size are stored as overflow items (which may require
	 * additional I/O to access). The default and the maximum allowed value are both one-tenth
	 * the size of a newly split internal page., an integer greater than or equal to 0; default
	 * \c 0.}
	 * @config{internal_key_truncate, configure internal key truncation\, discarding unnecessary
	 * trailing bytes on internal keys (ignored for custom collators)., a boolean flag; default
	 * \c true.}
	 * @config{internal_page_max, the maximum page size for internal nodes\, in bytes; the size
	 * must be a multiple of the allocation size and is significant for applications wanting to
	 * avoid excessive L2 cache misses while searching the tree.  The page maximum is the bytes
	 * of uncompressed data\, that is\, the limit is applied before any block compression is
	 * done., an integer between 512B and 512MB; default \c 4KB.}
	 * @config{key_format, the format of the data packed into key items.  See @ref
	 * schema_format_types for details.  By default\, the key_format is \c 'u' and applications
	 * use WT_ITEM structures to manipulate raw byte arrays.  By default\, records are stored in
	 * row-store files: keys of type \c 'r' are record numbers and records referenced by record
	 * number are stored in column-store files., a format string; default \c u.}
	 * @config{leaf_key_max, the largest key stored in a leaf node\, in bytes.  If set\, keys
	 * larger than the specified size are stored as overflow items (which may require additional
	 * I/O to access). The default value is one-tenth the size of a newly split leaf page., an
	 * integer greater than or equal to 0; default \c 0.}
	 * @config{leaf_page_max, the maximum page size for leaf nodes\, in bytes; the size must be
	 * a multiple of the allocation size\, and is significant for applications wanting to
	 * maximize sequential data transfer from a storage device.  The page maximum is the bytes
	 * of uncompressed data\, that is\, the limit is applied before any block compression is
	 * done., an integer between 512B and 512MB; default \c 32KB.}
	 * @config{leaf_value_max, the largest value stored in a leaf node\, in bytes.  If set\,
	 * values larger than the specified size are stored as overflow items (which may require
	 * additional I/O to access). If the size is larger than the maximum leaf page size\, the
	 * page size is temporarily ignored when large values are written.  The default is one-half
	 * the size of a newly split leaf page., an integer greater than or equal to 0; default \c
	 * 0.}
	 * @config{log = (, the transaction log configuration for this object.  Only valid if log is
	 * enabled in ::wiredtiger_open., a set of related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, if false\, this object has checkpoint-level
	 * durability., a boolean flag; default \c true.}
	 * @config{ ),,}
	 * @config{lsm = (, options only relevant for LSM data sources., a set of related
	 * configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;auto_throttle,
	 * Throttle inserts into LSM trees if flushing to disk isn't keeping up., a boolean flag;
	 * default \c true.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;bloom, create bloom filters on LSM tree
	 * chunks as they are merged., a boolean flag; default \c true.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;bloom_bit_count, the number of bits used per item for LSM
	 * bloom filters., an integer between 2 and 1000; default \c 16.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;bloom_config, config string used when creating Bloom
	 * filter files\, passed to WT_SESSION::create., a string; default empty.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;bloom_hash_count, the number of hash values per item used
	 * for LSM bloom filters., an integer between 2 and 100; default \c 8.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;bloom_oldest, create a bloom filter on the oldest LSM
	 * tree chunk.  Only supported if bloom filters are enabled., a boolean flag; default \c
	 * false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;chunk_count_limit, the maximum number of chunks
	 * to allow in an LSM tree.  This option automatically times out old data.  As new chunks
	 * are added old chunks will be removed.  Enabling this option disables LSM background
	 * merges., an integer; default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;chunk_max, the
	 * maximum size a single chunk can be.  Chunks larger than this size are not considered for
	 * further merges.  This is a soft limit\, and chunks larger than this value can be created.
	 * Must be larger than chunk_size., an integer between 100MB and 10TB; default \c 5GB.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;chunk_size, the maximum size of the in-memory chunk of an
	 * LSM tree.  This limit is soft - it is possible for chunks to be temporarily larger than
	 * this value.  This overrides the \c memory_page_max setting., an integer between 512K and
	 * 500MB; default \c 10MB.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;merge_custom = (, configure the
	 * tree to merge into a custom data source., a set of related configuration options defined
	 * below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;prefix, custom data
	 * source prefix instead of \c "file"., a string; default empty.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;start_generation, merge
	 * generation at which the custom data source is used (zero indicates no custom data
	 * source)., an integer between 0 and 10; default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;suffix, custom data source suffix
	 * instead of \c ".lsm"., a string; default empty.}
	 * @config{ ),,}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;merge_max, the maximum number of chunks to include in a
	 * merge operation., an integer between 2 and 100; default \c 15.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;merge_min, the minimum number of chunks to include in a
	 * merge operation.  If set to 0 or 1 half the value of merge_max is used., an integer no
	 * more than 100; default \c 0.}
	 * @config{ ),,}
	 * @config{memory_page_image_max, the maximum in-memory page image represented by a single
	 * storage block.  Depending on compression efficiency\, compression can create storage
	 * blocks which require significant resources to re-instantiate in the cache\, penalizing
	 * the performance of future point updates.  The value limits the maximum in-memory page
	 * image a storage block will need.  If set to 0\, a default of 4 times \c leaf_page_max is
	 * used., an integer greater than or equal to 0; default \c 0.}
	 * @config{memory_page_max, the maximum size a page can grow to in memory before being
	 * reconciled to disk.  The specified size will be adjusted to a lower bound of
	 * <code>leaf_page_max</code>\, and an upper bound of <code>cache_size / 10</code>. This
	 * limit is soft - it is possible for pages to be temporarily larger than this value.  This
	 * setting is ignored for LSM trees\, see \c chunk_size., an integer between 512B and 10TB;
	 * default \c 5MB.}
	 * @config{os_cache_dirty_max, maximum dirty system buffer cache usage\, in bytes.  If
	 * non-zero\, schedule writes for dirty blocks belonging to this object in the system buffer
	 * cache after that many bytes from this object are written into the buffer cache., an
	 * integer greater than or equal to 0; default \c 0.}
	 * @config{os_cache_max, maximum system buffer cache usage\, in bytes.  If non-zero\, evict
	 * object blocks from the system buffer cache after that many bytes from this object are
	 * read or written into the buffer cache., an integer greater than or equal to 0; default \c
	 * 0.}
	 * @config{prefix_compression, configure prefix compression on row-store leaf pages., a
	 * boolean flag; default \c false.}
	 * @config{prefix_compression_min, minimum gain before prefix compression will be used on
	 * row-store leaf pages., an integer greater than or equal to 0; default \c 4.}
	 * @config{split_pct, the Btree page split size as a percentage of the maximum Btree page
	 * size\, that is\, when a Btree page is split\, it will be split into smaller pages\, where
	 * each page is the specified percentage of the maximum Btree page size., an integer between
	 * 50 and 100; default \c 90.}
	 * @config{type, set the type of data source used to store a column group\, index or simple
	 * table.  By default\, a \c "file:" URI is derived from the object name.  The \c type
	 * configuration can be used to switch to a different data source\, such as LSM or an
	 * extension configured by the application., a string; default \c file.}
	 * @config{value_format, the format of the data packed into value items.  See @ref
	 * schema_format_types for details.  By default\, the value_format is \c 'u' and
	 * applications use a WT_ITEM structure to manipulate raw byte arrays.  Value items of type
	 * 't' are bitfields\, and when configured with record number type keys\, will be stored
	 * using a fixed-length store., a format string; default \c u.}
	 * @configend
	 * @errors
	 */
	int __F(create)(WT_SESSION *session,
	    const char *name, const char *config);

#if !defined(SWIG) && !defined(DOXYGEN)
	/*!
	 * Import a file.
	 *
	 * @snippet ex_all.c Import a file
	 *
	 * @param session the session handle
	 * @param name the URI of the object to import
	 * @configempty{WT_SESSION.import, see dist/api_data.py}
	 * @errors
	 */
	int __F(import)(WT_SESSION *session,
	    const char *name, const char *config);
#endif

	/*!
	 * Compact a live row- or column-store btree or LSM tree.
	 *
	 * @snippet ex_all.c Compact a table
	 *
	 * @param session the session handle
	 * @param name the URI of the object to compact, such as
	 * \c "table:stock"
	 * @configstart{WT_SESSION.compact, see dist/api_data.py}
	 * @config{timeout, maximum amount of time to allow for compact in seconds.  The actual
	 * amount of time spent in compact may exceed the configured value.  A value of zero
	 * disables the timeout., an integer; default \c 1200.}
	 * @configend
	 * @errors
	 */
	int __F(compact)(WT_SESSION *session,
	    const char *name, const char *config);

	/*!
	 * Drop (delete) an object.
	 *
	 * @exclusive
	 *
	 * @not_transactional
	 *
	 * @snippet ex_all.c Drop a table
	 *
	 * @param session the session handle
	 * @param name the URI of the object to drop, such as \c "table:stock"
	 * @configstart{WT_SESSION.drop, see dist/api_data.py}
	 * @config{force, return success if the object does not exist., a boolean flag; default \c
	 * false.}
	 * @config{remove_files, if the underlying files should be removed., a boolean flag; default
	 * \c true.}
	 * @configend
	 * @ebusy_errors
	 */
	int __F(drop)(WT_SESSION *session,
	    const char *name, const char *config);

	/*!
	 * Join a join cursor with a reference cursor.
	 *
	 * @snippet ex_schema.c Join cursors
	 *
	 * @param session the session handle
	 * @param join_cursor a cursor that was opened using a
	 * \c "join:" URI. It may not have been used for any operations
	 * other than other join calls.
	 * @param ref_cursor an index cursor having the same base table
	 * as the join_cursor, or a table cursor open on the same base table,
	 * or another join cursor. Unless the ref_cursor is another join
	 * cursor, it must be positioned.
	 *
	 * The ref_cursor limits the results seen by iterating the
	 * join_cursor to table items referred to by the key in this
	 * index. The set of keys referred to is modified by the compare
	 * config option.
	 *
	 * Multiple join calls builds up a set of ref_cursors, and
	 * by default, the results seen by iteration are the intersection
	 * of the cursor ranges participating in the join. When configured
	 * with \c "operation=or", the results seen are the union of
	 * the participating cursor ranges.
	 *
	 * After the join call completes, the ref_cursor cursor may not be
	 * used for any purpose other than get_key and get_value. Any other
	 * cursor method (e.g. next, prev,close) will fail. When the
	 * join_cursor is closed, the ref_cursor is made available for
	 * general use again. The application should close ref_cursor when
	 * finished with it, although not before the join_cursor is closed.
	 *
	 * @configstart{WT_SESSION.join, see dist/api_data.py}
	 * @config{bloom_bit_count, the number of bits used per item for the bloom filter., an
	 * integer between 2 and 1000; default \c 16.}
	 * @config{bloom_false_positives, return all values that pass the bloom filter\, without
	 * eliminating any false positives., a boolean flag; default \c false.}
	 * @config{bloom_hash_count, the number of hash values per item for the bloom filter., an
	 * integer between 2 and 100; default \c 8.}
	 * @config{compare, modifies the set of items to be returned so that the index key satisfies
	 * the given comparison relative to the key set in this cursor., a string\, chosen from the
	 * following options: \c "eq"\, \c "ge"\, \c "gt"\, \c "le"\, \c "lt"; default \c "eq".}
	 * @config{count, set an approximate count of the elements that would be included in the
	 * join.  This is used in sizing the bloom filter\, and also influences evaluation order for
	 * cursors in the join.  When the count is equal for multiple bloom filters in a composition
	 * of joins\, the bloom filter may be shared., an integer; default \c .}
	 * @config{operation, the operation applied between this and other joined cursors.  When
	 * "operation=and" is specified\, all the conditions implied by joins must be satisfied for
	 * an entry to be returned by the join cursor; when "operation=or" is specified\, only one
	 * must be satisfied.  All cursors joined to a join cursor must have matching operations., a
	 * string\, chosen from the following options: \c "and"\, \c "or"; default \c "and".}
	 * @config{strategy, when set to bloom\, a bloom filter is created and populated for this
	 * index.  This has an up front cost but may reduce the number of accesses to the main table
	 * when iterating the joined cursor.  The bloom setting requires that count be set., a
	 * string\, chosen from the following options: \c "bloom"\, \c "default"; default empty.}
	 * @configend
	 * @errors
	 */
	int __F(join)(WT_SESSION *session, WT_CURSOR *join_cursor,
	    WT_CURSOR *ref_cursor, const char *config);

	/*!
	 * Flush the log.
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.log_flush, see dist/api_data.py}
	 * @config{sync, forcibly flush the log and wait for it to achieve the synchronization level
	 * specified.  The \c background setting initiates a background synchronization intended to
	 * be used with a later call to WT_SESSION::transaction_sync.  The \c off setting forces any
	 * buffered log records to be written to the file system.  The \c on setting forces log
	 * records to be written to the storage device., a string\, chosen from the following
	 * options: \c "background"\, \c "off"\, \c "on"; default \c on.}
	 * @configend
	 * @errors
	 */
	int __F(log_flush)(WT_SESSION *session, const char *config);

	/*!
	 * Insert a ::WT_LOGREC_MESSAGE type record in the database log files
	 * (the database must be configured for logging when this method is
	 * called).
	 *
	 * @param session the session handle
	 * @param format a printf format specifier
	 * @errors
	 */
	int __F(log_printf)(WT_SESSION *session, const char *format, ...);

	/*!
	 * Rebalance a table or file, see @ref rebalance.
	 *
	 * @exclusive
	 *
	 * @snippet ex_all.c Rebalance a table
	 *
	 * @param session the session handle
	 * @param uri the current URI of the object, such as \c "table:mytable"
	 * @configempty{WT_SESSION.rebalance, see dist/api_data.py}
	 * @ebusy_errors
	 */
	int __F(rebalance)(
	    WT_SESSION *session, const char *uri, const char *config);

	/*!
	 * Rename an object.
	 *
	 * @not_transactional
	 *
	 * @snippet ex_all.c Rename a table
	 *
	 * @exclusive
	 *
	 * @param session the session handle
	 * @param uri the current URI of the object, such as \c "table:old"
	 * @param newuri the new URI of the object, such as \c "table:new"
	 * @configempty{WT_SESSION.rename, see dist/api_data.py}
	 * @ebusy_errors
	 */
	int __F(rename)(WT_SESSION *session,
	    const char *uri, const char *newuri, const char *config);

	/*!
	 * Reset the session handle.
	 *
	 * This method resets all cursors associated with this session and
	 * discards cached resources.  The session can be re-used immediately
	 * after this call returns. If a transaction is running on this
	 * session, then this call takes no action and return an error.
	 *
	 * @snippet ex_all.c Reset the session
	 *
	 * @param session the session handle
	 * @errors
	 */
	int __F(reset)(WT_SESSION *session);

	/*!
	 * Salvage a table or file.
	 *
	 * Salvage rebuilds the file, or files of which a table is comprised,
	 * discarding any corrupted file blocks.
	 *
	 * Previously deleted records may re-appear, and inserted records may
	 * disappear, when salvage is done, so salvage should not be run
	 * unless it is known to be necessary.  Normally, salvage should be
	 * called after a table or file has been corrupted, as reported by the
	 * WT_SESSION::verify method.
	 *
	 * Files are rebuilt in place, the salvage method overwrites the
	 * existing files.
	 *
	 * @exclusive
	 *
	 * @snippet ex_all.c Salvage a table
	 *
	 * @param session the session handle
	 * @param name the URI of the table or file to salvage
	 * @configstart{WT_SESSION.salvage, see dist/api_data.py}
	 * @config{force, force salvage even of files that do not appear to be WiredTiger files., a
	 * boolean flag; default \c false.}
	 * @configend
	 * @ebusy_errors
	 */
	int __F(salvage)(WT_SESSION *session,
	    const char *name, const char *config);

	/*!
	 * Truncate a file, table, cursor range, or backup cursor
	 *
	 * Truncate a table or file.
	 * @snippet ex_all.c Truncate a table
	 *
	 * Truncate a cursor range.  When truncating based on a cursor position,
	 * it is not required the cursor reference a record in the object, only
	 * that the key be set.  This allows applications to discard portions of
	 * the object name space without knowing exactly what records the object
	 * contains.
	 * @snippet ex_all.c Truncate a range
	 *
	 * Any specified cursors end with no position, and subsequent calls to
	 * the WT_CURSOR::next (WT_CURSOR::prev) method will iterate from the
	 * beginning (end) of the table.
	 *
	 * When a range truncate is in progress, and another transaction inserts
	 * a key into that range, the behavior is not well defined - a conflict
	 * may be detected or both transactions may be permitted to commit. If
	 * they do commit, and if there is a crash and recovery runs, the result
	 * may be different than what was in cache before the crash.
	 *
	 * Truncate a backup cursor.  This operation removes all log files that
	 * have been returned by the backup cursor.  It can be used to remove log
	 * files after copying them during @ref backup_incremental.
	 * @snippet ex_backup.c Truncate a backup cursor
	 *
	 * @param session the session handle
	 * @param name the URI of the table or file to truncate, or \c "log:"
	 * for a backup cursor
	 * @param start optional cursor marking the first record discarded;
	 * if <code>NULL</code>, the truncate starts from the beginning of
	 * the object; must be provided when truncating a backup cursor
	 * @param stop optional cursor marking the last record discarded;
	 * if <code>NULL</code>, the truncate continues to the end of the
	 * object; ignored when truncating a backup cursor
	 * @configempty{WT_SESSION.truncate, see dist/api_data.py}
	 * @errors
	 */
	int __F(truncate)(WT_SESSION *session,
	    const char *name,
	    WT_HANDLE_NULLABLE(WT_CURSOR) *start,
	    WT_HANDLE_NULLABLE(WT_CURSOR) *stop,
	    const char *config);

	/*!
	 * Upgrade a table or file.
	 *
	 * Upgrade upgrades a table or file, if upgrade is required.
	 *
	 * @exclusive
	 *
	 * @snippet ex_all.c Upgrade a table
	 *
	 * @param session the session handle
	 * @param name the URI of the table or file to upgrade
	 * @configempty{WT_SESSION.upgrade, see dist/api_data.py}
	 * @ebusy_errors
	 */
	int __F(upgrade)(WT_SESSION *session,
	    const char *name, const char *config);

	/*!
	 * Verify a table or file.
	 *
	 * Verify reports if a file, or the files of which a table is
	 * comprised, have been corrupted.  The WT_SESSION::salvage method
	 * can be used to repair a corrupted file,
	 *
	 * @snippet ex_all.c Verify a table
	 *
	 * @exclusive
	 *
	 * @param session the session handle
	 * @param name the URI of the table or file to verify, optional if verifying the history
	 * store
	 * @configstart{WT_SESSION.verify, see dist/api_data.py}
	 * @config{dump_address, Display page addresses\, time windows\, and page types as pages are
	 * verified\, using the application's message handler\, intended for debugging., a boolean
	 * flag; default \c false.}
	 * @config{dump_blocks, Display the contents of on-disk blocks as they are verified\, using
	 * the application's message handler\, intended for debugging., a boolean flag; default \c
	 * false.}
	 * @config{dump_layout, Display the layout of the files as they are verified\, using the
	 * application's message handler\, intended for debugging; requires optional support from
	 * the block manager., a boolean flag; default \c false.}
	 * @config{dump_offsets, Display the contents of specific on-disk blocks\, using the
	 * application's message handler\, intended for debugging., a list of strings; default
	 * empty.}
	 * @config{dump_pages, Display the contents of in-memory pages as they are verified\, using
	 * the application's message handler\, intended for debugging., a boolean flag; default \c
	 * false.}
	 * @config{stable_timestamp, Ensure that no data has a start timestamp after the stable
	 * timestamp\, to be run after rollback_to_stable., a boolean flag; default \c false.}
	 * @config{strict, Treat any verification problem as an error; by default\, verify will
	 * warn\, but not fail\, in the case of errors that won't affect future behavior (for
	 * example\, a leaked block)., a boolean flag; default \c false.}
	 * @configend
	 * @ebusy_errors
	 */
	int __F(verify)(WT_SESSION *session,
	    const char *name, const char *config);
	/*! @} */

	/*!
	 * @name Transactions
	 * @{
	 */
	/*!
	 * Start a transaction in this session.
	 *
	 * The transaction remains active until ended by
	 * WT_SESSION::commit_transaction or WT_SESSION::rollback_transaction.
	 * Operations performed on cursors capable of supporting transactional
	 * operations that are already open in this session, or which are opened
	 * before the transaction ends, will operate in the context of the
	 * transaction.
	 *
	 * @requires_notransaction
	 *
	 * @snippet ex_all.c transaction commit/rollback
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.begin_transaction, see dist/api_data.py}
	 * @config{ignore_prepare, whether to ignore the updates by other prepared transactions as
	 * part of read operations of this transaction.  When \c true\, forces the transaction to be
	 * read-only.  Use \c force to ignore prepared updates and permit writes (which can cause
	 * lost updates unless the application knows something about the relationship between
	 * prepared transactions and the updates that are ignoring them)., a string\, chosen from
	 * the following options: \c "false"\, \c "force"\, \c "true"; default \c false.}
	 * @config{isolation, the isolation level for this transaction; defaults to the session's
	 * isolation level., a string\, chosen from the following options: \c "read-uncommitted"\,
	 * \c "read-committed"\, \c "snapshot"; default empty.}
	 * @config{name, name of the transaction for tracing and debugging., a string; default
	 * empty.}
	 * @config{operation_timeout_ms, when non-zero\, a requested limit on the number of elapsed
	 * real time milliseconds taken to complete database operations in this transaction.  Time
	 * is measured from the start of each WiredTiger API call.  There is no guarantee any
	 * operation will not take longer than this amount of time.  If WiredTiger notices the limit
	 * has been exceeded\, an operation may return a WT_ROLLBACK error.  Default is to have no
	 * limit., an integer greater than or equal to 1; default \c 0.}
	 * @config{priority, priority of the transaction for resolving conflicts.  Transactions with
	 * higher values are less likely to abort., an integer between -100 and 100; default \c 0.}
	 * @config{read_timestamp, read using the specified timestamp.  The supplied value must not
	 * be older than the current oldest timestamp.  See @ref transaction_timestamps., a string;
	 * default empty.}
	 * @config{roundup_timestamps = (, round up timestamps of the transaction.  This setting
	 * alters the visibility expected in a transaction.  See @ref transaction_timestamps., a set
	 * of related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
	 * prepared, applicable only for prepared transactions.  Indicates if the prepare timestamp
	 * and the commit timestamp of this transaction can be rounded up.  If the prepare timestamp
	 * is less than the oldest timestamp\, the prepare timestamp will be rounded to the oldest
	 * timestamp.  If the commit timestamp is less than the prepare timestamp\, the commit
	 * timestamp will be rounded up to the prepare timestamp., a boolean flag; default \c
	 * false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;read, if the read timestamp is less than the
	 * oldest timestamp\, the read timestamp will be rounded up to the oldest timestamp., a
	 * boolean flag; default \c false.}
	 * @config{ ),,}
	 * @config{sync, whether to sync log records when the transaction commits\, inherited from
	 * ::wiredtiger_open \c transaction_sync., a boolean flag; default empty.}
	 * @configend
	 * @errors
	 */
	int __F(begin_transaction)(WT_SESSION *session, const char *config);

	/*!
	 * Commit the current transaction.
	 *
	 * A transaction must be in progress when this method is called.
	 *
	 * If WT_SESSION::commit_transaction returns an error, the transaction
	 * was rolled back, not committed.
	 *
	 * @requires_transaction
	 *
	 * @snippet ex_all.c transaction commit/rollback
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.commit_transaction, see dist/api_data.py}
	 * @config{commit_timestamp, set the commit timestamp for the current transaction.  The
	 * supplied value must not be older than the first commit timestamp set for the current
	 * transaction.  The value must also not be older than the current oldest and stable
	 * timestamps.  See @ref transaction_timestamps., a string; default empty.}
	 * @config{durable_timestamp, set the durable timestamp for the current transaction.  The
	 * supplied value must not be older than the commit timestamp set for the current
	 * transaction.  The value must also not be older than the current stable timestamp.  See
	 * @ref transaction_timestamps., a string; default empty.}
	 * @config{sync, override whether to sync log records when the transaction commits\,
	 * inherited from ::wiredtiger_open \c transaction_sync.  The \c background setting
	 * initiates a background synchronization intended to be used with a later call to
	 * WT_SESSION::transaction_sync.  The \c off setting does not wait for record to be written
	 * or synchronized.  The \c on setting forces log records to be written to the storage
	 * device., a string\, chosen from the following options: \c "background"\, \c "off"\, \c
	 * "on"; default empty.}
	 * @configend
	 * @errors
	 */
	int __F(commit_transaction)(WT_SESSION *session, const char *config);

	/*!
	 * Prepare the current transaction.
	 *
	 * A transaction must be in progress when this method is called.
	 *
	 * Preparing a transaction will guarantee a subsequent commit will
	 * succeed. Only commit and rollback are allowed on a transaction after
	 * it has been prepared. The transaction prepare API is designed to
	 * support MongoDB exclusively, and guarantees update conflicts have
	 * been resolved, but does not guarantee durability.
	 *
	 * @requires_transaction
	 *
	 * @snippet ex_all.c transaction prepare
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.prepare_transaction, see dist/api_data.py}
	 * @config{prepare_timestamp, set the prepare timestamp for the updates of the current
	 * transaction.  The supplied value must not be older than any active read timestamps.  See
	 * @ref transaction_timestamps., a string; default empty.}
	 * @configend
	 * @errors
	 */
	int __F(prepare_transaction)(WT_SESSION *session, const char *config);

	/*!
	 * Roll back the current transaction.
	 *
	 * A transaction must be in progress when this method is called.
	 *
	 * All cursors are reset.
	 *
	 * @requires_transaction
	 *
	 * @snippet ex_all.c transaction commit/rollback
	 *
	 * @param session the session handle
	 * @configempty{WT_SESSION.rollback_transaction, see dist/api_data.py}
	 * @errors
	 */
	int __F(rollback_transaction)(WT_SESSION *session, const char *config);

	/*!
	 * Set a timestamp on a transaction.
	 *
	 * @snippet ex_all.c transaction timestamp
	 *
	 * @requires_transaction
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.timestamp_transaction, see dist/api_data.py}
	 * @config{commit_timestamp, set the commit timestamp for the current transaction.  The
	 * supplied value must not be older than the first commit timestamp set for the current
	 * transaction.  The value must also not be older than the current oldest and stable
	 * timestamps.  See @ref transaction_timestamps., a string; default empty.}
	 * @config{durable_timestamp, set the durable timestamp for the current transaction.  The
	 * supplied value must not be older than the commit timestamp set for the current
	 * transaction.  The value must also not be older than the current stable timestamp.  See
	 * @ref transaction_timestamps., a string; default empty.}
	 * @config{prepare_timestamp, set the prepare timestamp for the updates of the current
	 * transaction.  The supplied value must not be older than any active read timestamps.  See
	 * @ref transaction_timestamps., a string; default empty.}
	 * @config{read_timestamp, read using the specified timestamp.  The supplied value must not
	 * be older than the current oldest timestamp.  This can only be set once for a transaction.
	 * See @ref transaction_timestamps., a string; default empty.}
	 * @configend
	 * @errors
	 */
	int __F(timestamp_transaction)(WT_SESSION *session, const char *config);

	/*!
	 * Query the session's transaction timestamp state.
	 *
	 * @param session the session handle
	 * @param[out] hex_timestamp a buffer that will be set to the
	 * hexadecimal encoding of the timestamp being queried.  Must be large
	 * enough to hold a NUL terminated, hex-encoded 8B timestamp (17 bytes).
	 * @configstart{WT_SESSION.query_timestamp, see dist/api_data.py}
	 * @config{get, specify which timestamp to query: \c commit returns the most recently set
	 * commit_timestamp.  \c first_commit returns the first set commit_timestamp.  \c prepare
	 * returns the timestamp used in preparing a transaction.  \c read returns the timestamp at
	 * which the transaction is reading at.  See @ref transaction_timestamps., a string\, chosen
	 * from the following options: \c "commit"\, \c "first_commit"\, \c "prepare"\, \c "read";
	 * default \c read.}
	 * @configend
	 * @errors
	 * If the session is not in a transaction ::WT_NOTFOUND will be
	 * returned.
	 */
	int __F(query_timestamp)(
	    WT_SESSION *session, char *hex_timestamp, const char *config);

	/*!
	 * Write a transactionally consistent snapshot of a database or set of
	 * objects.  In the absence of transaction timestamps, the checkpoint
	 * includes all transactions committed before the checkpoint starts.
	 *
	 * When timestamps are in use and a \c stable_timestamp has been set
	 * via WT_CONNECTION::set_timestamp and the checkpoint runs with
	 * \c use_timestamp=true (the default), updates committed with a
	 * timestamp larger than the \c stable_timestamp will not be included
	 * in the checkpoint for tables configured with \c log=(enabled=false).
	 * For tables with logging enabled, all committed changes will be
	 * included in the checkpoint (since recovery would roll them forward
	 * anyway).
	 *
	 * Additionally, existing named checkpoints may optionally be
	 * discarded.
	 *
	 * @requires_notransaction
	 *
	 * @snippet ex_all.c Checkpoint examples
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.checkpoint, see dist/api_data.py}
	 * @config{drop, specify a list of checkpoints to drop.  The list may additionally contain
	 * one of the following keys: \c "from=all" to drop all checkpoints\, \c "from=<checkpoint>"
	 * to drop all checkpoints after and including the named checkpoint\, or \c
	 * "to=<checkpoint>" to drop all checkpoints before and including the named checkpoint.
	 * Checkpoints cannot be dropped if open in a cursor.  While a hot backup is in progress\,
	 * checkpoints created prior to the start of the backup cannot be dropped., a list of
	 * strings; default empty.}
	 * @config{force, if false (the default)\, checkpoints may be skipped if the underlying
	 * object has not been modified\, if true\, this option forces the checkpoint., a boolean
	 * flag; default \c false.}
	 * @config{name, if set\, specify a name for the checkpoint (note that checkpoints including
	 * LSM trees may not be named)., a string; default empty.}
	 * @config{target, if non-empty\, checkpoint the list of objects., a list of strings;
	 * default empty.}
	 * @config{use_timestamp, if true (the default)\, create the checkpoint as of the last
	 * stable timestamp if timestamps are in use\, or all current updates if there is no stable
	 * timestamp set.  If false\, this option generates a checkpoint with all updates including
	 * those later than the timestamp., a boolean flag; default \c true.}
	 * @configend
	 * @errors
	 */
	int __F(checkpoint)(WT_SESSION *session, const char *config);

	/*!
	 * Return the transaction ID range pinned by the session handle.
	 *
	 * The ID range is approximate and is calculated based on the oldest
	 * ID needed for the active transaction in this session, compared
	 * to the newest transaction in the system.
	 *
	 * @snippet ex_all.c transaction pinned range
	 *
	 * @param session the session handle
	 * @param[out] range the range of IDs pinned by this session. Zero if
	 * there is no active transaction.
	 * @errors
	 */
	int __F(transaction_pinned_range)(WT_SESSION* session, uint64_t *range);

	/*!
	 * Wait for a transaction to become synchronized.  This method is
	 * only useful when ::wiredtiger_open is configured with the
	 * \c transaction_sync setting disabled.
	 *
	 * @requires_notransaction
	 *
	 * @snippet ex_all.c Transaction sync
	 *
	 * @param session the session handle
	 * @configstart{WT_SESSION.transaction_sync, see dist/api_data.py}
	 * @config{timeout_ms, maximum amount of time to wait for background sync to complete in
	 * milliseconds.  A value of zero disables the timeout and returns immediately., an integer;
	 * default \c 1200000.}
	 * @configend
	 * @errors
	 */
	int __F(transaction_sync)(WT_SESSION *session, const char *config);
	/*! @} */

#ifndef DOXYGEN
	/*!
	 * Call into the library.
	 *
	 * This method is used for breakpoints and to set other configuration
	 * when debugging layers not directly supporting those features.
	 *
	 * @param session the session handle
	 * @errors
	 */
	int __F(breakpoint)(WT_SESSION *session);
#endif
};

/*!
 * A connection to a WiredTiger database.  The connection may be opened within
 * the same address space as the caller or accessed over a socket connection.
 *
 * Most applications will open a single connection to a database for each
 * process.  The first process to open a connection to a database will access
 * the database in its own address space.  Subsequent connections (if allowed)
 * will communicate with the first process over a socket connection to perform
 * their operations.
 *
 * <b>Thread safety:</b> A WT_CONNECTION handle may be shared between threads,
 * see @ref threads for more information.
 */
struct __wt_connection {
	/*!
	 * @name Async operation handles
	 * @{
	 */
	/*!
	 * Wait for all outstanding operations to complete.
	 *
	 * @snippet ex_async.c async flush
	 *
	 * @param connection the connection handle
	 * @errors
	 */
	int __F(async_flush)(WT_CONNECTION *connection);

	/*!
	 * Return an async operation handle
	 *
	 * @snippet ex_async.c async handle allocation
	 *
	 * @param connection the connection handle
	 * @param uri the connection handle
	 * @configstart{WT_CONNECTION.async_new_op, see dist/api_data.py}
	 * @config{append, append the value as a new record\, creating a new record number key;
	 * valid only for operations with record number keys., a boolean flag; default \c false.}
	 * @config{overwrite, configures whether the cursor's insert\, update and remove methods
	 * check the existing state of the record.  If \c overwrite is \c false\, WT_CURSOR::insert
	 * fails with ::WT_DUPLICATE_KEY if the record exists\, WT_CURSOR::update and
	 * WT_CURSOR::remove fail with ::WT_NOTFOUND if the record does not exist., a boolean flag;
	 * default \c true.}
	 * @config{raw, ignore the encodings for the key and value\, manage data as if the formats
	 * were \c "u". See @ref cursor_raw for details., a boolean flag; default \c false.}
	 * @config{timeout, maximum amount of time to allow for compact in seconds.  The actual
	 * amount of time spent in compact may exceed the configured value.  A value of zero
	 * disables the timeout., an integer; default \c 1200.}
	 * @configend
	 * @param callback the operation callback
	 * @param[out] asyncopp the new op handle
	 * @errors
	 * If there are no available handles, \c EBUSY is returned.
	 */
	int __F(async_new_op)(WT_CONNECTION *connection,
	    const char *uri, const char *config, WT_ASYNC_CALLBACK *callback,
	    WT_ASYNC_OP **asyncopp);
	/*! @} */

	/*!
	 * Close a connection.
	 *
	 * Any open sessions will be closed. This will release the resources
	 * associated with the session handle, including rolling back any
	 * active transactions and closing any cursors that remain open in the
	 * session.
	 *
	 * @snippet ex_all.c Close a connection
	 *
	 * @param connection the connection handle
	 * @configstart{WT_CONNECTION.close, see dist/api_data.py}
	 * @config{leak_memory, don't free memory during close., a boolean flag; default \c false.}
	 * @config{use_timestamp, by default\, create the close checkpoint as of the last stable
	 * timestamp if timestamps are in use\, or all current updates if there is no stable
	 * timestamp set.  If false\, this option generates a checkpoint with all updates., a
	 * boolean flag; default \c true.}
	 * @configend
	 * @errors
	 */
	int __F(close)(WT_HANDLE_CLOSED(WT_CONNECTION) *connection,
	    const char *config);

#ifndef DOXYGEN
	/*!
	 * Output debug information for various subsystems. The output format
	 * may change over time, gathering the debug information may be
	 * invasive, and the information reported may not provide a point in
	 * time view of the system.
	 *
	 * @param connection the connection handle
	 * @configstart{WT_CONNECTION.debug_info, see dist/api_data.py}
	 * @config{cache, print cache information., a boolean flag; default \c false.}
	 * @config{cursors, print all open cursor information., a boolean flag; default \c false.}
	 * @config{handles, print open handles information., a boolean flag; default \c false.}
	 * @config{log, print log information., a boolean flag; default \c false.}
	 * @config{sessions, print open session information., a boolean flag; default \c false.}
	 * @config{txn, print global txn information., a boolean flag; default \c false.}
	 * @configend
	 * @errors
	 */
	int __F(debug_info)(WT_CONNECTION *connection, const char *config);
#endif

	/*!
	 * Reconfigure a connection handle.
	 *
	 * @snippet ex_all.c Reconfigure a connection
	 *
	 * @param connection the connection handle
	 * @configstart{WT_CONNECTION.reconfigure, see dist/api_data.py}
	 * @config{async = (, asynchronous operations configuration options., a set of related
	 * configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, enable
	 * asynchronous operation., a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;ops_max, maximum number of expected simultaneous
	 * asynchronous operations., an integer between 1 and 4096; default \c 1024.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;threads, the number of worker threads to service
	 * asynchronous requests.  Each worker thread uses a session from the configured
	 * session_max., an integer between 1 and 20; default \c 2.}
	 * @config{ ),,}
	 * @config{cache_max_wait_ms, the maximum number of milliseconds an application thread will
	 * wait for space to be available in cache before giving up.  Default will wait forever., an
	 * integer greater than or equal to 0; default \c 0.}
	 * @config{cache_overflow = (, cache overflow configuration options., a set of related
	 * configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;file_max, The
	 * maximum number of bytes that WiredTiger is allowed to use for its cache overflow
	 * mechanism.  If the cache overflow file exceeds this size\, a panic will be triggered.
	 * The default value means that the cache overflow file is unbounded and may use as much
	 * space as the filesystem will accommodate.  The minimum non-zero setting is 100MB., an
	 * integer greater than or equal to 0; default \c 0.}
	 * @config{ ),,}
	 * @config{cache_overhead, assume the heap allocator overhead is the specified percentage\,
	 * and adjust the cache usage by that amount (for example\, if there is 10GB of data in
	 * cache\, a percentage of 10 means WiredTiger treats this as 11GB). This value is
	 * configurable because different heap allocators have different overhead and different
	 * workloads will have different heap allocation sizes and patterns\, therefore applications
	 * may need to adjust this value based on allocator choice and behavior in measured
	 * workloads., an integer between 0 and 30; default \c 8.}
	 * @config{cache_size, maximum heap memory to allocate for the cache.  A database should
	 * configure either \c cache_size or \c shared_cache but not both., an integer between 1MB
	 * and 10TB; default \c 100MB.}
	 * @config{checkpoint = (, periodically checkpoint the database.  Enabling the checkpoint
	 * server uses a session from the configured session_max., a set of related configuration
	 * options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;log_size, wait for this amount of
	 * log record bytes to be written to the log between each checkpoint.  If non-zero\, this
	 * value will use a minimum of the log file size.  A database can configure both log_size
	 * and wait to set an upper bound for checkpoints; setting this value above 0 configures
	 * periodic checkpoints., an integer between 0 and 2GB; default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;wait, seconds to wait between each checkpoint; setting
	 * this value above 0 configures periodic checkpoints., an integer between 0 and 100000;
	 * default \c 0.}
	 * @config{ ),,}
	 * @config{compatibility = (, set compatibility version of database.  Changing the
	 * compatibility version requires that there are no active operations for the duration of
	 * the call., a set of related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;release, compatibility release version string., a string;
	 * default empty.}
	 * @config{ ),,}
	 * @config{debug_mode = (, control the settings of various extended debugging features., a
	 * set of related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
	 * checkpoint_retention, adjust log archiving to retain the log records of this number of
	 * checkpoints.  Zero or one means perform normal archiving., an integer between 0 and 1024;
	 * default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;cursor_copy, if true\, use the system
	 * allocator to make a copy of any data returned by a cursor operation and return the copy
	 * instead.  The copy is freed on the next cursor operation.  This allows memory sanitizers
	 * to detect inappropriate references to memory owned by cursors., a boolean flag; default
	 * \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;eviction, if true\, modify internal algorithms
	 * to change skew to force history store eviction to happen more aggressively.  This
	 * includes but is not limited to not skewing newest\, not favoring leaf pages\, and
	 * modifying the eviction score mechanism., a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;log_retention, adjust log archiving to retain at least
	 * this number of log files\, ignored if set to 0. (Warning: this option can remove log
	 * files required for recovery if no checkpoints have yet been done and the number of log
	 * files exceeds the configured value.  As WiredTiger cannot detect the difference between a
	 * system that has not yet checkpointed and one that will never checkpoint\, it might
	 * discard log files before any checkpoint is done.)., an integer between 0 and 1024;
	 * default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;realloc_exact, if true\, reallocation of
	 * memory will only provide the exact amount requested.  This will help with spotting memory
	 * allocation issues more easily., a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;rollback_error, return a WT_ROLLBACK error from a
	 * transaction operation about every Nth operation to simulate a collision., an integer
	 * between 0 and 10M; default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;slow_checkpoint, if
	 * true\, slow down checkpoint creation by slowing down internal page processing., a boolean
	 * flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;table_logging, if true\, write
	 * transaction related information to the log for all operations\, even operations for
	 * tables with logging turned off.  This setting introduces a log format change that may
	 * break older versions of WiredTiger.  These operations are informational and skipped in
	 * recovery., a boolean flag; default \c false.}
	 * @config{ ),,}
	 * @config{error_prefix, prefix string for error messages., a string; default empty.}
	 * @config{eviction = (, eviction configuration options., a set of related configuration
	 * options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;threads_max, maximum number of
	 * threads WiredTiger will start to help evict pages from cache.  The number of threads
	 * started will vary depending on the current eviction load.  Each eviction worker thread
	 * uses a session from the configured session_max., an integer between 1 and 20; default \c
	 * 8.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;threads_min, minimum number of threads WiredTiger
	 * will start to help evict pages from cache.  The number of threads currently running will
	 * vary depending on the current eviction load., an integer between 1 and 20; default \c 1.}
	 * @config{ ),,}
	 * @config{eviction_checkpoint_target, perform eviction at the beginning of checkpoints to
	 * bring the dirty content in cache to this level.  It is a percentage of the cache size if
	 * the value is within the range of 0 to 100 or an absolute size when greater than 100. The
	 * value is not allowed to exceed the \c cache_size.  Ignored if set to zero or \c in_memory
	 * is \c true., an integer between 0 and 10TB; default \c 1.}
	 * @config{eviction_dirty_target, perform eviction in worker threads when the cache contains
	 * at least this much dirty content.  It is a percentage of the cache size if the value is
	 * within the range of 1 to 100 or an absolute size when greater than 100. The value is not
	 * allowed to exceed the \c cache_size., an integer between 1 and 10TB; default \c 5.}
	 * @config{eviction_dirty_trigger, trigger application threads to perform eviction when the
	 * cache contains at least this much dirty content.  It is a percentage of the cache size if
	 * the value is within the range of 1 to 100 or an absolute size when greater than 100. The
	 * value is not allowed to exceed the \c cache_size.  This setting only alters behavior if
	 * it is lower than eviction_trigger., an integer between 1 and 10TB; default \c 20.}
	 * @config{eviction_target, perform eviction in worker threads when the cache contains at
	 * least this much content.  It is a percentage of the cache size if the value is within the
	 * range of 10 to 100 or an absolute size when greater than 100. The value is not allowed to
	 * exceed the \c cache_size., an integer between 10 and 10TB; default \c 80.}
	 * @config{eviction_trigger, trigger application threads to perform eviction when the cache
	 * contains at least this much content.  It is a percentage of the cache size if the value
	 * is within the range of 10 to 100 or an absolute size when greater than 100. The value is
	 * not allowed to exceed the \c cache_size., an integer between 10 and 10TB; default \c 95.}
	 * @config{eviction_updates_target, perform eviction in worker threads when the cache
	 * contains at least this many bytes of updates.  It is a percentage of the cache size if
	 * the value is within the range of 0 to 100 or an absolute size when greater than 100.
	 * Calculated as half of \c eviction_dirty_target by default.  The value is not allowed to
	 * exceed the \c cache_size., an integer between 0 and 10TB; default \c 0.}
	 * @config{eviction_updates_trigger, trigger application threads to perform eviction when
	 * the cache contains at least this many bytes of updates.  It is a percentage of the cache
	 * size if the value is within the range of 1 to 100 or an absolute size when greater than
	 * 100. Calculated as half of \c eviction_dirty_trigger by default.  The value is not
	 * allowed to exceed the \c cache_size.  This setting only alters behavior if it is lower
	 * than eviction_trigger., an integer between 0 and 10TB; default \c 0.}
	 * @config{file_manager = (, control how file handles are managed., a set of related
	 * configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
	 * close_handle_minimum, number of handles open before the file manager will look for
	 * handles to close., an integer greater than or equal to 0; default \c 250.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;close_idle_time, amount of time in seconds a file handle
	 * needs to be idle before attempting to close it.  A setting of 0 means that idle handles
	 * are not closed., an integer between 0 and 100000; default \c 30.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;close_scan_interval, interval in seconds at which to
	 * check for files that are inactive and close them., an integer between 1 and 100000;
	 * default \c 10.}
	 * @config{ ),,}
	 * @config{history_store = (, history store configuration options., a set of related
	 * configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;file_max, The
	 * maximum number of bytes that WiredTiger is allowed to use for its history store
	 * mechanism.  If the history store file exceeds this size\, a panic will be triggered.  The
	 * default value means that the history store file is unbounded and may use as much space as
	 * the filesystem will accommodate.  The minimum non-zero setting is 100MB., an integer
	 * greater than or equal to 0; default \c 0.}
	 * @config{ ),,}
	 * @config{io_capacity = (, control how many bytes per second are written and read.
	 * Exceeding the capacity results in throttling., a set of related configuration options
	 * defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;total, number of bytes per second
	 * available to all subsystems in total.  When set\, decisions about what subsystems are
	 * throttled\, and in what proportion\, are made internally.  The minimum non-zero setting
	 * is 1MB., an integer between 0 and 1TB; default \c 0.}
	 * @config{ ),,}
	 * @config{log = (, enable logging.  Enabling logging uses three sessions from the
	 * configured session_max., a set of related configuration options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;archive, automatically archive unneeded log files., a
	 * boolean flag; default \c true.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;os_cache_dirty_pct,
	 * maximum dirty system buffer cache usage\, as a percentage of the log's \c file_max.  If
	 * non-zero\, schedule writes for dirty blocks belonging to the log in the system buffer
	 * cache after that percentage of the log has been written into the buffer cache without an
	 * intervening file sync., an integer between 0 and 100; default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;prealloc, pre-allocate log files., a boolean flag;
	 * default \c true.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;zero_fill, manually write zeroes into
	 * log files., a boolean flag; default \c false.}
	 * @config{ ),,}
	 * @config{lsm_manager = (, configure database wide options for LSM tree management.  The
	 * LSM manager is started automatically the first time an LSM tree is opened.  The LSM
	 * manager uses a session from the configured session_max., a set of related configuration
	 * options defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;merge, merge LSM chunks where
	 * possible., a boolean flag; default \c true.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
	 * worker_thread_max, Configure a set of threads to manage merging LSM trees in the
	 * database.  Each worker thread uses a session handle from the configured session_max., an
	 * integer between 3 and 20; default \c 4.}
	 * @config{ ),,}
	 * @config{operation_timeout_ms, when non-zero\, a requested limit on the number of elapsed
	 * real time milliseconds application threads will take to complete database operations.
	 * Time is measured from the start of each WiredTiger API call.  There is no guarantee any
	 * operation will not take longer than this amount of time.  If WiredTiger notices the limit
	 * has been exceeded\, an operation may return a WT_ROLLBACK error.  Default is to have no
	 * limit., an integer greater than or equal to 1; default \c 0.}
	 * @config{operation_tracking = (, enable tracking of performance-critical functions.  See
	 * @ref operation_tracking for more information., a set of related configuration options
	 * defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, enable operation tracking
	 * subsystem., a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;path, the
	 * name of a directory into which operation tracking files are written.  The directory must
	 * already exist.  If the value is not an absolute path\, the path is relative to the
	 * database home (see @ref absolute_path for more information)., a string; default \c ".".}
	 * @config{ ),,}
	 * @config{shared_cache = (, shared cache configuration options.  A database should
	 * configure either a cache_size or a shared_cache not both.  Enabling a shared cache uses a
	 * session from the configured session_max.  A shared cache can not have absolute values
	 * configured for cache eviction settings., a set of related configuration options defined
	 * below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;chunk, the granularity that a shared cache is
	 * redistributed., an integer between 1MB and 10TB; default \c 10MB.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;name, the name of a cache that is shared between
	 * databases or \c "none" when no shared cache is configured., a string; default \c none.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;quota, maximum size of cache this database can be
	 * allocated from the shared cache.  Defaults to the entire shared cache size., an integer;
	 * default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;reserve, amount of cache this database is
	 * guaranteed to have available from the shared cache.  This setting is per database.
	 * Defaults to the chunk size., an integer; default \c 0.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
	 * size, maximum memory to allocate for the shared cache.  Setting this will update the
	 * value if one is already set., an integer between 1MB and 10TB; default \c 500MB.}
	 * @config{ ),,}
	 * @config{statistics, Maintain database statistics\, which may impact performance.
	 * Choosing "all" maintains all statistics regardless of cost\, "fast" maintains a subset of
	 * statistics that are relatively inexpensive\, "none" turns off all statistics.  The
	 * "clear" configuration resets statistics after they are gathered\, where appropriate (for
	 * example\, a cache size statistic is not cleared\, while the count of cursor insert
	 * operations will be cleared). When "clear" is configured for the database\, gathered
	 * statistics are reset each time a statistics cursor is used to gather statistics\, as well
	 * as each time statistics are logged using the \c statistics_log configuration.  See @ref
	 * statistics for more information., a list\, with values chosen from the following options:
	 * \c "all"\, \c "cache_walk"\, \c "fast"\, \c "none"\, \c "clear"\, \c "tree_walk"; default
	 * \c none.}
	 * @config{statistics_log = (, log any statistics the database is configured to maintain\,
	 * to a file.  See @ref statistics for more information.  Enabling the statistics log server
	 * uses a session from the configured session_max., a set of related configuration options
	 * defined below.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;json, encode statistics in JSON format.,
	 * a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;on_close, log
	 * statistics on database close., a boolean flag; default \c false.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;sources, if non-empty\, include statistics for the list
	 * of data source URIs\, if they are open at the time of the statistics logging.  The list
	 * may include URIs matching a single data source ("table:mytable")\, or a URI matching all
	 * data sources of a particular type ("table:")., a list of strings; default empty.}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;timestamp, a timestamp prepended to each log record\, may
	 * contain strftime conversion specifications\, when \c json is configured\, defaults to \c
	 * "%FT%Y.000Z"., a string; default \c "%b %d %H:%M:%S".}
	 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
	 * wait, seconds to wait between each write of the log records; setting this value above 0
	 * configures statistics logging., an integer between 0 and 100000; default \c 0.}
	 * @config{
	 * ),,}
	 * @config{verbose, enable messages for various events.  Options are given as a list\, such
	 * as <code>"verbose=[evictserver\,read]"</code>., a list\, with values chosen from the
	 * following options: \c "api"\, \c "backup"\, \c "block"\, \c "checkpoint"\, \c
	 * "checkpoint_cleanup"\, \c "checkpoint_progress"\, \c "compact"\, \c "compact_progress"\,
	 * \c "error_returns"\, \c "evict"\, \c "evict_stuck"\, \c "evictserver"\, \c "fileops"\, \c
	 * "handleops"\, \c "log"\, \c "history_store"\, \c "history_store_activity"\, \c "lsm"\, \c
	 * "lsm_manager"\, \c "metadata"\, \c "mutex"\, \c "overflow"\, \c "read"\, \c "rebalance"\,
	 * \c "reconcile"\, \c "recovery"\, \c "recovery_progress"\, \c "rts"\, \c "salvage"\, \c
	 * "shared_cache"\, \c "split"\, \c "temporary"\, \c "thread_group"\, \c "timestamp"\, \c
	 * "transaction"\, \c "verify"\, \c "version"\, \c "write"; default empty.}
	 * @configend
	 * @errors
	 */
	int __F(reconfigure)(WT_CONNECTION *connection, const char *config);

	/*!
	 * The home directory of the connection.
	 *
	 * @snippet ex_all.c Get the database home directory
	 *
	 * @param connection the connection handle
	 * @returns a pointer to a string naming the home directory
	 */
	const char *__F(get_home)(WT_CONNECTION *connection);

	/*!
	 * Add configuration options for a method.  See
	 * @ref custom_ds_config_add for more information.
	 *
	 * @snippet ex_all.c Configure method configuration
	 *
	 * @param connection the connection handle
	 * @param method the method being configured
	 * @param uri the object type or NULL for all object types
	 * @param config the additional configuration's name and default value
	 * @param type the additional configuration's type (must be one of
	 * \c "boolean"\, \c "int", \c "list" or \c "string")
	 * @param check the additional configuration check string, or NULL if
	 * none
	 * @errors
	 */
	int __F(configure_method)(WT_CONNECTION *connection,
	    const char *method, const char *uri,
	    const char *config, const char *type, const char *check);

	/*!
	 * Return if opening this handle created the database.
	 *
	 * @snippet ex_all.c Check if the database is newly created
	 *
	 * @param connection the connection handle
	 * @returns false (zero) if the connection existed before the call to
	 * ::wiredtiger_open, true (non-zero) if it was created by opening this
	 * handle.
	 */
	int __F(is_new)(WT_CONNECTION *connection);

	/*!
	 * @name Session handles
	 * @{
	 */
	/*!
	 * Open a session.
	 *
	 * @snippet ex_all.c Open a session
	 *
	 * @param connection the connection handle
	 * @param event_handler An event handler. If <code>NULL</code>, the
	 * connection's event handler is used. See @ref event_message_handling
	 * for more information.
	 * @configstart{WT_CONNECTION.open_session, see dist/api_data.py}
	 * @config{cache_cursors, enable caching of cursors for reuse.  Any calls to
	 * WT_CURSOR::close for a cursor created in this session will mark the cursor as cached and
	 * keep it available to be reused for later calls to WT_SESSION::open_cursor.  Cached
	 * cursors may be eventually closed.  This value is inherited from ::wiredtiger_open \c
	 * cache_cursors., a boolean flag; default \c true.}
	 * @config{ignore_cache_size, when set\, operations performed by this session ignore the
	 * cache size and are not blocked when the cache is full.  Note that use of this option for
	 * operations that create cache pressure can starve ordinary sessions that obey the cache
	 * size., a boolean flag; default \c false.}
	 * @config{isolation, the default isolation level for operations in this session., a
	 * string\, chosen from the following options: \c "read-uncommitted"\, \c "read-committed"\,
	 * \c "snapshot"; default \c read-committed.}
	 * @configend
	 * @param[out] sessionp the new session handle
	 * @errors
	 */
	int __F(open_session)(WT_CONNECTION *connection,
	    WT_EVENT_HANDLER *event_handler, const char *config,
	    WT_SESSION **sessionp);
	/*! @} */

	/*!
	 * @name Transactions
	 * @{
	 */
	/*!
	 * Query the global transaction timestamp state.
	 *
	 * @snippet ex_all.c query timestamp
	 *
	 * @param connection the connection handle
	 * @param[out] hex_timestamp a buffer that will be set to the
	 * hexadecimal encoding of the timestamp being queried.  Must be large
	 * enough to hold a NUL terminated, hex-encoded 8B timestamp (17 bytes).
	 * @configstart{WT_CONNECTION.query_timestamp, see dist/api_data.py}
	 * @config{get, specify which timestamp to query: \c all_durable returns the largest
	 * timestamp such that all timestamps up to that value have been made durable\, \c
	 * last_checkpoint returns the timestamp of the most recent stable checkpoint\, \c oldest
	 * returns the most recent \c oldest_timestamp set with WT_CONNECTION::set_timestamp\, \c
	 * oldest_reader returns the minimum of the read timestamps of all active readers \c pinned
	 * returns the minimum of the \c oldest_timestamp and the read timestamps of all active
	 * readers\, \c recovery returns the timestamp of the most recent stable checkpoint taken
	 * prior to a shutdown and \c stable returns the most recent \c stable_timestamp set with
	 * WT_CONNECTION::set_timestamp.  See @ref transaction_timestamps., a string\, chosen from
	 * the following options: \c "all_durable"\, \c "last_checkpoint"\, \c "oldest"\, \c
	 * "oldest_reader"\, \c "pinned"\, \c "recovery"\, \c "stable"; default \c all_durable.}
	 * @configend
	 * @errors
	 * If there is no matching timestamp (e.g., if this method is called
	 * before timestamps are used) ::WT_NOTFOUND will be returned.
	 */
	int __F(query_timestamp)(
	    WT_CONNECTION *connection, char *hex_timestamp, const char *config);

	/*!
	 * Set a global transaction timestamp.
	 *
	 * @snippet ex_all.c set commit timestamp
	 *
	 * @snippet ex_all.c set oldest timestamp
	 *
	 * @snippet ex_all.c set stable timestamp
	 *
	 * @param connection the connection handle
	 * @configstart{WT_CONNECTION.set_timestamp, see dist/api_data.py}
	 * @config{commit_timestamp, (deprecated) reset the maximum commit timestamp tracked by
	 * WiredTiger.  This will cause future calls to WT_CONNECTION::query_timestamp to ignore
	 * commit timestamps greater than the specified value until the next commit moves the
	 * tracked commit timestamp forwards.  This is only intended for use where the application
	 * is rolling back locally committed transactions.  The supplied value must not be older
	 * than the current oldest and stable timestamps.  See @ref transaction_timestamps., a
	 * string; default empty.}
	 * @config{durable_timestamp, reset the maximum durable timestamp tracked by WiredTiger.
	 * This will cause future calls to WT_CONNECTION::query_timestamp to ignore durable
	 * timestamps greater than the specified value until the next durable timestamp moves the
	 * tracked durable timestamp forwards.  This is only intended for use where the application
	 * is rolling back locally committed transactions.  The supplied value must not be older
	 * than the current oldest and stable timestamps.  See @ref transaction_timestamps., a
	 * string; default empty.}
	 * @config{force, set timestamps even if they violate normal ordering requirements.  For
	 * example allow the \c oldest_timestamp to move backwards., a boolean flag; default \c
	 * false.}
	 * @config{oldest_timestamp, future commits and queries will be no earlier than the
	 * specified timestamp.  Supplied values must be monotonically increasing\, any attempt to
	 * set the value to older than the current is silently ignored.  The supplied value must not
	 * be newer than the current stable timestamp.  See @ref transaction_timestamps., a string;
	 * default empty.}
	 * @config{stable_timestamp, checkpoints will not include commits that are newer than the
	 * specified timestamp in tables configured with \c log=(enabled=false). Supplied values
	 * must be monotonically increasing\, any attempt to set the value to older than the current
	 * is silently ignored.  The supplied value must not be older than the current oldest
	 * timestamp.  See @ref transaction_timestamps., a string; default empty.}
	 * @configend
	 * @errors
	 */
	int __F(set_timestamp)(
	    WT_CONNECTION *connection, const char *config);

	/*!
	 * Rollback in-memory non-logged state to an earlier point in time.
	 *
	 * This method uses a timestamp to define the rollback point, and requires the application
	 * use timestamps, the stable_timestamp have been set via a call to
	 * WT_CONNECTION::set_timestamp, and a checkpoint operating on the last stable timestamp
	 * to have completed. Any updates to checkpoint durable tables that are more recent than
	 * the stable timestamp are removed.
	 *
	 * This method requires that there are no active operations for the duration of the call.
	 *
	 * Any updates made to logged tables will not be rolled back. Any updates made without an
	 * associated timestamp will not be rolled back. See @ref transaction_timestamps.
	 *
	 * @snippet ex_all.c rollback to stable
	 *
	 * @param connection the connection handle
	 * @configempty{WT_CONNECTION.rollback_to_stable, see dist/api_data.py}
	 * @errors
	 */
	int __F(rollback_to_stable)(
	    WT_CONNECTION *connection, const char *config);

	/*! @} */

	/*!
	 * @name Extensions
	 * @{
	 */
	/*!
	 * Load an extension.
	 *
	 * @snippet ex_all.c Load an extension
	 *
	 * @param connection the connection handle
	 * @param path the filename of the extension module, or \c "local" to
	 * search the current application binary for the initialization
	 * function, see @ref extensions for more details.
	 * @configstart{WT_CONNECTION.load_extension, see dist/api_data.py}
	 * @config{config, configuration string passed to the entry point of the extension as its
	 * WT_CONFIG_ARG argument., a string; default empty.}
	 * @config{early_load, whether this extension should be loaded at the beginning of
	 * ::wiredtiger_open.  Only applicable to extensions loaded via the wiredtiger_open
	 * configurations string., a boolean flag; default \c false.}
	 * @config{entry, the entry point of the extension\, called to initialize the extension when
	 * it is loaded.  The signature of the function must match ::wiredtiger_extension_init., a
	 * string; default \c wiredtiger_extension_init.}
	 * @config{terminate, an optional function in the extension that is called before the
	 * extension is unloaded during WT_CONNECTION::close.  The signature of the function must
	 * match ::wiredtiger_extension_terminate., a string; default \c
	 * wiredtiger_extension_terminate.}
	 * @configend
	 * @errors
	 */
	int __F(load_extension)(WT_CONNECTION *connection,
	    const char *path, const char *config);

	/*!
	 * Add a custom data source.  See @ref custom_data_sources for more
	 * information.
	 *
	 * The application must first implement the WT_DATA_SOURCE interface
	 * and then register the implementation with WiredTiger:
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE register
	 *
	 * @param connection the connection handle
	 * @param prefix the URI prefix for this data source, e.g., "file:"
	 * @param data_source the application-supplied implementation of
	 *	WT_DATA_SOURCE to manage this data source.
	 * @configempty{WT_CONNECTION.add_data_source, see dist/api_data.py}
	 * @errors
	 */
	int __F(add_data_source)(WT_CONNECTION *connection, const char *prefix,
	    WT_DATA_SOURCE *data_source, const char *config);

	/*!
	 * Add a custom collation function.
	 *
	 * The application must first implement the WT_COLLATOR interface and
	 * then register the implementation with WiredTiger:
	 *
	 * @snippet ex_all.c WT_COLLATOR register
	 *
	 * @param connection the connection handle
	 * @param name the name of the collation to be used in calls to
	 * 	WT_SESSION::create, may not be \c "none"
	 * @param collator the application-supplied collation handler
	 * @configempty{WT_CONNECTION.add_collator, see dist/api_data.py}
	 * @errors
	 */
	int __F(add_collator)(WT_CONNECTION *connection,
	    const char *name, WT_COLLATOR *collator, const char *config);

	/*!
	 * Add a compression function.
	 *
	 * The application must first implement the WT_COMPRESSOR interface
	 * and then register the implementation with WiredTiger:
	 *
	 * @snippet nop_compress.c WT_COMPRESSOR initialization structure
	 *
	 * @snippet nop_compress.c WT_COMPRESSOR initialization function
	 *
	 * @param connection the connection handle
	 * @param name the name of the compression function to be used in calls
	 *	to WT_SESSION::create, may not be \c "none"
	 * @param compressor the application-supplied compression handler
	 * @configempty{WT_CONNECTION.add_compressor, see dist/api_data.py}
	 * @errors
	 */
	int __F(add_compressor)(WT_CONNECTION *connection,
	    const char *name, WT_COMPRESSOR *compressor, const char *config);

	/*!
	 * Add an encryption function.
	 *
	 * The application must first implement the WT_ENCRYPTOR interface
	 * and then register the implementation with WiredTiger:
	 *
	 * @snippet nop_encrypt.c WT_ENCRYPTOR initialization structure
	 *
	 * @snippet nop_encrypt.c WT_ENCRYPTOR initialization function
	 *
	 * @param connection the connection handle
	 * @param name the name of the encryption function to be used in calls
	 *	to WT_SESSION::create, may not be \c "none"
	 * @param encryptor the application-supplied encryption handler
	 * @configempty{WT_CONNECTION.add_encryptor, see dist/api_data.py}
	 * @errors
	 */
	int __F(add_encryptor)(WT_CONNECTION *connection,
	    const char *name, WT_ENCRYPTOR *encryptor, const char *config);

	/*!
	 * Add a custom extractor for index keys or column groups.
	 *
	 * The application must first implement the WT_EXTRACTOR interface and
	 * then register the implementation with WiredTiger:
	 *
	 * @snippet ex_all.c WT_EXTRACTOR register
	 *
	 * @param connection the connection handle
	 * @param name the name of the extractor to be used in calls to
	 * 	WT_SESSION::create, may not be \c "none"
	 * @param extractor the application-supplied extractor
	 * @configempty{WT_CONNECTION.add_extractor, see dist/api_data.py}
	 * @errors
	 */
	int __F(add_extractor)(WT_CONNECTION *connection, const char *name,
	    WT_EXTRACTOR *extractor, const char *config);

	/*!
	 * Configure a custom file system.
	 *
	 * This method can only be called from an early loaded extension
	 * module. The application must first implement the WT_FILE_SYSTEM
	 * interface and then register the implementation with WiredTiger:
	 *
	 * @snippet ex_file_system.c WT_FILE_SYSTEM register
	 *
	 * @param connection the connection handle
	 * @param fs the populated file system structure
	 * @configempty{WT_CONNECTION.set_file_system, see dist/api_data.py}
	 * @errors
	 */
	int __F(set_file_system)(
	    WT_CONNECTION *connection, WT_FILE_SYSTEM *fs, const char *config);

	/*!
	 * Return a reference to the WiredTiger extension functions.
	 *
	 * @snippet ex_data_source.c WT_EXTENSION_API declaration
	 *
	 * @param wt_conn the WT_CONNECTION handle
	 * @returns a reference to a WT_EXTENSION_API structure.
	 */
	WT_EXTENSION_API *__F(get_extension_api)(WT_CONNECTION *wt_conn);
	/*! @} */
};

/*!
 * Open a connection to a database.
 *
 * @snippet ex_all.c Open a connection
 *
 * @param home The path to the database home directory.  See @ref home
 * for more information.
 * @param event_handler An event handler. If <code>NULL</code>, a default
 * event handler is installed that writes error messages to stderr. See
 * @ref event_message_handling for more information.
 * @configstart{wiredtiger_open, see dist/api_data.py}
 * @config{async = (, asynchronous operations configuration options., a set of related configuration
 * options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, enable asynchronous operation.,
 * a boolean flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;ops_max, maximum number of
 * expected simultaneous asynchronous operations., an integer between 1 and 4096; default \c 1024.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;threads, the number of worker threads to service asynchronous
 * requests.  Each worker thread uses a session from the configured session_max., an integer between
 * 1 and 20; default \c 2.}
 * @config{ ),,}
 * @config{buffer_alignment, in-memory alignment (in bytes) for buffers used for I/O. The default
 * value of -1 indicates a platform-specific alignment value should be used (4KB on Linux systems
 * when direct I/O is configured\, zero elsewhere)., an integer between -1 and 1MB; default \c -1.}
 * @config{builtin_extension_config, A structure where the keys are the names of builtin extensions
 * and the values are passed to WT_CONNECTION::load_extension as the \c config parameter (for
 * example\, <code>builtin_extension_config={zlib={compression_level=3}}</code>)., a string; default
 * empty.}
 * @config{cache_cursors, enable caching of cursors for reuse.  This is the default value for any
 * sessions created\, and can be overridden in configuring \c cache_cursors in
 * WT_CONNECTION.open_session., a boolean flag; default \c true.}
 * @config{cache_max_wait_ms, the maximum number of milliseconds an application thread will wait for
 * space to be available in cache before giving up.  Default will wait forever., an integer greater
 * than or equal to 0; default \c 0.}
 * @config{cache_overflow = (, cache overflow configuration options., a set of related configuration
 * options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;file_max, The maximum number of bytes
 * that WiredTiger is allowed to use for its cache overflow mechanism.  If the cache overflow file
 * exceeds this size\, a panic will be triggered.  The default value means that the cache overflow
 * file is unbounded and may use as much space as the filesystem will accommodate.  The minimum
 * non-zero setting is 100MB., an integer greater than or equal to 0; default \c 0.}
 * @config{ ),,}
 * @config{cache_overhead, assume the heap allocator overhead is the specified percentage\, and
 * adjust the cache usage by that amount (for example\, if there is 10GB of data in cache\, a
 * percentage of 10 means WiredTiger treats this as 11GB). This value is configurable because
 * different heap allocators have different overhead and different workloads will have different
 * heap allocation sizes and patterns\, therefore applications may need to adjust this value based
 * on allocator choice and behavior in measured workloads., an integer between 0 and 30; default \c
 * 8.}
 * @config{cache_size, maximum heap memory to allocate for the cache.  A database should configure
 * either \c cache_size or \c shared_cache but not both., an integer between 1MB and 10TB; default
 * \c 100MB.}
 * @config{checkpoint = (, periodically checkpoint the database.  Enabling the checkpoint server
 * uses a session from the configured session_max., a set of related configuration options defined
 * below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;log_size, wait for this amount of log record bytes to be
 * written to the log between each checkpoint.  If non-zero\, this value will use a minimum of the
 * log file size.  A database can configure both log_size and wait to set an upper bound for
 * checkpoints; setting this value above 0 configures periodic checkpoints., an integer between 0
 * and 2GB; default \c 0.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;wait, seconds to wait between each
 * checkpoint; setting this value above 0 configures periodic checkpoints., an integer between 0 and
 * 100000; default \c 0.}
 * @config{ ),,}
 * @config{checkpoint_sync, flush files to stable storage when closing or writing checkpoints., a
 * boolean flag; default \c true.}
 * @config{compatibility = (, set compatibility version of database.  Changing the compatibility
 * version requires that there are no active operations for the duration of the call., a set of
 * related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;release,
 * compatibility release version string., a string; default empty.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
 * require_max, required maximum compatibility version of existing data files.  Must be greater than
 * or equal to any release version set in the \c release setting.  Has no effect if creating the
 * database., a string; default empty.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;require_min, required
 * minimum compatibility version of existing data files.  Must be less than or equal to any release
 * version set in the \c release setting.  Has no effect if creating the database., a string;
 * default empty.}
 * @config{ ),,}
 * @config{config_base, write the base configuration file if creating the database.  If \c false in
 * the config passed directly to ::wiredtiger_open\, will ignore any existing base configuration
 * file in addition to not creating one.  See @ref config_base for more information., a boolean
 * flag; default \c true.}
 * @config{create, create the database if it does not exist., a boolean flag; default \c false.}
 * @config{debug_mode = (, control the settings of various extended debugging features., a set of
 * related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
 * checkpoint_retention, adjust log archiving to retain the log records of this number of
 * checkpoints.  Zero or one means perform normal archiving., an integer between 0 and 1024; default
 * \c 0.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;cursor_copy, if true\, use the system allocator to make a
 * copy of any data returned by a cursor operation and return the copy instead.  The copy is freed
 * on the next cursor operation.  This allows memory sanitizers to detect inappropriate references
 * to memory owned by cursors., a boolean flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
 * eviction, if true\, modify internal algorithms to change skew to force history store eviction to
 * happen more aggressively.  This includes but is not limited to not skewing newest\, not favoring
 * leaf pages\, and modifying the eviction score mechanism., a boolean flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;log_retention, adjust log archiving to retain at least this
 * number of log files\, ignored if set to 0. (Warning: this option can remove log files required
 * for recovery if no checkpoints have yet been done and the number of log files exceeds the
 * configured value.  As WiredTiger cannot detect the difference between a system that has not yet
 * checkpointed and one that will never checkpoint\, it might discard log files before any
 * checkpoint is done.)., an integer between 0 and 1024; default \c 0.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;realloc_exact, if true\, reallocation of memory will only provide
 * the exact amount requested.  This will help with spotting memory allocation issues more easily.,
 * a boolean flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;rollback_error, return a
 * WT_ROLLBACK error from a transaction operation about every Nth operation to simulate a
 * collision., an integer between 0 and 10M; default \c 0.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
 * slow_checkpoint, if true\, slow down checkpoint creation by slowing down internal page
 * processing., a boolean flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;table_logging, if
 * true\, write transaction related information to the log for all operations\, even operations for
 * tables with logging turned off.  This setting introduces a log format change that may break older
 * versions of WiredTiger.  These operations are informational and skipped in recovery., a boolean
 * flag; default \c false.}
 * @config{ ),,}
 * @config{direct_io, Use \c O_DIRECT on POSIX systems\, and \c FILE_FLAG_NO_BUFFERING on Windows to
 * access files.  Options are given as a list\, such as <code>"direct_io=[data]"</code>. Configuring
 * \c direct_io requires care\, see @ref tuning_system_buffer_cache_direct_io for important
 * warnings.  Including \c "data" will cause WiredTiger data files to use direct I/O\, including \c
 * "log" will cause WiredTiger log files to use direct I/O\, and including \c "checkpoint" will
 * cause WiredTiger data files opened at a checkpoint (i.e: read-only) to use direct I/O. \c
 * direct_io should be combined with \c write_through to get the equivalent of \c O_DIRECT on
 * Windows., a list\, with values chosen from the following options: \c "checkpoint"\, \c "data"\,
 * \c "log"; default empty.}
 * @config{encryption = (, configure an encryptor for system wide metadata and logs.  If a system
 * wide encryptor is set\, it is also used for encrypting data files and tables\, unless encryption
 * configuration is explicitly set for them when they are created with WT_SESSION::create., a set of
 * related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;keyid, An
 * identifier that identifies a unique instance of the encryptor.  It is stored in clear text\, and
 * thus is available when the wiredtiger database is reopened.  On the first use of a (name\, keyid)
 * combination\, the WT_ENCRYPTOR::customize function is called with the keyid as an argument., a
 * string; default empty.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;name, Permitted values are \c "none" or
 * custom encryption engine name created with WT_CONNECTION::add_encryptor.  See @ref encryption for
 * more information., a string; default \c none.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;secretkey, A
 * string that is passed to the WT_ENCRYPTOR::customize function.  It is never stored in clear
 * text\, so must be given to any subsequent ::wiredtiger_open calls to reopen the database.  It
 * must also be provided to any "wt" commands used with this database., a string; default empty.}
 * @config{ ),,}
 * @config{error_prefix, prefix string for error messages., a string; default empty.}
 * @config{eviction = (, eviction configuration options., a set of related configuration options
 * defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;threads_max, maximum number of threads WiredTiger
 * will start to help evict pages from cache.  The number of threads started will vary depending on
 * the current eviction load.  Each eviction worker thread uses a session from the configured
 * session_max., an integer between 1 and 20; default \c 8.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;
 * threads_min, minimum number of threads WiredTiger will start to help evict pages from cache.  The
 * number of threads currently running will vary depending on the current eviction load., an integer
 * between 1 and 20; default \c 1.}
 * @config{ ),,}
 * @config{eviction_checkpoint_target, perform eviction at the beginning of checkpoints to bring the
 * dirty content in cache to this level.  It is a percentage of the cache size if the value is
 * within the range of 0 to 100 or an absolute size when greater than 100. The value is not allowed
 * to exceed the \c cache_size.  Ignored if set to zero or \c in_memory is \c true., an integer
 * between 0 and 10TB; default \c 1.}
 * @config{eviction_dirty_target, perform eviction in worker threads when the cache contains at
 * least this much dirty content.  It is a percentage of the cache size if the value is within the
 * range of 1 to 100 or an absolute size when greater than 100. The value is not allowed to exceed
 * the \c cache_size., an integer between 1 and 10TB; default \c 5.}
 * @config{eviction_dirty_trigger, trigger application threads to perform eviction when the cache
 * contains at least this much dirty content.  It is a percentage of the cache size if the value is
 * within the range of 1 to 100 or an absolute size when greater than 100. The value is not allowed
 * to exceed the \c cache_size.  This setting only alters behavior if it is lower than
 * eviction_trigger., an integer between 1 and 10TB; default \c 20.}
 * @config{eviction_target, perform eviction in worker threads when the cache contains at least this
 * much content.  It is a percentage of the cache size if the value is within the range of 10 to 100
 * or an absolute size when greater than 100. The value is not allowed to exceed the \c cache_size.,
 * an integer between 10 and 10TB; default \c 80.}
 * @config{eviction_trigger, trigger application threads to perform eviction when the cache contains
 * at least this much content.  It is a percentage of the cache size if the value is within the
 * range of 10 to 100 or an absolute size when greater than 100. The value is not allowed to exceed
 * the \c cache_size., an integer between 10 and 10TB; default \c 95.}
 * @config{eviction_updates_target, perform eviction in worker threads when the cache contains at
 * least this many bytes of updates.  It is a percentage of the cache size if the value is within
 * the range of 0 to 100 or an absolute size when greater than 100. Calculated as half of \c
 * eviction_dirty_target by default.  The value is not allowed to exceed the \c cache_size., an
 * integer between 0 and 10TB; default \c 0.}
 * @config{eviction_updates_trigger, trigger application threads to perform eviction when the cache
 * contains at least this many bytes of updates.  It is a percentage of the cache size if the value
 * is within the range of 1 to 100 or an absolute size when greater than 100. Calculated as half of
 * \c eviction_dirty_trigger by default.  The value is not allowed to exceed the \c cache_size.
 * This setting only alters behavior if it is lower than eviction_trigger., an integer between 0 and
 * 10TB; default \c 0.}
 * @config{exclusive, fail if the database already exists\, generally used with the \c create
 * option., a boolean flag; default \c false.}
 * @config{extensions, list of shared library extensions to load (using dlopen). Any values
 * specified to a library extension are passed to WT_CONNECTION::load_extension as the \c config
 * parameter (for example\, <code>extensions=(/path/ext.so={entry=my_entry})</code>)., a list of
 * strings; default empty.}
 * @config{file_close_sync, control whether to flush modified files to storage independent of a
 * global checkpoint when closing file handles to acquire exclusive access to a table.  If set to
 * false\, and logging is disabled\, API calls that require exclusive access to tables will return
 * EBUSY if there have been changes made to the table since the last global checkpoint.  When
 * logging is enabled\, the value for <code>file_close_sync</code> has no effect\, and\, modified
 * file is always flushed to storage when closing file handles to acquire exclusive access to the
 * table., a boolean flag; default \c true.}
 * @config{file_extend, file extension configuration.  If set\, extend files of the set type in
 * allocations of the set size\, instead of a block at a time as each new block is written.  For
 * example\, <code>file_extend=(data=16MB)</code>. If set to 0\, disable the file extension for the
 * set type.  For log files\, the allowed range is between 100KB and 2GB; values larger than the
 * configured maximum log size and the default config would extend log files in allocations of the
 * maximum log file size., a list\, with values chosen from the following options: \c "data"\, \c
 * "log"; default empty.}
 * @config{file_manager = (, control how file handles are managed., a set of related configuration
 * options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;close_handle_minimum, number of handles
 * open before the file manager will look for handles to close., an integer greater than or equal to
 * 0; default \c 250.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;close_idle_time, amount of time in seconds a
 * file handle needs to be idle before attempting to close it.  A setting of 0 means that idle
 * handles are not closed., an integer between 0 and 100000; default \c 30.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;close_scan_interval, interval in seconds at which to check for
 * files that are inactive and close them., an integer between 1 and 100000; default \c 10.}
 * @config{ ),,}
 * @config{history_store = (, history store configuration options., a set of related configuration
 * options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;file_max, The maximum number of bytes
 * that WiredTiger is allowed to use for its history store mechanism.  If the history store file
 * exceeds this size\, a panic will be triggered.  The default value means that the history store
 * file is unbounded and may use as much space as the filesystem will accommodate.  The minimum
 * non-zero setting is 100MB., an integer greater than or equal to 0; default \c 0.}
 * @config{ ),,}
 * @config{in_memory, keep data in-memory only.  See @ref in_memory for more information., a boolean
 * flag; default \c false.}
 * @config{io_capacity = (, control how many bytes per second are written and read.  Exceeding the
 * capacity results in throttling., a set of related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;total, number of bytes per second available to all subsystems in
 * total.  When set\, decisions about what subsystems are throttled\, and in what proportion\, are
 * made internally.  The minimum non-zero setting is 1MB., an integer between 0 and 1TB; default \c
 * 0.}
 * @config{ ),,}
 * @config{log = (, enable logging.  Enabling logging uses three sessions from the configured
 * session_max., a set of related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;archive, automatically archive unneeded log files., a boolean
 * flag; default \c true.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;compressor, configure a compressor for
 * log records.  Permitted values are \c "none" or custom compression engine name created with
 * WT_CONNECTION::add_compressor.  If WiredTiger has builtin support for \c "lz4"\, \c "snappy"\, \c
 * "zlib" or \c "zstd" compression\, these names are also available.  See @ref compression for more
 * information., a string; default \c none.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, enable logging
 * subsystem., a boolean flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;file_max, the
 * maximum size of log files., an integer between 100KB and 2GB; default \c 100MB.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;os_cache_dirty_pct, maximum dirty system buffer cache usage\, as
 * a percentage of the log's \c file_max.  If non-zero\, schedule writes for dirty blocks belonging
 * to the log in the system buffer cache after that percentage of the log has been written into the
 * buffer cache without an intervening file sync., an integer between 0 and 100; default \c 0.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;path, the name of a directory into which log files are written.
 * The directory must already exist.  If the value is not an absolute path\, the path is relative to
 * the database home (see @ref absolute_path for more information)., a string; default \c ".".}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;prealloc, pre-allocate log files., a boolean flag; default \c
 * true.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;recover, run recovery or error if recovery needs to run
 * after an unclean shutdown., a string\, chosen from the following options: \c "error"\, \c "on";
 * default \c on.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;zero_fill, manually write zeroes into log files.,
 * a boolean flag; default \c false.}
 * @config{ ),,}
 * @config{lsm_manager = (, configure database wide options for LSM tree management.  The LSM
 * manager is started automatically the first time an LSM tree is opened.  The LSM manager uses a
 * session from the configured session_max., a set of related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;merge, merge LSM chunks where possible., a boolean flag; default
 * \c true.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;worker_thread_max, Configure a set of threads to manage
 * merging LSM trees in the database.  Each worker thread uses a session handle from the configured
 * session_max., an integer between 3 and 20; default \c 4.}
 * @config{ ),,}
 * @config{mmap, Use memory mapping when accessing files in a read-only mode., a boolean flag;
 * default \c true.}
 * @config{mmap_all, Use memory mapping to read and write all data files\, may not be configured
 * with direct I/O., a boolean flag; default \c false.}
 * @config{multiprocess, permit sharing between processes (will automatically start an RPC server
 * for primary processes and use RPC for secondary processes). <b>Not yet supported in
 * WiredTiger</b>., a boolean flag; default \c false.}
 * @config{operation_timeout_ms, when non-zero\, a requested limit on the number of elapsed real
 * time milliseconds application threads will take to complete database operations.  Time is
 * measured from the start of each WiredTiger API call.  There is no guarantee any operation will
 * not take longer than this amount of time.  If WiredTiger notices the limit has been exceeded\, an
 * operation may return a WT_ROLLBACK error.  Default is to have no limit., an integer greater than
 * or equal to 1; default \c 0.}
 * @config{operation_tracking = (, enable tracking of performance-critical functions.  See @ref
 * operation_tracking for more information., a set of related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, enable operation tracking subsystem., a boolean flag;
 * default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;path, the name of a directory into which
 * operation tracking files are written.  The directory must already exist.  If the value is not an
 * absolute path\, the path is relative to the database home (see @ref absolute_path for more
 * information)., a string; default \c ".".}
 * @config{ ),,}
 * @config{readonly, open connection in read-only mode.  The database must exist.  All methods that
 * may modify a database are disabled.  See @ref readonly for more information., a boolean flag;
 * default \c false.}
 * @config{salvage, open connection and salvage any WiredTiger-owned database and log files that it
 * detects as corrupted.  This API should only be used after getting an error return of
 * WT_TRY_SALVAGE. Salvage rebuilds files in place\, overwriting existing files.  We recommend
 * making a backup copy of all files with the WiredTiger prefix prior to passing this flag., a
 * boolean flag; default \c false.}
 * @config{session_max, maximum expected number of sessions (including server threads)., an integer
 * greater than or equal to 1; default \c 100.}
 * @config{shared_cache = (, shared cache configuration options.  A database should configure either
 * a cache_size or a shared_cache not both.  Enabling a shared cache uses a session from the
 * configured session_max.  A shared cache can not have absolute values configured for cache
 * eviction settings., a set of related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;chunk, the granularity that a shared cache is redistributed., an
 * integer between 1MB and 10TB; default \c 10MB.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;name, the name of
 * a cache that is shared between databases or \c "none" when no shared cache is configured., a
 * string; default \c none.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;quota, maximum size of cache this
 * database can be allocated from the shared cache.  Defaults to the entire shared cache size., an
 * integer; default \c 0.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;reserve, amount of cache this database is
 * guaranteed to have available from the shared cache.  This setting is per database.  Defaults to
 * the chunk size., an integer; default \c 0.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;size, maximum memory
 * to allocate for the shared cache.  Setting this will update the value if one is already set., an
 * integer between 1MB and 10TB; default \c 500MB.}
 * @config{ ),,}
 * @config{statistics, Maintain database statistics\, which may impact performance.  Choosing "all"
 * maintains all statistics regardless of cost\, "fast" maintains a subset of statistics that are
 * relatively inexpensive\, "none" turns off all statistics.  The "clear" configuration resets
 * statistics after they are gathered\, where appropriate (for example\, a cache size statistic is
 * not cleared\, while the count of cursor insert operations will be cleared). When "clear" is
 * configured for the database\, gathered statistics are reset each time a statistics cursor is used
 * to gather statistics\, as well as each time statistics are logged using the \c statistics_log
 * configuration.  See @ref statistics for more information., a list\, with values chosen from the
 * following options: \c "all"\, \c "cache_walk"\, \c "fast"\, \c "none"\, \c "clear"\, \c
 * "tree_walk"; default \c none.}
 * @config{statistics_log = (, log any statistics the database is configured to maintain\, to a
 * file.  See @ref statistics for more information.  Enabling the statistics log server uses a
 * session from the configured session_max., a set of related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;json, encode statistics in JSON format., a boolean flag; default
 * \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;on_close, log statistics on database close., a boolean
 * flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;path, the name of a directory into which
 * statistics files are written.  The directory must already exist.  If the value is not an absolute
 * path\, the path is relative to the database home (see @ref absolute_path for more information).,
 * a string; default \c ".".}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;sources, if non-empty\, include
 * statistics for the list of data source URIs\, if they are open at the time of the statistics
 * logging.  The list may include URIs matching a single data source ("table:mytable")\, or a URI
 * matching all data sources of a particular type ("table:")., a list of strings; default empty.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;timestamp, a timestamp prepended to each log record\, may contain
 * strftime conversion specifications\, when \c json is configured\, defaults to \c "%FT%Y.000Z"., a
 * string; default \c "%b %d %H:%M:%S".}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;wait, seconds to wait
 * between each write of the log records; setting this value above 0 configures statistics logging.,
 * an integer between 0 and 100000; default \c 0.}
 * @config{ ),,}
 * @config{transaction_sync = (, how to sync log records when the transaction commits., a set of
 * related configuration options defined below.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;enabled, whether to
 * sync the log on every commit by default\, can be overridden by the \c sync setting to
 * WT_SESSION::commit_transaction., a boolean flag; default \c false.}
 * @config{&nbsp;&nbsp;&nbsp;&nbsp;method, the method used to ensure log records are stable on
 * disk\, see @ref tune_durability for more information., a string\, chosen from the following
 * options: \c "dsync"\, \c "fsync"\, \c "none"; default \c fsync.}
 * @config{ ),,}
 * @config{use_environment, use the \c WIREDTIGER_CONFIG and \c WIREDTIGER_HOME environment
 * variables if the process is not running with special privileges.  See @ref home for more
 * information., a boolean flag; default \c true.}
 * @config{use_environment_priv, use the \c WIREDTIGER_CONFIG and \c WIREDTIGER_HOME environment
 * variables even if the process is running with special privileges.  See @ref home for more
 * information., a boolean flag; default \c false.}
 * @config{verbose, enable messages for various events.  Options are given as a list\, such as
 * <code>"verbose=[evictserver\,read]"</code>., a list\, with values chosen from the following
 * options: \c "api"\, \c "backup"\, \c "block"\, \c "checkpoint"\, \c "checkpoint_cleanup"\, \c
 * "checkpoint_progress"\, \c "compact"\, \c "compact_progress"\, \c "error_returns"\, \c "evict"\,
 * \c "evict_stuck"\, \c "evictserver"\, \c "fileops"\, \c "handleops"\, \c "log"\, \c
 * "history_store"\, \c "history_store_activity"\, \c "lsm"\, \c "lsm_manager"\, \c "metadata"\, \c
 * "mutex"\, \c "overflow"\, \c "read"\, \c "rebalance"\, \c "reconcile"\, \c "recovery"\, \c
 * "recovery_progress"\, \c "rts"\, \c "salvage"\, \c "shared_cache"\, \c "split"\, \c "temporary"\,
 * \c "thread_group"\, \c "timestamp"\, \c "transaction"\, \c "verify"\, \c "version"\, \c "write";
 * default empty.}
 * @config{verify_metadata, open connection and verify any WiredTiger metadata.  This API allows
 * verification and detection of corruption in WiredTiger metadata., a boolean flag; default \c
 * false.}
 * @config{write_through, Use \c FILE_FLAG_WRITE_THROUGH on Windows to write to files.  Ignored on
 * non-Windows systems.  Options are given as a list\, such as <code>"write_through=[data]"</code>.
 * Configuring \c write_through requires care\, see @ref tuning_system_buffer_cache_direct_io for
 * important warnings.  Including \c "data" will cause WiredTiger data files to write through
 * cache\, including \c "log" will cause WiredTiger log files to write through cache.  \c
 * write_through should be combined with \c direct_io to get the equivalent of POSIX \c O_DIRECT on
 * Windows., a list\, with values chosen from the following options: \c "data"\, \c "log"; default
 * empty.}
 * @configend
 * Additionally, if files named \c WiredTiger.config or \c WiredTiger.basecfg
 * appear in the WiredTiger home directory, they are read for configuration
 * values (see @ref config_file and @ref config_base for details).
 * See @ref config_order for ordering of the configuration mechanisms.
 * @param[out] connectionp A pointer to the newly opened connection handle
 * @errors
 */
int wiredtiger_open(const char *home,
    WT_EVENT_HANDLER *event_handler, const char *config,
    WT_CONNECTION **connectionp) WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Return information about a WiredTiger error as a string (see
 * WT_SESSION::strerror for a thread-safe API).
 *
 * @snippet ex_all.c Display an error
 *
 * @param error a return value from a WiredTiger, ISO C, or POSIX standard API
 * @returns a string representation of the error
 */
const char *wiredtiger_strerror(int error) WT_ATTRIBUTE_LIBRARY_VISIBLE;

#if !defined(SWIG)
/*!
 * The interface implemented by applications to accept notifications
 * of the completion of asynchronous operations.
 *
 * Applications register their implementation with WiredTiger by calling
 * WT_CONNECTION::async_new_op.
 *
 * @snippet ex_async.c async handle allocation
 */
struct __wt_async_callback {
	/*!
	 * Callback to receive completion notification.
	 *
	 * @param[in] op the operation handle
	 * @param[in] op_ret the result of the async operation
	 * @param[in] flags currently unused
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet ex_async.c async example callback implementation
	 */
	int (*notify)(WT_ASYNC_CALLBACK *cb, WT_ASYNC_OP *op,
	    int op_ret, uint32_t flags);
};
#endif

/*!
 * The interface implemented by applications to handle error, informational and
 * progress messages.  Entries set to NULL are ignored and the default handlers
 * will continue to be used.
 */
struct __wt_event_handler {
	/*!
	 * Callback to handle error messages; by default, error messages are
	 * written to the stderr stream. See @ref event_message_handling for
	 * more information.
	 *
	 * Errors that require the application to exit and restart will have
	 * their \c error value set to \c WT_PANIC. The application can exit
	 * immediately when \c WT_PANIC is passed to an event handler, there
	 * is no reason to return into WiredTiger.
	 *
	 * Event handler returns are not ignored: if the handler returns
	 * non-zero, the error may cause the WiredTiger function posting the
	 * event to fail, and may even cause operation or library failure.
	 *
	 * @param session the WiredTiger session handle in use when the error
	 * was generated. The handle may have been created by the application
	 * or automatically by WiredTiger.
	 * @param error a return value from a WiredTiger, ISO C, or
	 * POSIX standard API, which can be converted to a string using
	 * WT_SESSION::strerror
	 * @param message an error string
	 */
	int (*handle_error)(WT_EVENT_HANDLER *handler,
	    WT_SESSION *session, int error, const char *message);

	/*!
	 * Callback to handle informational messages; by default, informational
	 * messages are written to the stdout stream. See
	 * @ref event_message_handling for more information.
	 *
	 * Message handler returns are not ignored: if the handler returns
	 * non-zero, the error may cause the WiredTiger function posting the
	 * event to fail, and may even cause operation or library failure.
	 *
	 * @param session the WiredTiger session handle in use when the message
	 * was generated. The handle may have been created by the application
	 * or automatically by WiredTiger.
	 * @param message an informational string
	 */
	int (*handle_message)(WT_EVENT_HANDLER *handler,
	    WT_SESSION *session, const char *message);

	/*!
	 * Callback to handle progress messages; by default, progress messages
	 * are not written. See @ref event_message_handling for more
	 * information.
	 *
	 * Progress handler returns are not ignored: if the handler returns
	 * non-zero, the error may cause the WiredTiger function posting the
	 * event to fail, and may even cause operation or library failure.
	 *
	 * @param session the WiredTiger session handle in use when the
	 * progress message was generated. The handle may have been created by
	 * the application or automatically by WiredTiger.
	 * @param operation a string representation of the operation
	 * @param progress a counter
	 */
	int (*handle_progress)(WT_EVENT_HANDLER *handler,
	    WT_SESSION *session, const char *operation, uint64_t progress);

	/*!
	 * Callback to handle automatic close of a WiredTiger handle.
	 *
	 * Close handler returns are not ignored: if the handler returns
	 * non-zero, the error may cause the WiredTiger function posting the
	 * event to fail, and may even cause operation or library failure.
	 *
	 * @param session The session handle that is being closed if the
	 * cursor parameter is NULL.
	 * @param cursor The cursor handle that is being closed, or NULL if
	 * it is a session handle being closed.
	 */
	int (*handle_close)(WT_EVENT_HANDLER *handler,
	    WT_SESSION *session, WT_CURSOR *cursor);
};

/*!
 * @name Data packing and unpacking
 * @{
 */

/*!
 * Pack a structure into a buffer.
 *
 * See @ref packing for a description of the permitted format strings.
 *
 * @section pack_examples Packing Examples
 *
 * For example, the string <code>"iSh"</code> will pack a 32-bit integer
 * followed by a NUL-terminated string, followed by a 16-bit integer.  The
 * default, big-endian encoding will be used, with no alignment.  This could be
 * used in C as follows:
 *
 * @snippet ex_all.c Pack fields into a buffer
 *
 * Then later, the values can be unpacked as follows:
 *
 * @snippet ex_all.c Unpack fields from a buffer
 *
 * @param session the session handle
 * @param buffer a pointer to a packed byte array
 * @param len the number of valid bytes in the buffer
 * @param format the data format, see @ref packing
 * @errors
 */
int wiredtiger_struct_pack(WT_SESSION *session,
    void *buffer, size_t len, const char *format, ...)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Calculate the size required to pack a structure.
 *
 * Note that for variable-sized fields including variable-sized strings and
 * integers, the calculated sized merely reflects the expected sizes specified
 * in the format string itself.
 *
 * @snippet ex_all.c Get the packed size
 *
 * @param session the session handle
 * @param lenp a location where the number of bytes needed for the
 * matching call to ::wiredtiger_struct_pack is returned
 * @param format the data format, see @ref packing
 * @errors
 */
int wiredtiger_struct_size(WT_SESSION *session,
    size_t *lenp, const char *format, ...) WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Unpack a structure from a buffer.
 *
 * Reverse of ::wiredtiger_struct_pack: gets values out of a
 * packed byte string.
 *
 * @snippet ex_all.c Unpack fields from a buffer
 *
 * @param session the session handle
 * @param buffer a pointer to a packed byte array
 * @param len the number of valid bytes in the buffer
 * @param format the data format, see @ref packing
 * @errors
 */
int wiredtiger_struct_unpack(WT_SESSION *session,
    const void *buffer, size_t len, const char *format, ...)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

#if !defined(SWIG)

/*!
 * Streaming interface to packing.
 *
 * This allows applications to pack or unpack records one field at a time.
 * This is an opaque handle returned by ::wiredtiger_pack_start or
 * ::wiredtiger_unpack_start.  It must be closed with ::wiredtiger_pack_close.
 */
typedef struct __wt_pack_stream WT_PACK_STREAM;

/*!
 * Start a packing operation into a buffer with the given format string.  This
 * should be followed by a series of calls to ::wiredtiger_pack_item,
 * ::wiredtiger_pack_int, ::wiredtiger_pack_str or ::wiredtiger_pack_uint
 * to fill in the values.
 *
 * @param session the session handle
 * @param format the data format, see @ref packing
 * @param buffer a pointer to memory to hold the packed data
 * @param size the size of the buffer
 * @param[out] psp the new packing stream handle
 * @errors
 */
int wiredtiger_pack_start(WT_SESSION *session,
    const char *format, void *buffer, size_t size, WT_PACK_STREAM **psp)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Start an unpacking operation from a buffer with the given format string.
 * This should be followed by a series of calls to ::wiredtiger_unpack_item,
 * ::wiredtiger_unpack_int, ::wiredtiger_unpack_str or ::wiredtiger_unpack_uint
 * to retrieve the packed values.
 *
 * @param session the session handle
 * @param format the data format, see @ref packing
 * @param buffer a pointer to memory holding the packed data
 * @param size the size of the buffer
 * @param[out] psp the new packing stream handle
 * @errors
 */
int wiredtiger_unpack_start(WT_SESSION *session,
    const char *format, const void *buffer, size_t size, WT_PACK_STREAM **psp)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Close a packing stream.
 *
 * @param ps the packing stream handle
 * @param[out] usedp the number of bytes in the buffer used by the stream
 * @errors
 */
int wiredtiger_pack_close(WT_PACK_STREAM *ps, size_t *usedp)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Pack an item into a packing stream.
 *
 * @param ps the packing stream handle
 * @param item an item to pack
 * @errors
 */
int wiredtiger_pack_item(WT_PACK_STREAM *ps, WT_ITEM *item)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Pack a signed integer into a packing stream.
 *
 * @param ps the packing stream handle
 * @param i a signed integer to pack
 * @errors
 */
int wiredtiger_pack_int(WT_PACK_STREAM *ps, int64_t i)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Pack a string into a packing stream.
 *
 * @param ps the packing stream handle
 * @param s a string to pack
 * @errors
 */
int wiredtiger_pack_str(WT_PACK_STREAM *ps, const char *s)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Pack an unsigned integer into a packing stream.
 *
 * @param ps the packing stream handle
 * @param u an unsigned integer to pack
 * @errors
 */
int wiredtiger_pack_uint(WT_PACK_STREAM *ps, uint64_t u)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Unpack an item from a packing stream.
 *
 * @param ps the packing stream handle
 * @param item an item to unpack
 * @errors
 */
int wiredtiger_unpack_item(WT_PACK_STREAM *ps, WT_ITEM *item)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Unpack a signed integer from a packing stream.
 *
 * @param ps the packing stream handle
 * @param[out] ip the unpacked signed integer
 * @errors
 */
int wiredtiger_unpack_int(WT_PACK_STREAM *ps, int64_t *ip)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Unpack a string from a packing stream.
 *
 * @param ps the packing stream handle
 * @param[out] sp the unpacked string
 * @errors
 */
int wiredtiger_unpack_str(WT_PACK_STREAM *ps, const char **sp)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Unpack an unsigned integer from a packing stream.
 *
 * @param ps the packing stream handle
 * @param[out] up the unpacked unsigned integer
 * @errors
 */
int wiredtiger_unpack_uint(WT_PACK_STREAM *ps, uint64_t *up)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;
/*! @} */

/*!
 * @name Configuration strings
 * @{
 */

/*!
 * The configuration information returned by the WiredTiger configuration
 * parsing functions in the WT_EXTENSION_API and the public API.
 */
struct __wt_config_item {
	/*!
	 * The value of a configuration string.
	 *
	 * Regardless of the type of the configuration string (boolean, int,
	 * list or string), the \c str field will reference the value of the
	 * configuration string.
	 *
	 * The bytes referenced by \c str are <b>not</b> nul-terminated,
	 * use the \c len field instead of a terminating nul byte.
	 */
	const char *str;

	/*! The number of bytes in the value referenced by \c str. */
	size_t len;

	/*!
	 * The numeric value of a configuration boolean or integer.
	 *
	 * If the configuration string's value is "true" or "false", the
	 * \c val field will be set to 1 (true), or 0 (false).
	 *
	 * If the configuration string can be legally interpreted as an integer,
	 * using the strtoll function rules as specified in ISO/IEC 9899:1990
	 * ("ISO C90"), that integer will be stored in the \c val field.
	 */
	int64_t val;

	/*! Permitted values of the \c type field. */
	enum {
		/*! A string value with quotes stripped. */
		WT_CONFIG_ITEM_STRING,
		/*! A boolean literal ("true" or "false"). */
		WT_CONFIG_ITEM_BOOL,
		/*! An unquoted identifier: a string value without quotes. */
		WT_CONFIG_ITEM_ID,
		/*! A numeric value. */
		WT_CONFIG_ITEM_NUM,
		/*! A nested structure or list, including brackets. */
		WT_CONFIG_ITEM_STRUCT
	}
	/*!
	 * The type of value determined by the parser.  In all cases,
	 * the \c str and \c len fields are set.
	 */
	type;
};

#if !defined(SWIG) && !defined(DOXYGEN)
/*!
 * Validate a configuration string for a WiredTiger API.
 * This API is outside the scope of a WiredTiger connection handle, since
 * applications may need to validate configuration strings prior to calling
 * ::wiredtiger_open.
 * @param session the session handle (may be \c NULL if the database not yet
 * opened).
 * @param event_handler An event handler (used if \c session is \c NULL; if both
 * \c session and \c event_handler are \c NULL, error messages will be written
 * to stderr).
 * @param name the WiredTiger function or method to validate.
 * @param config the configuration string being parsed.
 * @returns zero for success, non-zero to indicate an error.
 *
 * @snippet ex_all.c Validate a configuration string
 */
int wiredtiger_config_validate(WT_SESSION *session,
    WT_EVENT_HANDLER *event_handler, const char *name, const char *config)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;
#endif

/*!
 * Create a handle that can be used to parse or create configuration strings
 * compatible with WiredTiger APIs.
 * This API is outside the scope of a WiredTiger connection handle, since
 * applications may need to generate configuration strings prior to calling
 * ::wiredtiger_open.
 * @param session the session handle to be used for error reporting (if NULL,
 *	error messages will be written to stderr).
 * @param config the configuration string being parsed. The string must
 *	remain valid for the lifetime of the parser handle.
 * @param len the number of valid bytes in \c config
 * @param[out] config_parserp A pointer to the newly opened handle
 * @errors
 *
 * @snippet ex_config_parse.c Create a configuration parser
 */
int wiredtiger_config_parser_open(WT_SESSION *session,
    const char *config, size_t len, WT_CONFIG_PARSER **config_parserp)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * A handle that can be used to search and traverse configuration strings
 * compatible with WiredTiger APIs.
 * To parse the contents of a list or nested configuration string use a new
 * configuration parser handle based on the content of the ::WT_CONFIG_ITEM
 * retrieved from the parent configuration string.
 *
 * @section config_parse_examples Configuration String Parsing examples
 *
 * This could be used in C to create a configuration parser as follows:
 *
 * @snippet ex_config_parse.c Create a configuration parser
 *
 * Once the parser has been created the content can be queried directly:
 *
 * @snippet ex_config_parse.c get
 *
 * Or the content can be traversed linearly:
 *
 * @snippet ex_config_parse.c next
 *
 * Nested configuration values can be queried using a shorthand notation:
 *
 * @snippet ex_config_parse.c nested get
 *
 * Nested configuration values can be traversed using multiple
 * ::WT_CONFIG_PARSER handles:
 *
 * @snippet ex_config_parse.c nested traverse
 */
struct __wt_config_parser {

	/*!
	 * Close the configuration scanner releasing any resources.
	 *
	 * @param config_parser the configuration parser handle
	 * @errors
	 *
	 */
	int __F(close)(WT_CONFIG_PARSER *config_parser);

	/*!
	 * Return the next key/value pair.
	 *
	 * If an item has no explicitly assigned value, the item will be
	 * returned in \c key and the \c value will be set to the boolean
	 * \c "true" value.
	 *
	 * @param config_parser the configuration parser handle
	 * @param key the returned key
	 * @param value the returned value
	 * @errors
	 * When iteration would pass the end of the configuration string
	 * ::WT_NOTFOUND will be returned.
	 */
	int __F(next)(WT_CONFIG_PARSER *config_parser,
	    WT_CONFIG_ITEM *key, WT_CONFIG_ITEM *value);

	/*!
	 * Return the value of an item in the configuration string.
	 *
	 * @param config_parser the configuration parser handle
	 * @param key configuration key string
	 * @param value the returned value
	 * @errors
	 *
	 */
	int __F(get)(WT_CONFIG_PARSER *config_parser,
	    const char *key, WT_CONFIG_ITEM *value);
};

/*! @} */

/*!
 * @name Support functions
 * @anchor support_functions
 * @{
 */

/*!
 * Return a pointer to a function that calculates a CRC32C checksum.
 *
 * The WiredTiger library CRC32C checksum function uses hardware support where
 * available, else it falls back to a software implementation.
 *
 * @snippet ex_all.c Checksum a buffer
 *
 * @returns a pointer to a function that takes a buffer and length and returns
 * the CRC32C checksum
 */
uint32_t (*wiredtiger_crc32c_func(void))(const void *, size_t)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

#endif /* !defined(SWIG) */

/*!
 * Calculate a set of WT_MODIFY operations to represent an update.
 * This call will calculate a set of modifications to an old value that produce
 * the new value.  If more modifications are required than fit in the array
 * passed in by the caller, or if more bytes have changed than the \c maxdiff
 * parameter, the call will fail.  The matching algorithm is approximate, so it
 * may fail and return WT_NOTFOUND if a matching set of WT_MODIFY operations
 * is not found.
 *
 * The \c maxdiff parameter bounds how much work will be done searching for a
 * match: to ensure a match is found, it may need to be set larger than actual
 * number of bytes that differ between the old and new values.  In particular,
 * repeated patterns of bytes in the values can lead to suboptimal matching,
 * and matching ranges less than 64 bytes long will not be detected.
 *
 * If the call succeeds, the WT_MODIFY operations will point into \c newv,
 * which must remain valid until WT_CURSOR::modify is called.
 *
 * @snippet ex_all.c Calculate a modify operation
 *
 * @param session the current WiredTiger session (may be NULL)
 * @param oldv old value
 * @param newv new value
 * @param maxdiff maximum bytes difference
 * @param[out] entries array of modifications producing the new value
 * @param[in,out] nentriesp size of \c entries array passed in,
 *	set to the number of entries used
 * @errors
 */
int wiredtiger_calc_modify(WT_SESSION *session,
    const WT_ITEM *oldv, const WT_ITEM *newv,
    size_t maxdiff, WT_MODIFY *entries, int *nentriesp)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*!
 * Get version information.
 *
 * @snippet ex_all.c Get the WiredTiger library version #1
 * @snippet ex_all.c Get the WiredTiger library version #2
 *
 * @param majorp a location where the major version number is returned
 * @param minorp a location where the minor version number is returned
 * @param patchp a location where the patch version number is returned
 * @returns a string representation of the version
 */
const char *wiredtiger_version(int *majorp, int *minorp, int *patchp)
    WT_ATTRIBUTE_LIBRARY_VISIBLE;

/*! @} */

/*******************************************
 * Error returns
 *******************************************/
/*!
 * @name Error returns
 * Most functions and methods in WiredTiger return an integer code indicating
 * whether the operation succeeded or failed.  A return of zero indicates
 * success, all non-zero return values indicate some kind of failure.
 *
 * WiredTiger reserves all values from -31,800 to -31,999 as possible error
 * return values.  WiredTiger may also return C99/POSIX error codes such as
 * \c ENOMEM, \c EINVAL and \c ENOTSUP, with the usual meanings.
 *
 * The following are all of the WiredTiger-specific error returns:
 * @{
 */
/*
 * DO NOT EDIT: automatically built by dist/api_err.py.
 * Error return section: BEGIN
 */
/*!
 * Conflict between concurrent operations.
 * This error is generated when an operation cannot be completed due to a
 * conflict with concurrent operations.  The operation may be retried; if a
 * transaction is in progress, it should be rolled back and the operation
 * retried in a new transaction.
 */
#define	WT_ROLLBACK	(-31800)
/*!
 * Attempt to insert an existing key.
 * This error is generated when the application attempts to insert a record with
 * the same key as an existing record without the 'overwrite' configuration to
 * WT_SESSION::open_cursor.
 */
#define	WT_DUPLICATE_KEY	(-31801)
/*!
 * Non-specific WiredTiger error.
 * This error is returned when an error is not covered by a specific error
 * return.
 */
#define	WT_ERROR	(-31802)
/*!
 * Item not found.
 * This error indicates an operation did not find a value to return.  This
 * includes cursor search and other operations where no record matched the
 * cursor's search key such as WT_CURSOR::update or WT_CURSOR::remove.
 */
#define	WT_NOTFOUND	(-31803)
/*!
 * WiredTiger library panic.
 * This error indicates an underlying problem that requires a database restart.
 * The application may exit immediately, no further WiredTiger calls are
 * required (and further calls will themselves immediately fail).
 */
#define	WT_PANIC	(-31804)
/*! @cond internal */
/*! Restart the operation (internal). */
#define	WT_RESTART	(-31805)
/*! @endcond */
/*!
 * Recovery must be run to continue.
 * This error is generated when wiredtiger_open is configured to return an error
 * if recovery is required to use the database.
 */
#define	WT_RUN_RECOVERY	(-31806)
/*!
 * Operation would overflow cache.
 * This error is only generated when wiredtiger_open is configured to run in-
 * memory, and an insert or update operation requires more than the configured
 * cache size to complete. The operation may be retried; if a transaction is in
 * progress, it should be rolled back and the operation retried in a new
 * transaction.
 */
#define	WT_CACHE_FULL	(-31807)
/*!
 * Conflict with a prepared update.
 * This error is generated when the application attempts to update an already
 * updated record which is in prepared state. An updated record will be in
 * prepared state, when the transaction that performed the update is in prepared
 * state.
 */
#define	WT_PREPARE_CONFLICT	(-31808)
/*!
 * Database corruption detected.
 * This error is generated when corruption is detected in an on-disk file.
 * During normal operations, this may occur in rare circumstances as a result of
 * a system crash. The application may choose to salvage the file or retry
 * wiredtiger_open with the 'salvage=true' configuration setting.
 */
#define	WT_TRY_SALVAGE	(-31809)
/*
 * Error return section: END
 * DO NOT EDIT: automatically built by dist/api_err.py.
 */
/*! @} */

#ifndef DOXYGEN
#define	WT_DEADLOCK	WT_ROLLBACK		/* Backward compatibility */
#endif

/*! @} */

/*!
 * @defgroup wt_ext WiredTiger Extension API
 * The functions and interfaces applications use to customize and extend the
 * behavior of WiredTiger.
 * @{
 */

/*******************************************
 * Forward structure declarations for the extension API
 *******************************************/
struct __wt_config_arg;	typedef struct __wt_config_arg WT_CONFIG_ARG;

/*!
 * The interface implemented by applications to provide custom ordering of
 * records.
 *
 * Applications register their implementation with WiredTiger by calling
 * WT_CONNECTION::add_collator.  See @ref custom_collators for more
 * information.
 *
 * @snippet ex_extending.c add collator nocase
 *
 * @snippet ex_extending.c add collator prefix10
 */
struct __wt_collator {
	/*!
	 * Callback to compare keys.
	 *
	 * @param[out] cmp set to -1 if <code>key1 < key2</code>,
	 * 	0 if <code>key1 == key2</code>,
	 * 	1 if <code>key1 > key2</code>.
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet ex_all.c Implement WT_COLLATOR
	 *
	 * @snippet ex_extending.c case insensitive comparator
	 *
	 * @snippet ex_extending.c n character comparator
	 */
	int (*compare)(WT_COLLATOR *collator, WT_SESSION *session,
	    const WT_ITEM *key1, const WT_ITEM *key2, int *cmp);

	/*!
	 * If non-NULL, this callback is called to customize the collator
	 * for each data source.  If the callback returns a non-NULL
	 * collator, that instance is used instead of this one for all
	 * comparisons.
	 */
	int (*customize)(WT_COLLATOR *collator, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ITEM *passcfg, WT_COLLATOR **customp);

	/*!
	 * If non-NULL a callback performed when the data source is closed
	 * for customized extractors otherwise when the database is closed.
	 *
	 * The WT_COLLATOR::terminate callback is intended to allow cleanup,
	 * the handle will not be subsequently accessed by WiredTiger.
	 */
	int (*terminate)(WT_COLLATOR *collator, WT_SESSION *session);
};

/*!
 * The interface implemented by applications to provide custom compression.
 *
 * Compressors must implement the WT_COMPRESSOR interface: the
 * WT_COMPRESSOR::compress and WT_COMPRESSOR::decompress callbacks must be
 * specified, and WT_COMPRESSOR::pre_size is optional.  To build your own
 * compressor, use one of the compressors in \c ext/compressors as a template:
 * \c ext/nop_compress is a simple compressor that passes through data
 * unchanged, and is a reasonable starting point.
 *
 * Applications register their implementation with WiredTiger by calling
 * WT_CONNECTION::add_compressor.
 *
 * @snippet nop_compress.c WT_COMPRESSOR initialization structure
 * @snippet nop_compress.c WT_COMPRESSOR initialization function
 */
struct __wt_compressor {
	/*!
	 * Callback to compress a chunk of data.
	 *
	 * WT_COMPRESSOR::compress takes a source buffer and a destination
	 * buffer, by default of the same size.  If the callback can compress
	 * the buffer to a smaller size in the destination, it does so, sets
	 * the \c compression_failed return to 0 and returns 0.  If compression
	 * does not produce a smaller result, the callback sets the
	 * \c compression_failed return to 1 and returns 0. If another
	 * error occurs, it returns an errno or WiredTiger error code.
	 *
	 * On entry, \c src will point to memory, with the length of the memory
	 * in \c src_len.  After successful completion, the callback should
	 * return \c 0 and set \c result_lenp to the number of bytes required
	 * for the compressed representation.
	 *
	 * On entry, \c dst points to the destination buffer with a length
	 * of \c dst_len.  If the WT_COMPRESSOR::pre_size method is specified,
	 * the destination buffer will be at least the size returned by that
	 * method; otherwise, the destination buffer will be at least as large
	 * as the length of the data to compress.
	 *
	 * If compression would not shrink the data or the \c dst buffer is not
	 * large enough to hold the compressed data, the callback should set
	 * \c compression_failed to a non-zero value and return 0.
	 *
	 * @param[in] src the data to compress
	 * @param[in] src_len the length of the data to compress
	 * @param[in] dst the destination buffer
	 * @param[in] dst_len the length of the destination buffer
	 * @param[out] result_lenp the length of the compressed data
	 * @param[out] compression_failed non-zero if compression did not
	 * decrease the length of the data (compression may not have completed)
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet nop_compress.c WT_COMPRESSOR compress
	 */
	int (*compress)(WT_COMPRESSOR *compressor, WT_SESSION *session,
	    uint8_t *src, size_t src_len,
	    uint8_t *dst, size_t dst_len,
	    size_t *result_lenp, int *compression_failed);

	/*!
	 * Callback to decompress a chunk of data.
	 *
	 * WT_COMPRESSOR::decompress takes a source buffer and a destination
	 * buffer.  The contents are switched from \c compress: the
	 * source buffer is the compressed value, and the destination buffer is
	 * sized to be the original size.  If the callback successfully
	 * decompresses the source buffer to the destination buffer, it returns
	 * 0.  If an error occurs, it returns an errno or WiredTiger error code.
	 * The source buffer that WT_COMPRESSOR::decompress takes may have a
	 * size that is rounded up from the size originally produced by
	 * WT_COMPRESSOR::compress, with the remainder of the buffer set to
	 * zeroes. Most compressors do not care about this difference if the
	 * size to be decompressed can be implicitly discovered from the
	 * compressed data.  If your compressor cares, you may need to allocate
	 * space for, and store, the actual size in the compressed buffer.  See
	 * the source code for the included snappy compressor for an example.
	 *
	 * On entry, \c src will point to memory, with the length of the memory
	 * in \c src_len.  After successful completion, the callback should
	 * return \c 0 and set \c result_lenp to the number of bytes required
	 * for the decompressed representation.
	 *
	 * If the \c dst buffer is not big enough to hold the decompressed
	 * data, the callback should return an error.
	 *
	 * @param[in] src the data to decompress
	 * @param[in] src_len the length of the data to decompress
	 * @param[in] dst the destination buffer
	 * @param[in] dst_len the length of the destination buffer
	 * @param[out] result_lenp the length of the decompressed data
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet nop_compress.c WT_COMPRESSOR decompress
	 */
	int (*decompress)(WT_COMPRESSOR *compressor, WT_SESSION *session,
	    uint8_t *src, size_t src_len,
	    uint8_t *dst, size_t dst_len,
	    size_t *result_lenp);

	/*!
	 * Callback to size a destination buffer for compression
	 *
	 * WT_COMPRESSOR::pre_size is an optional callback that, given the
	 * source buffer and size, produces the size of the destination buffer
	 * to be given to WT_COMPRESSOR::compress.  This is useful for
	 * compressors that assume that the output buffer is sized for the
	 * worst case and thus no overrun checks are made.  If your compressor
	 * works like this, WT_COMPRESSOR::pre_size will need to be defined.
	 * See the source code for the snappy compressor for an example.
	 * However, if your compressor detects and avoids overruns against its
	 * target buffer, you will not need to define WT_COMPRESSOR::pre_size.
	 * When WT_COMPRESSOR::pre_size is set to NULL, the destination buffer
	 * is sized the same as the source buffer.  This is always sufficient,
	 * since a compression result that is larger than the source buffer is
	 * discarded by WiredTiger.
	 *
	 * If not NULL, this callback is called before each call to
	 * WT_COMPRESSOR::compress to determine the size of the destination
	 * buffer to provide.  If the callback is NULL, the destination
	 * buffer will be the same size as the source buffer.
	 *
	 * The callback should set \c result_lenp to a suitable buffer size
	 * for compression, typically the maximum length required by
	 * WT_COMPRESSOR::compress.
	 *
	 * This callback function is for compressors that require an output
	 * buffer larger than the source buffer (for example, that do not
	 * check for buffer overflow during compression).
	 *
	 * @param[in] src the data to compress
	 * @param[in] src_len the length of the data to compress
	 * @param[out] result_lenp the required destination buffer size
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet nop_compress.c WT_COMPRESSOR presize
	 */
	int (*pre_size)(WT_COMPRESSOR *compressor, WT_SESSION *session,
	    uint8_t *src, size_t src_len, size_t *result_lenp);

	/*!
	 * If non-NULL, a callback performed when the database is closed.
	 *
	 * The WT_COMPRESSOR::terminate callback is intended to allow cleanup,
	 * the handle will not be subsequently accessed by WiredTiger.
	 *
	 * @snippet nop_compress.c WT_COMPRESSOR terminate
	 */
	int (*terminate)(WT_COMPRESSOR *compressor, WT_SESSION *session);
};

/*!
 * Applications can extend WiredTiger by providing new implementations of the
 * WT_DATA_SOURCE class.  Each data source supports a different URI scheme for
 * data sources to WT_SESSION::create, WT_SESSION::open_cursor and related
 * methods.  See @ref custom_data_sources for more information.
 *
 * <b>Thread safety:</b> WiredTiger may invoke methods on the WT_DATA_SOURCE
 * interface from multiple threads concurrently.  It is the responsibility of
 * the implementation to protect any shared data.
 *
 * Applications register their implementation with WiredTiger by calling
 * WT_CONNECTION::add_data_source.
 *
 * @snippet ex_data_source.c WT_DATA_SOURCE register
 */
struct __wt_data_source {
	/*!
	 * Callback to alter an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE alter
	 */
	int (*alter)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to create a new object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE create
	 */
	int (*create)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to compact an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE compact
	 */
	int (*compact)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to drop an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE drop
	 */
	int (*drop)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to initialize a cursor.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE open_cursor
	 */
	int (*open_cursor)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config, WT_CURSOR **new_cursor);

	/*!
	 * Callback to rename an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE rename
	 */
	int (*rename)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, const char *newuri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to salvage an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE salvage
	 */
	int (*salvage)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to get the size of an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE size
	 */
	int (*size)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, wt_off_t *size);

	/*!
	 * Callback to truncate an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE truncate
	 */
	int (*truncate)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to truncate a range of an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE range truncate
	 */
	int (*range_truncate)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    WT_CURSOR *start, WT_CURSOR *stop);

	/*!
	 * Callback to verify an object.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE verify
	 */
	int (*verify)(WT_DATA_SOURCE *dsrc, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ARG *config);

	/*!
	 * Callback to checkpoint the database.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE checkpoint
	 */
	int (*checkpoint)(
	    WT_DATA_SOURCE *dsrc, WT_SESSION *session, WT_CONFIG_ARG *config);

	/*!
	 * If non-NULL, a callback performed when the database is closed.
	 *
	 * The WT_DATA_SOURCE::terminate callback is intended to allow cleanup,
	 * the handle will not be subsequently accessed by WiredTiger.
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE terminate
	 */
	int (*terminate)(WT_DATA_SOURCE *dsrc, WT_SESSION *session);

	/*!
	 * If non-NULL, a callback performed before an LSM merge.
	 *
	 * @param[in] source a cursor configured with the data being merged
	 * @param[in] dest a cursor on the new object being filled by the merge
	 *
	 * @snippet ex_data_source.c WT_DATA_SOURCE lsm_pre_merge
	 */
	int (*lsm_pre_merge)(
	    WT_DATA_SOURCE *dsrc, WT_CURSOR *source, WT_CURSOR *dest);
};

/*!
 * The interface implemented by applications to provide custom encryption.
 *
 * Encryptors must implement the WT_ENCRYPTOR interface: the
 * WT_ENCRYPTOR::encrypt, WT_ENCRYPTOR::decrypt and WT_ENCRYPTOR::sizing
 * callbacks must be specified, WT_ENCRYPTOR::customize and
 * WT_ENCRYPTOR::terminate are optional.  To build your own encryptor, use
 * one of the encryptors in \c ext/encryptors as a template:
 * \c ext/encryptors/nop_encrypt is a simple encryptor that passes through
 * data unchanged, and is a reasonable starting point;
 * \c ext/encryptors/rotn_encrypt is an encryptor implementing
 * a simple rotation cipher, it shows the use of \c keyid, \c secretkey,
 * and implements the WT_ENCRYPTOR::customize and
 * WT_ENCRYPTOR::terminate callbacks.
 *
 * Applications register their implementation with WiredTiger by calling
 * WT_CONNECTION::add_encryptor.
 *
 * @snippet nop_encrypt.c WT_ENCRYPTOR initialization structure
 * @snippet nop_encrypt.c WT_ENCRYPTOR initialization function
 */
struct __wt_encryptor {
	/*!
	 * Callback to encrypt a chunk of data.
	 *
	 * WT_ENCRYPTOR::encrypt takes a source buffer and a destination
	 * buffer.  The callback encrypts the source buffer (plain text)
	 * into the destination buffer.
	 *
	 * On entry, \c src will point to memory, with the length of the memory
	 * in \c src_len.  After successful completion, the callback should
	 * return \c 0 and set \c result_lenp to the number of bytes required
	 * for the encrypted representation.
	 *
	 * On entry, \c dst points to the destination buffer with a length
	 * of \c dst_len.  The destination buffer will be at least src_len
	 * plus the size returned by that WT_ENCRYPT::sizing.
	 *
	 * This callback cannot be NULL.
	 *
	 * @param[in] src the data to encrypt
	 * @param[in] src_len the length of the data to encrypt
	 * @param[in] dst the destination buffer
	 * @param[in] dst_len the length of the destination buffer
	 * @param[out] result_lenp the length of the encrypted data
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet nop_encrypt.c WT_ENCRYPTOR encrypt
	 */
	int (*encrypt)(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
	    uint8_t *src, size_t src_len,
	    uint8_t *dst, size_t dst_len,
	    size_t *result_lenp);

	/*!
	 * Callback to decrypt a chunk of data.
	 *
	 * WT_ENCRYPTOR::decrypt takes a source buffer and a destination
	 * buffer.  The contents are switched from \c encrypt: the
	 * source buffer is the encrypted value, and the destination buffer is
	 * sized to be the original size.  If the callback successfully
	 * decrypts the source buffer to the destination buffer, it returns
	 * 0.  If an error occurs, it returns an errno or WiredTiger error code.
	 *
	 * On entry, \c src will point to memory, with the length of the memory
	 * in \c src_len.  After successful completion, the callback should
	 * return \c 0 and set \c result_lenp to the number of bytes required
	 * for the decrypted representation.
	 *
	 * If the \c dst buffer is not big enough to hold the decrypted
	 * data, the callback should return an error.
	 *
	 * This callback cannot be NULL.
	 *
	 * @param[in] src the data to decrypt
	 * @param[in] src_len the length of the data to decrypt
	 * @param[in] dst the destination buffer
	 * @param[in] dst_len the length of the destination buffer
	 * @param[out] result_lenp the length of the decrypted data
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet nop_encrypt.c WT_ENCRYPTOR decrypt
	 */
	int (*decrypt)(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
	    uint8_t *src, size_t src_len,
	    uint8_t *dst, size_t dst_len,
	    size_t *result_lenp);

	/*!
	 * Callback to size a destination buffer for encryption.
	 *
	 * WT_ENCRYPTOR::sizing is an callback that returns the number
	 * of additional bytes that is needed when encrypting a
	 * text buffer.  This is always necessary, since encryptors
	 * typically generate encrypted text that is larger than the
	 * plain text input. Without such a call, WiredTiger would
	 * have no way to know the worst case for the encrypted buffer size.
	 * The WiredTiger encryption infrastructure assumes that
	 * buffer sizing is not dependent on the number of bytes
	 * of input, that there is a one to one relationship in number
	 * of bytes needed between input and output.
	 *
	 * This callback cannot be NULL.
	 *
	 * The callback should set \c expansion_constantp to the additional
	 * number of bytes needed.
	 *
	 * @param[out] expansion_constantp the additional number of bytes needed
	 *    when encrypting.
	 * @returns zero for success, non-zero to indicate an error.
	 *
	 * @snippet nop_encrypt.c WT_ENCRYPTOR sizing
	 */
	int (*sizing)(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
	    size_t *expansion_constantp);

	/*!
	 * If non-NULL, this callback is called to customize the encryptor.
	 * The customize function is called whenever a keyid is used for the
	 * first time with this encryptor, whether it be in
	 * the ::wiredtiger_open call or the WT_SESSION::create
	 * call. This gives the algorithm an
	 * opportunity to retrieve and save keys in a customized encryptor.
	 * If the callback returns a non-NULL encryptor, that instance
	 * is used instead of this one for any callbacks.
	 *
	 * @param[in] encrypt_config the "encryption" portion of the
	 *    configuration from the wiredtiger_open or WT_SESSION::create call
	 * @param[out] customp the new modified encryptor, or NULL.
	 * @returns zero for success, non-zero to indicate an error.
	 */
	int (*customize)(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
	    WT_CONFIG_ARG *encrypt_config, WT_ENCRYPTOR **customp);

	/*!
	 * If non-NULL, a callback performed when the database is closed.
	 * It is called for each encryptor that was added using
	 * WT_CONNECTION::add_encryptor or returned by the
	 * WT_ENCRYPTOR::customize callback.
	 *
	 * The WT_ENCRYPTOR::terminate callback is intended to allow cleanup,
	 * the handle will not be subsequently accessed by WiredTiger.
	 *
	 * @snippet nop_encrypt.c WT_ENCRYPTOR terminate
	 */
	int (*terminate)(WT_ENCRYPTOR *encryptor, WT_SESSION *session);
};

/*!
 * The interface implemented by applications to provide custom extraction of
 * index keys or column group values.
 *
 * Applications register implementations with WiredTiger by calling
 * WT_CONNECTION::add_extractor.  See @ref custom_extractors for more
 * information.
 *
 * @snippet ex_all.c WT_EXTRACTOR register
 */
struct __wt_extractor {
	/*!
	 * Callback to extract a value for an index or column group.
	 *
	 * @errors
	 *
	 * @snippet ex_all.c WT_EXTRACTOR
	 *
	 * @param extractor the WT_EXTRACTOR implementation
	 * @param session the current WiredTiger session
	 * @param key the table key in raw format, see @ref cursor_raw for
	 *	details
	 * @param value the table value in raw format, see @ref cursor_raw for
	 *	details
	 * @param[out] result_cursor the method should call WT_CURSOR::set_key
	 *	and WT_CURSOR::insert on this cursor to return a key.  The \c
	 *	key_format of the cursor will match that passed to
	 *	WT_SESSION::create for the index.  Multiple index keys can be
	 *	created for each record by calling WT_CURSOR::insert multiple
	 *	times.
	 */
	int (*extract)(WT_EXTRACTOR *extractor, WT_SESSION *session,
	    const WT_ITEM *key, const WT_ITEM *value,
	    WT_CURSOR *result_cursor);

	/*!
	 * If non-NULL, this callback is called to customize the extractor for
	 * each index.  If the callback returns a non-NULL extractor, that
	 * instance is used instead of this one for all comparisons.
	 */
	int (*customize)(WT_EXTRACTOR *extractor, WT_SESSION *session,
	    const char *uri, WT_CONFIG_ITEM *appcfg, WT_EXTRACTOR **customp);

	/*!
	 * If non-NULL a callback performed when the index or column group
	 * is closed for customized extractors otherwise when the database
	 * is closed.
	 *
	 * The WT_EXTRACTOR::terminate callback is intended to allow cleanup,
	 * the handle will not be subsequently accessed by WiredTiger.
	 */
	int (*terminate)(WT_EXTRACTOR *extractor, WT_SESSION *session);
};

#if !defined(SWIG)
/*! WT_FILE_SYSTEM::open_file file types */
typedef enum {
	WT_FS_OPEN_FILE_TYPE_CHECKPOINT,/*!< open a data file checkpoint */
	WT_FS_OPEN_FILE_TYPE_DATA,	/*!< open a data file */
	WT_FS_OPEN_FILE_TYPE_DIRECTORY,	/*!< open a directory */
	WT_FS_OPEN_FILE_TYPE_LOG,	/*!< open a log file */
	WT_FS_OPEN_FILE_TYPE_REGULAR	/*!< open a regular file */
} WT_FS_OPEN_FILE_TYPE;

#ifdef DOXYGEN
/*! WT_FILE_SYSTEM::open_file flags: random access pattern */
#define	WT_FS_OPEN_ACCESS_RAND	0x0
/*! WT_FILE_SYSTEM::open_file flags: sequential access pattern */
#define	WT_FS_OPEN_ACCESS_SEQ	0x0
/*! WT_FILE_SYSTEM::open_file flags: create if does not exist */
#define	WT_FS_OPEN_CREATE	0x0
/*! WT_FILE_SYSTEM::open_file flags: direct I/O requested */
#define	WT_FS_OPEN_DIRECTIO	0x0
/*! WT_FILE_SYSTEM::open_file flags: file creation must be durable */
#define	WT_FS_OPEN_DURABLE	0x0
/*!
 * WT_FILE_SYSTEM::open_file flags: return EBUSY if exclusive use not available
 */
#define	WT_FS_OPEN_EXCLUSIVE	0x0
/*! WT_FILE_SYSTEM::open_file flags: open is read-only */
#define	WT_FS_OPEN_READONLY	0x0

/*!
 * WT_FILE_SYSTEM::remove or WT_FILE_SYSTEM::rename flags: the remove or rename
 * operation must be durable
 */
#define	WT_FS_DURABLE		0x0
#else
/* AUTOMATIC FLAG VALUE GENERATION START */
#define	WT_FS_OPEN_ACCESS_RAND	0x01u
#define	WT_FS_OPEN_ACCESS_SEQ	0x02u
#define	WT_FS_OPEN_CREATE	0x04u
#define	WT_FS_OPEN_DIRECTIO	0x08u
#define	WT_FS_OPEN_DURABLE	0x10u
#define	WT_FS_OPEN_EXCLUSIVE	0x20u
#define	WT_FS_OPEN_FIXED	0x40u	/* Path not home relative (internal) */
#define	WT_FS_OPEN_READONLY	0x80u
/* AUTOMATIC FLAG VALUE GENERATION STOP */

/* AUTOMATIC FLAG VALUE GENERATION START */
#define	WT_FS_DURABLE		0x1u
/* AUTOMATIC FLAG VALUE GENERATION STOP */
#endif

/*!
 * The interface implemented by applications to provide a custom file system
 * implementation.
 *
 * <b>Thread safety:</b> WiredTiger may invoke methods on the WT_FILE_SYSTEM
 * interface from multiple threads concurrently. It is the responsibility of
 * the implementation to protect any shared data.
 *
 * Applications register implementations with WiredTiger by calling
 * WT_CONNECTION::add_file_system.  See @ref custom_file_systems for more
 * information.
 *
 * @snippet ex_file_system.c WT_FILE_SYSTEM register
 */
struct __wt_file_system {
	/*!
	 * Return a list of file names for the named directory.
	 *
	 * @errors
	 *
	 * @param file_system the WT_FILE_SYSTEM
	 * @param session the current WiredTiger session
	 * @param directory the name of the directory
	 * @param prefix if not NULL, only files with names matching the prefix
	 *    are returned
	 * @param[out] dirlist the method returns an allocated array of
	 *    individually allocated strings, one for each entry in the
	 *    directory.
	 * @param[out] countp the number of entries returned
	 */
	int (*fs_directory_list)(WT_FILE_SYSTEM *file_system,
	    WT_SESSION *session, const char *directory, const char *prefix,
	    char ***dirlist, uint32_t *countp);

#if !defined(DOXYGEN)
	/*
	 * Return a single file name for the named directory.
	 */
	int (*fs_directory_list_single)(WT_FILE_SYSTEM *file_system,
	    WT_SESSION *session, const char *directory, const char *prefix,
	    char ***dirlist, uint32_t *countp);
#endif

	/*!
	 * Free memory allocated by WT_FILE_SYSTEM::directory_list.
	 *
	 * @errors
	 *
	 * @param file_system the WT_FILE_SYSTEM
	 * @param session the current WiredTiger session
	 * @param dirlist array returned by WT_FILE_SYSTEM::directory_list
	 * @param count count returned by WT_FILE_SYSTEM::directory_list
	 */
	int (*fs_directory_list_free)(WT_FILE_SYSTEM *file_system,
	    WT_SESSION *session, char **dirlist, uint32_t count);

	/*!
	 * Return if the named file system object exists.
	 *
	 * @errors
	 *
	 * @param file_system the WT_FILE_SYSTEM
	 * @param session the current WiredTiger session
	 * @param name the name of the file
	 * @param[out] existp If the named file system object exists
	 */
	int (*fs_exist)(WT_FILE_SYSTEM *file_system,
	    WT_SESSION *session, const char *name, bool *existp);

	/*!
	 * Open a handle for a named file system object
	 *
	 * The method should return ENOENT if the file is not being created and
	 * does not exist.
	 *
	 * The method should return EACCES if the file cannot be opened in the
	 * requested mode (for example, a file opened for writing in a readonly
	 * file system).
	 *
	 * The method should return EBUSY if ::WT_FS_OPEN_EXCLUSIVE is set and
	 * the file is in use.
	 *
	 * @errors
	 *
	 * @param file_system the WT_FILE_SYSTEM
	 * @param session the current WiredTiger session
	 * @param name the name of the file system object
	 * @param file_type the type of the file
	 *    The file type is provided to allow optimization for different file
	 *    access patterns.
	 * @param flags flags indicating how to open the file, one or more of
	 *    ::WT_FS_OPEN_CREATE, ::WT_FS_OPEN_DIRECTIO, ::WT_FS_OPEN_DURABLE,
	 *    ::WT_FS_OPEN_EXCLUSIVE or ::WT_FS_OPEN_READONLY.
	 * @param[out] file_handlep the handle to the newly opened file. File
	 *    system implementations must allocate memory for the handle and
	 *    the WT_FILE_HANDLE::name field, and fill in the WT_FILE_HANDLE::
	 *    fields. Applications wanting to associate private information
	 *    with the WT_FILE_HANDLE:: structure should declare and allocate
	 *    their own structure as a superset of a WT_FILE_HANDLE:: structure.
	 */
	int (*fs_open_file)(WT_FILE_SYSTEM *file_system, WT_SESSION *session,
	    const char *name, WT_FS_OPEN_FILE_TYPE file_type, uint32_t flags,
	    WT_FILE_HANDLE **file_handlep);

	/*!
	 * Remove a named file system object
	 *
	 * This method is not required for readonly file systems and should be
	 * set to NULL when not required by the file system.
	 *
	 * @errors
	 *
	 * @param file_system the WT_FILE_SYSTEM
	 * @param session the current WiredTiger session
	 * @param name the name of the file system object
	 * @param durable if the operation requires durability
	 * @param flags 0 or ::WT_FS_DURABLE
	 */
	int (*fs_remove)(WT_FILE_SYSTEM *file_system,
	    WT_SESSION *session, const char *name, uint32_t flags);

	/*!
	 * Rename a named file system object
	 *
	 * This method is not required for readonly file systems and should be
	 * set to NULL when not required by the file system.
	 *
	 * @errors
	 *
	 * @param file_system the WT_FILE_SYSTEM
	 * @param session the current WiredTiger session
	 * @param from the original name of the object
	 * @param to the new name for the object
	 * @param flags 0 or ::WT_FS_DURABLE
	 */
	int (*fs_rename)(WT_FILE_SYSTEM *file_system, WT_SESSION *session,
	    const char *from, const char *to, uint32_t flags);

	/*!
	 * Return the size of a named file system object
	 *
	 * @errors
	 *
	 * @param file_system the WT_FILE_SYSTEM
	 * @param session the current WiredTiger session
	 * @param name the name of the file system object
	 * @param[out] sizep the size of the file system entry
	 */
	int (*fs_size)(WT_FILE_SYSTEM *file_system,
	    WT_SESSION *session, const char *name, wt_off_t *sizep);

	/*!
	 * A callback performed when the file system is closed and will no
	 * longer be accessed by the WiredTiger database.
	 *
	 * This method is not required and should be set to NULL when not
	 * required by the file system.
	 *
	 * The WT_FILE_SYSTEM::terminate callback is intended to allow cleanup,
	 * the handle will not be subsequently accessed by WiredTiger.
	 */
	int (*terminate)(WT_FILE_SYSTEM *file_system, WT_SESSION *session);
};

/*! WT_FILE_HANDLE::fadvise flags: no longer need */
#define	WT_FILE_HANDLE_DONTNEED	1
/*! WT_FILE_HANDLE::fadvise flags: will need */
#define	WT_FILE_HANDLE_WILLNEED	2

/*!
 * A file handle implementation returned by WT_FILE_SYSTEM::open_file.
 *
 * <b>Thread safety:</b> Unless explicitly stated otherwise, WiredTiger may
 * invoke methods on the WT_FILE_HANDLE interface from multiple threads
 * concurrently. It is the responsibility of the implementation to protect
 * any shared data.
 *
 * See @ref custom_file_systems for more information.
 */
struct __wt_file_handle {
	/*!
	 * The enclosing file system, set by WT_FILE_SYSTEM::open_file.
	 */
	WT_FILE_SYSTEM *file_system;

	/*!
	 * The name of the file, set by WT_FILE_SYSTEM::open_file.
	 */
	char *name;

	/*!
	 * Close a file handle, the handle will not be further accessed by
	 * WiredTiger.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 */
	int (*close)(WT_FILE_HANDLE *file_handle, WT_SESSION *session);

	/*!
	 * Indicate expected future use of file ranges, based on the POSIX
	 * 1003.1 standard fadvise.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param offset the file offset
	 * @param len the size of the advisory
	 * @param advice one of ::WT_FILE_HANDLE_WILLNEED or
	 *    ::WT_FILE_HANDLE_DONTNEED.
	 */
	int (*fh_advise)(WT_FILE_HANDLE *file_handle,
	    WT_SESSION *session, wt_off_t offset, wt_off_t len, int advice);

	/*!
	 * Extend the file.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * Any allocated disk space must read as 0 bytes, and no existing file
	 * data may change. Allocating all necessary underlying storage (not
	 * changing just the file's metadata), is likely to result in increased
	 * performance.
	 *
	 * This method is not called by multiple threads concurrently (on the
	 * same file handle). If the file handle's extension method supports
	 * concurrent calls, set the WT_FILE_HANDLE::fh_extend_nolock method
	 * instead. See @ref custom_file_systems for more information.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param offset desired file size after extension
	 */
	int (*fh_extend)(
	    WT_FILE_HANDLE *file_handle, WT_SESSION *session, wt_off_t offset);

	/*!
	 * Extend the file.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * Any allocated disk space must read as 0 bytes, and no existing file
	 * data may change. Allocating all necessary underlying storage (not
	 * only changing the file's metadata), is likely to result in increased
	 * performance.
	 *
	 * This method may be called by multiple threads concurrently (on the
	 * same file handle). If the file handle's extension method does not
	 * support concurrent calls, set the WT_FILE_HANDLE::fh_extend method
	 * instead. See @ref custom_file_systems for more information.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param offset desired file size after extension
	 */
	int (*fh_extend_nolock)(
	    WT_FILE_HANDLE *file_handle, WT_SESSION *session, wt_off_t offset);

	/*!
	 * Lock/unlock a file from the perspective of other processes running
	 * in the system, where necessary.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param lock whether to lock or unlock
	 */
	int (*fh_lock)(
	    WT_FILE_HANDLE *file_handle, WT_SESSION *session, bool lock);

	/*!
	 * Map a file into memory, based on the POSIX 1003.1 standard mmap.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param[out] mapped_regionp a reference to a memory location into
	 *    which should be stored a pointer to the start of the mapped region
	 * @param[out] lengthp a reference to a memory location into which
	 *    should be stored the length of the region
	 * @param[out] mapped_cookiep a reference to a memory location into
	 *    which can be optionally stored a pointer to an opaque cookie
	 *    which is subsequently passed to WT_FILE_HANDLE::unmap.
	 */
	int (*fh_map)(WT_FILE_HANDLE *file_handle, WT_SESSION *session,
	    void *mapped_regionp, size_t *lengthp, void *mapped_cookiep);

	/*!
	 * Unmap part of a memory mapped file, based on the POSIX 1003.1
	 * standard madvise.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param map a location in the mapped region unlikely to be used in the
	 *    near future
	 * @param length the length of the mapped region to discard
	 * @param mapped_cookie any cookie set by the WT_FILE_HANDLE::map method
	 */
	int (*fh_map_discard)(WT_FILE_HANDLE *file_handle,
	    WT_SESSION *session, void *map, size_t length, void *mapped_cookie);

	/*!
	 * Preload part of a memory mapped file, based on the POSIX 1003.1
	 * standard madvise.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param map a location in the mapped region likely to be used in the
	 *    near future
	 * @param length the size of the mapped region to preload
	 * @param mapped_cookie any cookie set by the WT_FILE_HANDLE::map method
	 */
	int (*fh_map_preload)(WT_FILE_HANDLE *file_handle, WT_SESSION *session,
	    const void *map, size_t length, void *mapped_cookie);

	/*!
	 * Unmap a memory mapped file, based on the POSIX 1003.1 standard
	 * munmap.
	 *
	 * This method is only required if a valid implementation of map is
	 * provided by the file, and should be set to NULL otherwise.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param mapped_region a pointer to the start of the mapped region
	 * @param length the length of the mapped region
	 * @param mapped_cookie any cookie set by the WT_FILE_HANDLE::map method
	 */
	int (*fh_unmap)(WT_FILE_HANDLE *file_handle, WT_SESSION *session,
	    void *mapped_region, size_t length, void *mapped_cookie);

	/*!
	 * Read from a file, based on the POSIX 1003.1 standard pread.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param offset the offset in the file to start reading from
	 * @param len the amount to read
	 * @param[out] buf buffer to hold the content read from file
	 */
	int (*fh_read)(WT_FILE_HANDLE *file_handle,
	    WT_SESSION *session, wt_off_t offset, size_t len, void *buf);

	/*!
	 * Return the size of a file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param sizep the size of the file
	 */
	int (*fh_size)(
	    WT_FILE_HANDLE *file_handle, WT_SESSION *session, wt_off_t *sizep);

	/*!
	 * Make outstanding file writes durable and do not return until writes
	 * are complete.
	 *
	 * This method is not required for read-only files, and should be set
	 * to NULL when not supported by the file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 */
	int (*fh_sync)(WT_FILE_HANDLE *file_handle, WT_SESSION *session);

	/*!
	 * Schedule the outstanding file writes required for durability and
	 * return immediately.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 */
	int (*fh_sync_nowait)(WT_FILE_HANDLE *file_handle, WT_SESSION *session);

	/*!
	 * Truncate the file.
	 *
	 * This method is not required, and should be set to NULL when not
	 * supported by the file.
	 *
	 * This method is not called by multiple threads concurrently (on the
	 * same file handle).
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param offset desired file size after truncate
	 */
	int (*fh_truncate)(
	    WT_FILE_HANDLE *file_handle, WT_SESSION *session, wt_off_t offset);

	/*!
	 * Write to a file, based on the POSIX 1003.1 standard pwrite.
	 *
	 * This method is not required for read-only files, and should be set
	 * to NULL when not supported by the file.
	 *
	 * @errors
	 *
	 * @param file_handle the WT_FILE_HANDLE
	 * @param session the current WiredTiger session
	 * @param offset offset at which to start writing
	 * @param length amount of data to write
	 * @param buf content to be written to the file
	 */
	int (*fh_write)(WT_FILE_HANDLE *file_handle, WT_SESSION *session,
	    wt_off_t offset, size_t length, const void *buf);
};
#endif /* !defined(SWIG) */

/*!
 * Entry point to an extension, called when the extension is loaded.
 *
 * @param connection the connection handle
 * @param config the config information passed to WT_CONNECTION::load_extension
 * @errors
 */
extern int wiredtiger_extension_init(
    WT_CONNECTION *connection, WT_CONFIG_ARG *config);

/*!
 * Optional cleanup function for an extension, called during
 * WT_CONNECTION::close.
 *
 * @param connection the connection handle
 * @errors
 */
extern int wiredtiger_extension_terminate(WT_CONNECTION *connection);

/*! @} */

/*!
 * @addtogroup wt
 * @{
 */
/*!
 * @name Incremental backup types
 * @anchor backup_types
 * @{
 */
/*! invalid type */
#define WT_BACKUP_INVALID	0
/*! whole file */
#define WT_BACKUP_FILE		1
/*! file range */
#define WT_BACKUP_RANGE		2
/*! @} */

/*!
 * @name Log record and operation types
 * @anchor log_types
 * @{
 */
/*
 * NOTE:  The values of these record types and operations must
 * never change because they're written into the log.  Append
 * any new records or operations to the appropriate set.
 */
/*! checkpoint */
#define	WT_LOGREC_CHECKPOINT	0
/*! transaction commit */
#define	WT_LOGREC_COMMIT	1
/*! file sync */
#define	WT_LOGREC_FILE_SYNC	2
/*! message */
#define	WT_LOGREC_MESSAGE	3
/*! system/internal record */
#define	WT_LOGREC_SYSTEM	4
/*! invalid operation */
#define	WT_LOGOP_INVALID	0
/*! column-store put */
#define	WT_LOGOP_COL_PUT	1
/*! column-store remove */
#define	WT_LOGOP_COL_REMOVE	2
/*! column-store truncate */
#define	WT_LOGOP_COL_TRUNCATE	3
/*! row-store put */
#define	WT_LOGOP_ROW_PUT	4
/*! row-store remove */
#define	WT_LOGOP_ROW_REMOVE	5
/*! row-store truncate */
#define	WT_LOGOP_ROW_TRUNCATE	6
/*! checkpoint start */
#define	WT_LOGOP_CHECKPOINT_START	7
/*! previous LSN */
#define	WT_LOGOP_PREV_LSN	8
/*! column-store modify */
#define	WT_LOGOP_COL_MODIFY	9
/*! row-store modify */
#define	WT_LOGOP_ROW_MODIFY	10
/*
 * NOTE: Diagnostic-only log operations should have values in
 * the ignore range.
 */
/*! Diagnostic: transaction timestamps */
#define	WT_LOGOP_TXN_TIMESTAMP	(WT_LOGOP_IGNORE | 11)
/*! @} */

/*******************************************
 * Statistic reference.
 *******************************************/
/*
 * DO NOT EDIT: automatically built by dist/stat.py.
 * Statistics section: BEGIN
 */

/*!
 * @name Connection statistics
 * @anchor statistics_keys
 * @anchor statistics_conn
 * Statistics are accessed through cursors with \c "statistics:" URIs.
 * Individual statistics can be queried through the cursor using the following
 * keys.  See @ref data_statistics for more information.
 * @{
 */
/*! LSM: application work units currently queued */
#define	WT_STAT_CONN_LSM_WORK_QUEUE_APP			1000
/*! LSM: merge work units currently queued */
#define	WT_STAT_CONN_LSM_WORK_QUEUE_MANAGER		1001
/*! LSM: rows merged in an LSM tree */
#define	WT_STAT_CONN_LSM_ROWS_MERGED			1002
/*! LSM: sleep for LSM checkpoint throttle */
#define	WT_STAT_CONN_LSM_CHECKPOINT_THROTTLE		1003
/*! LSM: sleep for LSM merge throttle */
#define	WT_STAT_CONN_LSM_MERGE_THROTTLE			1004
/*! LSM: switch work units currently queued */
#define	WT_STAT_CONN_LSM_WORK_QUEUE_SWITCH		1005
/*! LSM: tree maintenance operations discarded */
#define	WT_STAT_CONN_LSM_WORK_UNITS_DISCARDED		1006
/*! LSM: tree maintenance operations executed */
#define	WT_STAT_CONN_LSM_WORK_UNITS_DONE		1007
/*! LSM: tree maintenance operations scheduled */
#define	WT_STAT_CONN_LSM_WORK_UNITS_CREATED		1008
/*! LSM: tree queue hit maximum */
#define	WT_STAT_CONN_LSM_WORK_QUEUE_MAX			1009
/*! async: current work queue length */
#define	WT_STAT_CONN_ASYNC_CUR_QUEUE			1010
/*! async: maximum work queue length */
#define	WT_STAT_CONN_ASYNC_MAX_QUEUE			1011
/*! async: number of allocation state races */
#define	WT_STAT_CONN_ASYNC_ALLOC_RACE			1012
/*! async: number of flush calls */
#define	WT_STAT_CONN_ASYNC_FLUSH			1013
/*! async: number of operation slots viewed for allocation */
#define	WT_STAT_CONN_ASYNC_ALLOC_VIEW			1014
/*! async: number of times operation allocation failed */
#define	WT_STAT_CONN_ASYNC_FULL				1015
/*! async: number of times worker found no work */
#define	WT_STAT_CONN_ASYNC_NOWORK			1016
/*! async: total allocations */
#define	WT_STAT_CONN_ASYNC_OP_ALLOC			1017
/*! async: total compact calls */
#define	WT_STAT_CONN_ASYNC_OP_COMPACT			1018
/*! async: total insert calls */
#define	WT_STAT_CONN_ASYNC_OP_INSERT			1019
/*! async: total remove calls */
#define	WT_STAT_CONN_ASYNC_OP_REMOVE			1020
/*! async: total search calls */
#define	WT_STAT_CONN_ASYNC_OP_SEARCH			1021
/*! async: total update calls */
#define	WT_STAT_CONN_ASYNC_OP_UPDATE			1022
/*! block-manager: blocks pre-loaded */
#define	WT_STAT_CONN_BLOCK_PRELOAD			1023
/*! block-manager: blocks read */
#define	WT_STAT_CONN_BLOCK_READ				1024
/*! block-manager: blocks written */
#define	WT_STAT_CONN_BLOCK_WRITE			1025
/*! block-manager: bytes read */
#define	WT_STAT_CONN_BLOCK_BYTE_READ			1026
/*! block-manager: bytes read via memory map API */
#define	WT_STAT_CONN_BLOCK_BYTE_READ_MMAP		1027
/*! block-manager: bytes read via system call API */
#define	WT_STAT_CONN_BLOCK_BYTE_READ_SYSCALL		1028
/*! block-manager: bytes written */
#define	WT_STAT_CONN_BLOCK_BYTE_WRITE			1029
/*! block-manager: bytes written for checkpoint */
#define	WT_STAT_CONN_BLOCK_BYTE_WRITE_CHECKPOINT	1030
/*! block-manager: bytes written via memory map API */
#define	WT_STAT_CONN_BLOCK_BYTE_WRITE_MMAP		1031
/*! block-manager: bytes written via system call API */
#define	WT_STAT_CONN_BLOCK_BYTE_WRITE_SYSCALL		1032
/*! block-manager: mapped blocks read */
#define	WT_STAT_CONN_BLOCK_MAP_READ			1033
/*! block-manager: mapped bytes read */
#define	WT_STAT_CONN_BLOCK_BYTE_MAP_READ		1034
/*!
 * block-manager: number of times the file was remapped because it
 * changed size via fallocate or truncate
 */
#define	WT_STAT_CONN_BLOCK_REMAP_FILE_RESIZE		1035
/*! block-manager: number of times the region was remapped via write */
#define	WT_STAT_CONN_BLOCK_REMAP_FILE_WRITE		1036
/*! cache: application threads page read from disk to cache count */
#define	WT_STAT_CONN_CACHE_READ_APP_COUNT		1037
/*! cache: application threads page read from disk to cache time (usecs) */
#define	WT_STAT_CONN_CACHE_READ_APP_TIME		1038
/*! cache: application threads page write from cache to disk count */
#define	WT_STAT_CONN_CACHE_WRITE_APP_COUNT		1039
/*! cache: application threads page write from cache to disk time (usecs) */
#define	WT_STAT_CONN_CACHE_WRITE_APP_TIME		1040
/*! cache: bytes allocated for updates */
#define	WT_STAT_CONN_CACHE_BYTES_UPDATES		1041
/*! cache: bytes belonging to page images in the cache */
#define	WT_STAT_CONN_CACHE_BYTES_IMAGE			1042
/*! cache: bytes belonging to the history store table in the cache */
#define	WT_STAT_CONN_CACHE_BYTES_HS			1043
/*! cache: bytes currently in the cache */
#define	WT_STAT_CONN_CACHE_BYTES_INUSE			1044
/*! cache: bytes dirty in the cache cumulative */
#define	WT_STAT_CONN_CACHE_BYTES_DIRTY_TOTAL		1045
/*! cache: bytes not belonging to page images in the cache */
#define	WT_STAT_CONN_CACHE_BYTES_OTHER			1046
/*! cache: bytes read into cache */
#define	WT_STAT_CONN_CACHE_BYTES_READ			1047
/*! cache: bytes written from cache */
#define	WT_STAT_CONN_CACHE_BYTES_WRITE			1048
/*! cache: cache overflow score */
#define	WT_STAT_CONN_CACHE_LOOKASIDE_SCORE		1049
/*! cache: checkpoint blocked page eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_CHECKPOINT		1050
/*! cache: eviction calls to get a page */
#define	WT_STAT_CONN_CACHE_EVICTION_GET_REF		1051
/*! cache: eviction calls to get a page found queue empty */
#define	WT_STAT_CONN_CACHE_EVICTION_GET_REF_EMPTY	1052
/*! cache: eviction calls to get a page found queue empty after locking */
#define	WT_STAT_CONN_CACHE_EVICTION_GET_REF_EMPTY2	1053
/*! cache: eviction currently operating in aggressive mode */
#define	WT_STAT_CONN_CACHE_EVICTION_AGGRESSIVE_SET	1054
/*! cache: eviction empty score */
#define	WT_STAT_CONN_CACHE_EVICTION_EMPTY_SCORE		1055
/*! cache: eviction passes of a file */
#define	WT_STAT_CONN_CACHE_EVICTION_WALK_PASSES		1056
/*! cache: eviction server candidate queue empty when topping up */
#define	WT_STAT_CONN_CACHE_EVICTION_QUEUE_EMPTY		1057
/*! cache: eviction server candidate queue not empty when topping up */
#define	WT_STAT_CONN_CACHE_EVICTION_QUEUE_NOT_EMPTY	1058
/*! cache: eviction server evicting pages */
#define	WT_STAT_CONN_CACHE_EVICTION_SERVER_EVICTING	1059
/*!
 * cache: eviction server slept, because we did not make progress with
 * eviction
 */
#define	WT_STAT_CONN_CACHE_EVICTION_SERVER_SLEPT	1060
/*! cache: eviction server unable to reach eviction goal */
#define	WT_STAT_CONN_CACHE_EVICTION_SLOW		1061
/*! cache: eviction server waiting for a leaf page */
#define	WT_STAT_CONN_CACHE_EVICTION_WALK_LEAF_NOTFOUND	1062
/*! cache: eviction state */
#define	WT_STAT_CONN_CACHE_EVICTION_STATE		1063
/*! cache: eviction walk target pages histogram - 0-9 */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_PAGE_LT10	1064
/*! cache: eviction walk target pages histogram - 10-31 */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_PAGE_LT32	1065
/*! cache: eviction walk target pages histogram - 128 and higher */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_PAGE_GE128	1066
/*! cache: eviction walk target pages histogram - 32-63 */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_PAGE_LT64	1067
/*! cache: eviction walk target pages histogram - 64-128 */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_PAGE_LT128	1068
/*! cache: eviction walk target strategy both clean and dirty pages */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_STRATEGY_BOTH_CLEAN_AND_DIRTY	1069
/*! cache: eviction walk target strategy only clean pages */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_STRATEGY_CLEAN	1070
/*! cache: eviction walk target strategy only dirty pages */
#define	WT_STAT_CONN_CACHE_EVICTION_TARGET_STRATEGY_DIRTY	1071
/*! cache: eviction walks abandoned */
#define	WT_STAT_CONN_CACHE_EVICTION_WALKS_ABANDONED	1072
/*! cache: eviction walks gave up because they restarted their walk twice */
#define	WT_STAT_CONN_CACHE_EVICTION_WALKS_STOPPED	1073
/*!
 * cache: eviction walks gave up because they saw too many pages and
 * found no candidates
 */
#define	WT_STAT_CONN_CACHE_EVICTION_WALKS_GAVE_UP_NO_TARGETS	1074
/*!
 * cache: eviction walks gave up because they saw too many pages and
 * found too few candidates
 */
#define	WT_STAT_CONN_CACHE_EVICTION_WALKS_GAVE_UP_RATIO	1075
/*! cache: eviction walks reached end of tree */
#define	WT_STAT_CONN_CACHE_EVICTION_WALKS_ENDED		1076
/*! cache: eviction walks started from root of tree */
#define	WT_STAT_CONN_CACHE_EVICTION_WALK_FROM_ROOT	1077
/*! cache: eviction walks started from saved location in tree */
#define	WT_STAT_CONN_CACHE_EVICTION_WALK_SAVED_POS	1078
/*! cache: eviction worker thread active */
#define	WT_STAT_CONN_CACHE_EVICTION_ACTIVE_WORKERS	1079
/*! cache: eviction worker thread created */
#define	WT_STAT_CONN_CACHE_EVICTION_WORKER_CREATED	1080
/*! cache: eviction worker thread evicting pages */
#define	WT_STAT_CONN_CACHE_EVICTION_WORKER_EVICTING	1081
/*! cache: eviction worker thread removed */
#define	WT_STAT_CONN_CACHE_EVICTION_WORKER_REMOVED	1082
/*! cache: eviction worker thread stable number */
#define	WT_STAT_CONN_CACHE_EVICTION_STABLE_STATE_WORKERS	1083
/*! cache: files with active eviction walks */
#define	WT_STAT_CONN_CACHE_EVICTION_WALKS_ACTIVE	1084
/*! cache: files with new eviction walks started */
#define	WT_STAT_CONN_CACHE_EVICTION_WALKS_STARTED	1085
/*! cache: force re-tuning of eviction workers once in a while */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_RETUNE	1086
/*!
 * cache: forced eviction - history store pages failed to evict while
 * session has history store cursor open
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_HS_FAIL	1087
/*!
 * cache: forced eviction - history store pages selected while session
 * has history store cursor open
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_HS		1088
/*!
 * cache: forced eviction - history store pages successfully evicted
 * while session has history store cursor open
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_HS_SUCCESS	1089
/*! cache: forced eviction - pages evicted that were clean count */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_CLEAN		1090
/*! cache: forced eviction - pages evicted that were clean time (usecs) */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_CLEAN_TIME	1091
/*! cache: forced eviction - pages evicted that were dirty count */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_DIRTY		1092
/*! cache: forced eviction - pages evicted that were dirty time (usecs) */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_DIRTY_TIME	1093
/*!
 * cache: forced eviction - pages selected because of too many deleted
 * items count
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_DELETE	1094
/*! cache: forced eviction - pages selected count */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE		1095
/*! cache: forced eviction - pages selected unable to be evicted count */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_FAIL		1096
/*! cache: forced eviction - pages selected unable to be evicted time */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_FAIL_TIME	1097
/*!
 * cache: forced eviction - session returned rollback error while force
 * evicting due to being oldest
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FORCE_ROLLBACK	1098
/*! cache: hazard pointer blocked page eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_HAZARD		1099
/*! cache: hazard pointer check calls */
#define	WT_STAT_CONN_CACHE_HAZARD_CHECKS		1100
/*! cache: hazard pointer check entries walked */
#define	WT_STAT_CONN_CACHE_HAZARD_WALKS			1101
/*! cache: hazard pointer maximum array length */
#define	WT_STAT_CONN_CACHE_HAZARD_MAX			1102
/*! cache: history store key truncation calls that returned restart */
#define	WT_STAT_CONN_CACHE_HS_KEY_TRUNCATE_MIX_TS_RESTART	1103
/*! cache: history store key truncation due to mixed timestamps */
#define	WT_STAT_CONN_CACHE_HS_KEY_TRUNCATE_MIX_TS	1104
/*!
 * cache: history store key truncation due to the key being removed from
 * the data page
 */
#define	WT_STAT_CONN_CACHE_HS_KEY_TRUNCATE_ONPAGE_REMOVAL	1105
/*! cache: history store score */
#define	WT_STAT_CONN_CACHE_HS_SCORE			1106
/*! cache: history store table insert calls */
#define	WT_STAT_CONN_CACHE_HS_INSERT			1107
/*! cache: history store table insert calls that returned restart */
#define	WT_STAT_CONN_CACHE_HS_INSERT_RESTART		1108
/*! cache: history store table max on-disk size */
#define	WT_STAT_CONN_CACHE_HS_ONDISK_MAX		1109
/*! cache: history store table on-disk size */
#define	WT_STAT_CONN_CACHE_HS_ONDISK			1110
/*!
 * cache: history store table out-of-order resolved updates that lose
 * their durable timestamp
 */
#define	WT_STAT_CONN_CACHE_HS_ORDER_LOSE_DURABLE_TIMESTAMP	1111
/*!
 * cache: history store table out-of-order updates that were fixed up by
 * moving existing records
 */
#define	WT_STAT_CONN_CACHE_HS_ORDER_FIXUP_MOVE		1112
/*!
 * cache: history store table out-of-order updates that were fixed up
 * during insertion
 */
#define	WT_STAT_CONN_CACHE_HS_ORDER_FIXUP_INSERT	1113
/*! cache: history store table reads */
#define	WT_STAT_CONN_CACHE_HS_READ			1114
/*! cache: history store table reads missed */
#define	WT_STAT_CONN_CACHE_HS_READ_MISS			1115
/*! cache: history store table reads requiring squashed modifies */
#define	WT_STAT_CONN_CACHE_HS_READ_SQUASH		1116
/*! cache: history store table remove calls due to key truncation */
#define	WT_STAT_CONN_CACHE_HS_REMOVE_KEY_TRUNCATE	1117
/*! cache: history store table writes requiring squashed modifies */
#define	WT_STAT_CONN_CACHE_HS_WRITE_SQUASH		1118
/*! cache: in-memory page passed criteria to be split */
#define	WT_STAT_CONN_CACHE_INMEM_SPLITTABLE		1119
/*! cache: in-memory page splits */
#define	WT_STAT_CONN_CACHE_INMEM_SPLIT			1120
/*! cache: internal pages evicted */
#define	WT_STAT_CONN_CACHE_EVICTION_INTERNAL		1121
/*! cache: internal pages queued for eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_INTERNAL_PAGES_QUEUED	1122
/*! cache: internal pages seen by eviction walk */
#define	WT_STAT_CONN_CACHE_EVICTION_INTERNAL_PAGES_SEEN	1123
/*! cache: internal pages seen by eviction walk that are already queued */
#define	WT_STAT_CONN_CACHE_EVICTION_INTERNAL_PAGES_ALREADY_QUEUED	1124
/*! cache: internal pages split during eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_SPLIT_INTERNAL	1125
/*! cache: leaf pages split during eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_SPLIT_LEAF		1126
/*! cache: maximum bytes configured */
#define	WT_STAT_CONN_CACHE_BYTES_MAX			1127
/*! cache: maximum page size at eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_MAXIMUM_PAGE_SIZE	1128
/*! cache: modified pages evicted */
#define	WT_STAT_CONN_CACHE_EVICTION_DIRTY		1129
/*! cache: modified pages evicted by application threads */
#define	WT_STAT_CONN_CACHE_EVICTION_APP_DIRTY		1130
/*! cache: operations timed out waiting for space in cache */
#define	WT_STAT_CONN_CACHE_TIMED_OUT_OPS		1131
/*! cache: overflow pages read into cache */
#define	WT_STAT_CONN_CACHE_READ_OVERFLOW		1132
/*! cache: page split during eviction deepened the tree */
#define	WT_STAT_CONN_CACHE_EVICTION_DEEPEN		1133
/*! cache: page written requiring history store records */
#define	WT_STAT_CONN_CACHE_WRITE_HS			1134
/*! cache: pages currently held in the cache */
#define	WT_STAT_CONN_CACHE_PAGES_INUSE			1135
/*! cache: pages evicted by application threads */
#define	WT_STAT_CONN_CACHE_EVICTION_APP			1136
/*! cache: pages queued for eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_PAGES_QUEUED	1137
/*! cache: pages queued for eviction post lru sorting */
#define	WT_STAT_CONN_CACHE_EVICTION_PAGES_QUEUED_POST_LRU	1138
/*! cache: pages queued for urgent eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_PAGES_QUEUED_URGENT	1139
/*! cache: pages queued for urgent eviction during walk */
#define	WT_STAT_CONN_CACHE_EVICTION_PAGES_QUEUED_OLDEST	1140
/*! cache: pages read into cache */
#define	WT_STAT_CONN_CACHE_READ				1141
/*! cache: pages read into cache after truncate */
#define	WT_STAT_CONN_CACHE_READ_DELETED			1142
/*! cache: pages read into cache after truncate in prepare state */
#define	WT_STAT_CONN_CACHE_READ_DELETED_PREPARED	1143
/*! cache: pages requested from the cache */
#define	WT_STAT_CONN_CACHE_PAGES_REQUESTED		1144
/*! cache: pages seen by eviction walk */
#define	WT_STAT_CONN_CACHE_EVICTION_PAGES_SEEN		1145
/*! cache: pages seen by eviction walk that are already queued */
#define	WT_STAT_CONN_CACHE_EVICTION_PAGES_ALREADY_QUEUED	1146
/*! cache: pages selected for eviction unable to be evicted */
#define	WT_STAT_CONN_CACHE_EVICTION_FAIL		1147
/*!
 * cache: pages selected for eviction unable to be evicted as the parent
 * page has overflow items
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FAIL_PARENT_HAS_OVERFLOW_ITEMS	1148
/*!
 * cache: pages selected for eviction unable to be evicted because of
 * active children on an internal page
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FAIL_ACTIVE_CHILDREN_ON_AN_INTERNAL_PAGE	1149
/*!
 * cache: pages selected for eviction unable to be evicted because of
 * failure in reconciliation
 */
#define	WT_STAT_CONN_CACHE_EVICTION_FAIL_IN_RECONCILIATION	1150
/*! cache: pages walked for eviction */
#define	WT_STAT_CONN_CACHE_EVICTION_WALK		1151
/*! cache: pages written from cache */
#define	WT_STAT_CONN_CACHE_WRITE			1152
/*! cache: pages written requiring in-memory restoration */
#define	WT_STAT_CONN_CACHE_WRITE_RESTORE		1153
/*! cache: percentage overhead */
#define	WT_STAT_CONN_CACHE_OVERHEAD			1154
/*! cache: tracked bytes belonging to internal pages in the cache */
#define	WT_STAT_CONN_CACHE_BYTES_INTERNAL		1155
/*! cache: tracked bytes belonging to leaf pages in the cache */
#define	WT_STAT_CONN_CACHE_BYTES_LEAF			1156
/*! cache: tracked dirty bytes in the cache */
#define	WT_STAT_CONN_CACHE_BYTES_DIRTY			1157
/*! cache: tracked dirty pages in the cache */
#define	WT_STAT_CONN_CACHE_PAGES_DIRTY			1158
/*! cache: unmodified pages evicted */
#define	WT_STAT_CONN_CACHE_EVICTION_CLEAN		1159
/*! capacity: background fsync file handles considered */
#define	WT_STAT_CONN_FSYNC_ALL_FH_TOTAL			1160
/*! capacity: background fsync file handles synced */
#define	WT_STAT_CONN_FSYNC_ALL_FH			1161
/*! capacity: background fsync time (msecs) */
#define	WT_STAT_CONN_FSYNC_ALL_TIME			1162
/*! capacity: bytes read */
#define	WT_STAT_CONN_CAPACITY_BYTES_READ		1163
/*! capacity: bytes written for checkpoint */
#define	WT_STAT_CONN_CAPACITY_BYTES_CKPT		1164
/*! capacity: bytes written for eviction */
#define	WT_STAT_CONN_CAPACITY_BYTES_EVICT		1165
/*! capacity: bytes written for log */
#define	WT_STAT_CONN_CAPACITY_BYTES_LOG			1166
/*! capacity: bytes written total */
#define	WT_STAT_CONN_CAPACITY_BYTES_WRITTEN		1167
/*! capacity: threshold to call fsync */
#define	WT_STAT_CONN_CAPACITY_THRESHOLD			1168
/*! capacity: time waiting due to total capacity (usecs) */
#define	WT_STAT_CONN_CAPACITY_TIME_TOTAL		1169
/*! capacity: time waiting during checkpoint (usecs) */
#define	WT_STAT_CONN_CAPACITY_TIME_CKPT			1170
/*! capacity: time waiting during eviction (usecs) */
#define	WT_STAT_CONN_CAPACITY_TIME_EVICT		1171
/*! capacity: time waiting during logging (usecs) */
#define	WT_STAT_CONN_CAPACITY_TIME_LOG			1172
/*! capacity: time waiting during read (usecs) */
#define	WT_STAT_CONN_CAPACITY_TIME_READ			1173
/*! checkpoint-cleanup: pages added for eviction */
#define	WT_STAT_CONN_CC_PAGES_EVICT			1174
/*! checkpoint-cleanup: pages removed */
#define	WT_STAT_CONN_CC_PAGES_REMOVED			1175
/*! checkpoint-cleanup: pages skipped during tree walk */
#define	WT_STAT_CONN_CC_PAGES_WALK_SKIPPED		1176
/*! checkpoint-cleanup: pages visited */
#define	WT_STAT_CONN_CC_PAGES_VISITED			1177
/*! connection: auto adjusting condition resets */
#define	WT_STAT_CONN_COND_AUTO_WAIT_RESET		1178
/*! connection: auto adjusting condition wait calls */
#define	WT_STAT_CONN_COND_AUTO_WAIT			1179
/*!
 * connection: auto adjusting condition wait raced to update timeout and
 * skipped updating
 */
#define	WT_STAT_CONN_COND_AUTO_WAIT_SKIPPED		1180
/*! connection: detected system time went backwards */
#define	WT_STAT_CONN_TIME_TRAVEL			1181
/*! connection: files currently open */
#define	WT_STAT_CONN_FILE_OPEN				1182
/*! connection: memory allocations */
#define	WT_STAT_CONN_MEMORY_ALLOCATION			1183
/*! connection: memory frees */
#define	WT_STAT_CONN_MEMORY_FREE			1184
/*! connection: memory re-allocations */
#define	WT_STAT_CONN_MEMORY_GROW			1185
/*! connection: pthread mutex condition wait calls */
#define	WT_STAT_CONN_COND_WAIT				1186
/*! connection: pthread mutex shared lock read-lock calls */
#define	WT_STAT_CONN_RWLOCK_READ			1187
/*! connection: pthread mutex shared lock write-lock calls */
#define	WT_STAT_CONN_RWLOCK_WRITE			1188
/*! connection: total fsync I/Os */
#define	WT_STAT_CONN_FSYNC_IO				1189
/*! connection: total read I/Os */
#define	WT_STAT_CONN_READ_IO				1190
/*! connection: total write I/Os */
#define	WT_STAT_CONN_WRITE_IO				1191
/*! cursor: Total number of entries skipped by cursor next calls */
#define	WT_STAT_CONN_CURSOR_NEXT_SKIP_TOTAL		1192
/*! cursor: Total number of entries skipped by cursor prev calls */
#define	WT_STAT_CONN_CURSOR_PREV_SKIP_TOTAL		1193
/*!
 * cursor: Total number of entries skipped to position the history store
 * cursor
 */
#define	WT_STAT_CONN_CURSOR_SKIP_HS_CUR_POSITION	1194
/*! cursor: cached cursor count */
#define	WT_STAT_CONN_CURSOR_CACHED_COUNT		1195
/*! cursor: cursor bulk loaded cursor insert calls */
#define	WT_STAT_CONN_CURSOR_INSERT_BULK			1196
/*! cursor: cursor close calls that result in cache */
#define	WT_STAT_CONN_CURSOR_CACHE			1197
/*! cursor: cursor create calls */
#define	WT_STAT_CONN_CURSOR_CREATE			1198
/*! cursor: cursor insert calls */
#define	WT_STAT_CONN_CURSOR_INSERT			1199
/*! cursor: cursor insert key and value bytes */
#define	WT_STAT_CONN_CURSOR_INSERT_BYTES		1200
/*! cursor: cursor modify calls */
#define	WT_STAT_CONN_CURSOR_MODIFY			1201
/*! cursor: cursor modify key and value bytes affected */
#define	WT_STAT_CONN_CURSOR_MODIFY_BYTES		1202
/*! cursor: cursor modify value bytes modified */
#define	WT_STAT_CONN_CURSOR_MODIFY_BYTES_TOUCH		1203
/*! cursor: cursor next calls */
#define	WT_STAT_CONN_CURSOR_NEXT			1204
/*!
 * cursor: cursor next calls that skip greater than or equal to 100
 * entries
 */
#define	WT_STAT_CONN_CURSOR_NEXT_SKIP_GE_100		1205
/*! cursor: cursor next calls that skip less than 100 entries */
#define	WT_STAT_CONN_CURSOR_NEXT_SKIP_LT_100		1206
/*! cursor: cursor operation restarted */
#define	WT_STAT_CONN_CURSOR_RESTART			1207
/*! cursor: cursor prev calls */
#define	WT_STAT_CONN_CURSOR_PREV			1208
/*!
 * cursor: cursor prev calls that skip due to a globally visible history
 * store tombstone
 */
#define	WT_STAT_CONN_CURSOR_PREV_HS_TOMBSTONE		1209
/*!
 * cursor: cursor prev calls that skip due to a globally visible history
 * store tombstone in rollback to stable
 */
#define	WT_STAT_CONN_CURSOR_PREV_HS_TOMBSTONE_RTS	1210
/*!
 * cursor: cursor prev calls that skip greater than or equal to 100
 * entries
 */
#define	WT_STAT_CONN_CURSOR_PREV_SKIP_GE_100		1211
/*! cursor: cursor prev calls that skip less than 100 entries */
#define	WT_STAT_CONN_CURSOR_PREV_SKIP_LT_100		1212
/*! cursor: cursor remove calls */
#define	WT_STAT_CONN_CURSOR_REMOVE			1213
/*! cursor: cursor remove key bytes removed */
#define	WT_STAT_CONN_CURSOR_REMOVE_BYTES		1214
/*! cursor: cursor reserve calls */
#define	WT_STAT_CONN_CURSOR_RESERVE			1215
/*! cursor: cursor reset calls */
#define	WT_STAT_CONN_CURSOR_RESET			1216
/*! cursor: cursor search calls */
#define	WT_STAT_CONN_CURSOR_SEARCH			1217
/*! cursor: cursor search history store calls */
#define	WT_STAT_CONN_CURSOR_SEARCH_HS			1218
/*! cursor: cursor search near calls */
#define	WT_STAT_CONN_CURSOR_SEARCH_NEAR			1219
/*! cursor: cursor sweep buckets */
#define	WT_STAT_CONN_CURSOR_SWEEP_BUCKETS		1220
/*! cursor: cursor sweep cursors closed */
#define	WT_STAT_CONN_CURSOR_SWEEP_CLOSED		1221
/*! cursor: cursor sweep cursors examined */
#define	WT_STAT_CONN_CURSOR_SWEEP_EXAMINED		1222
/*! cursor: cursor sweeps */
#define	WT_STAT_CONN_CURSOR_SWEEP			1223
/*! cursor: cursor truncate calls */
#define	WT_STAT_CONN_CURSOR_TRUNCATE			1224
/*! cursor: cursor update calls */
#define	WT_STAT_CONN_CURSOR_UPDATE			1225
/*! cursor: cursor update key and value bytes */
#define	WT_STAT_CONN_CURSOR_UPDATE_BYTES		1226
/*! cursor: cursor update value size change */
#define	WT_STAT_CONN_CURSOR_UPDATE_BYTES_CHANGED	1227
/*! cursor: cursors reused from cache */
#define	WT_STAT_CONN_CURSOR_REOPEN			1228
/*! cursor: open cursor count */
#define	WT_STAT_CONN_CURSOR_OPEN_COUNT			1229
/*! data-handle: connection data handle size */
#define	WT_STAT_CONN_DH_CONN_HANDLE_SIZE		1230
/*! data-handle: connection data handles currently active */
#define	WT_STAT_CONN_DH_CONN_HANDLE_COUNT		1231
/*! data-handle: connection sweep candidate became referenced */
#define	WT_STAT_CONN_DH_SWEEP_REF			1232
/*! data-handle: connection sweep dhandles closed */
#define	WT_STAT_CONN_DH_SWEEP_CLOSE			1233
/*! data-handle: connection sweep dhandles removed from hash list */
#define	WT_STAT_CONN_DH_SWEEP_REMOVE			1234
/*! data-handle: connection sweep time-of-death sets */
#define	WT_STAT_CONN_DH_SWEEP_TOD			1235
/*! data-handle: connection sweeps */
#define	WT_STAT_CONN_DH_SWEEPS				1236
/*! data-handle: session dhandles swept */
#define	WT_STAT_CONN_DH_SESSION_HANDLES			1237
/*! data-handle: session sweep attempts */
#define	WT_STAT_CONN_DH_SESSION_SWEEPS			1238
/*! lock: checkpoint lock acquisitions */
#define	WT_STAT_CONN_LOCK_CHECKPOINT_COUNT		1239
/*! lock: checkpoint lock application thread wait time (usecs) */
#define	WT_STAT_CONN_LOCK_CHECKPOINT_WAIT_APPLICATION	1240
/*! lock: checkpoint lock internal thread wait time (usecs) */
#define	WT_STAT_CONN_LOCK_CHECKPOINT_WAIT_INTERNAL	1241
/*! lock: dhandle lock application thread time waiting (usecs) */
#define	WT_STAT_CONN_LOCK_DHANDLE_WAIT_APPLICATION	1242
/*! lock: dhandle lock internal thread time waiting (usecs) */
#define	WT_STAT_CONN_LOCK_DHANDLE_WAIT_INTERNAL		1243
/*! lock: dhandle read lock acquisitions */
#define	WT_STAT_CONN_LOCK_DHANDLE_READ_COUNT		1244
/*! lock: dhandle write lock acquisitions */
#define	WT_STAT_CONN_LOCK_DHANDLE_WRITE_COUNT		1245
/*!
 * lock: durable timestamp queue lock application thread time waiting
 * (usecs)
 */
#define	WT_STAT_CONN_LOCK_DURABLE_TIMESTAMP_WAIT_APPLICATION	1246
/*!
 * lock: durable timestamp queue lock internal thread time waiting
 * (usecs)
 */
#define	WT_STAT_CONN_LOCK_DURABLE_TIMESTAMP_WAIT_INTERNAL	1247
/*! lock: durable timestamp queue read lock acquisitions */
#define	WT_STAT_CONN_LOCK_DURABLE_TIMESTAMP_READ_COUNT	1248
/*! lock: durable timestamp queue write lock acquisitions */
#define	WT_STAT_CONN_LOCK_DURABLE_TIMESTAMP_WRITE_COUNT	1249
/*! lock: metadata lock acquisitions */
#define	WT_STAT_CONN_LOCK_METADATA_COUNT		1250
/*! lock: metadata lock application thread wait time (usecs) */
#define	WT_STAT_CONN_LOCK_METADATA_WAIT_APPLICATION	1251
/*! lock: metadata lock internal thread wait time (usecs) */
#define	WT_STAT_CONN_LOCK_METADATA_WAIT_INTERNAL	1252
/*!
 * lock: read timestamp queue lock application thread time waiting
 * (usecs)
 */
#define	WT_STAT_CONN_LOCK_READ_TIMESTAMP_WAIT_APPLICATION	1253
/*! lock: read timestamp queue lock internal thread time waiting (usecs) */
#define	WT_STAT_CONN_LOCK_READ_TIMESTAMP_WAIT_INTERNAL	1254
/*! lock: read timestamp queue read lock acquisitions */
#define	WT_STAT_CONN_LOCK_READ_TIMESTAMP_READ_COUNT	1255
/*! lock: read timestamp queue write lock acquisitions */
#define	WT_STAT_CONN_LOCK_READ_TIMESTAMP_WRITE_COUNT	1256
/*! lock: schema lock acquisitions */
#define	WT_STAT_CONN_LOCK_SCHEMA_COUNT			1257
/*! lock: schema lock application thread wait time (usecs) */
#define	WT_STAT_CONN_LOCK_SCHEMA_WAIT_APPLICATION	1258
/*! lock: schema lock internal thread wait time (usecs) */
#define	WT_STAT_CONN_LOCK_SCHEMA_WAIT_INTERNAL		1259
/*!
 * lock: table lock application thread time waiting for the table lock
 * (usecs)
 */
#define	WT_STAT_CONN_LOCK_TABLE_WAIT_APPLICATION	1260
/*!
 * lock: table lock internal thread time waiting for the table lock
 * (usecs)
 */
#define	WT_STAT_CONN_LOCK_TABLE_WAIT_INTERNAL		1261
/*! lock: table read lock acquisitions */
#define	WT_STAT_CONN_LOCK_TABLE_READ_COUNT		1262
/*! lock: table write lock acquisitions */
#define	WT_STAT_CONN_LOCK_TABLE_WRITE_COUNT		1263
/*! lock: txn global lock application thread time waiting (usecs) */
#define	WT_STAT_CONN_LOCK_TXN_GLOBAL_WAIT_APPLICATION	1264
/*! lock: txn global lock internal thread time waiting (usecs) */
#define	WT_STAT_CONN_LOCK_TXN_GLOBAL_WAIT_INTERNAL	1265
/*! lock: txn global read lock acquisitions */
#define	WT_STAT_CONN_LOCK_TXN_GLOBAL_READ_COUNT		1266
/*! lock: txn global write lock acquisitions */
#define	WT_STAT_CONN_LOCK_TXN_GLOBAL_WRITE_COUNT	1267
/*! log: busy returns attempting to switch slots */
#define	WT_STAT_CONN_LOG_SLOT_SWITCH_BUSY		1268
/*! log: force archive time sleeping (usecs) */
#define	WT_STAT_CONN_LOG_FORCE_ARCHIVE_SLEEP		1269
/*! log: log bytes of payload data */
#define	WT_STAT_CONN_LOG_BYTES_PAYLOAD			1270
/*! log: log bytes written */
#define	WT_STAT_CONN_LOG_BYTES_WRITTEN			1271
/*! log: log files manually zero-filled */
#define	WT_STAT_CONN_LOG_ZERO_FILLS			1272
/*! log: log flush operations */
#define	WT_STAT_CONN_LOG_FLUSH				1273
/*! log: log force write operations */
#define	WT_STAT_CONN_LOG_FORCE_WRITE			1274
/*! log: log force write operations skipped */
#define	WT_STAT_CONN_LOG_FORCE_WRITE_SKIP		1275
/*! log: log records compressed */
#define	WT_STAT_CONN_LOG_COMPRESS_WRITES		1276
/*! log: log records not compressed */
#define	WT_STAT_CONN_LOG_COMPRESS_WRITE_FAILS		1277
/*! log: log records too small to compress */
#define	WT_STAT_CONN_LOG_COMPRESS_SMALL			1278
/*! log: log release advances write LSN */
#define	WT_STAT_CONN_LOG_RELEASE_WRITE_LSN		1279
/*! log: log scan operations */
#define	WT_STAT_CONN_LOG_SCANS				1280
/*! log: log scan records requiring two reads */
#define	WT_STAT_CONN_LOG_SCAN_REREADS			1281
/*! log: log server thread advances write LSN */
#define	WT_STAT_CONN_LOG_WRITE_LSN			1282
/*! log: log server thread write LSN walk skipped */
#define	WT_STAT_CONN_LOG_WRITE_LSN_SKIP			1283
/*! log: log sync operations */
#define	WT_STAT_CONN_LOG_SYNC				1284
/*! log: log sync time duration (usecs) */
#define	WT_STAT_CONN_LOG_SYNC_DURATION			1285
/*! log: log sync_dir operations */
#define	WT_STAT_CONN_LOG_SYNC_DIR			1286
/*! log: log sync_dir time duration (usecs) */
#define	WT_STAT_CONN_LOG_SYNC_DIR_DURATION		1287
/*! log: log write operations */
#define	WT_STAT_CONN_LOG_WRITES				1288
/*! log: logging bytes consolidated */
#define	WT_STAT_CONN_LOG_SLOT_CONSOLIDATED		1289
/*! log: maximum log file size */
#define	WT_STAT_CONN_LOG_MAX_FILESIZE			1290
/*! log: number of pre-allocated log files to create */
#define	WT_STAT_CONN_LOG_PREALLOC_MAX			1291
/*! log: pre-allocated log files not ready and missed */
#define	WT_STAT_CONN_LOG_PREALLOC_MISSED		1292
/*! log: pre-allocated log files prepared */
#define	WT_STAT_CONN_LOG_PREALLOC_FILES			1293
/*! log: pre-allocated log files used */
#define	WT_STAT_CONN_LOG_PREALLOC_USED			1294
/*! log: records processed by log scan */
#define	WT_STAT_CONN_LOG_SCAN_RECORDS			1295
/*! log: slot close lost race */
#define	WT_STAT_CONN_LOG_SLOT_CLOSE_RACE		1296
/*! log: slot close unbuffered waits */
#define	WT_STAT_CONN_LOG_SLOT_CLOSE_UNBUF		1297
/*! log: slot closures */
#define	WT_STAT_CONN_LOG_SLOT_CLOSES			1298
/*! log: slot join atomic update races */
#define	WT_STAT_CONN_LOG_SLOT_RACES			1299
/*! log: slot join calls atomic updates raced */
#define	WT_STAT_CONN_LOG_SLOT_YIELD_RACE		1300
/*! log: slot join calls did not yield */
#define	WT_STAT_CONN_LOG_SLOT_IMMEDIATE			1301
/*! log: slot join calls found active slot closed */
#define	WT_STAT_CONN_LOG_SLOT_YIELD_CLOSE		1302
/*! log: slot join calls slept */
#define	WT_STAT_CONN_LOG_SLOT_YIELD_SLEEP		1303
/*! log: slot join calls yielded */
#define	WT_STAT_CONN_LOG_SLOT_YIELD			1304
/*! log: slot join found active slot closed */
#define	WT_STAT_CONN_LOG_SLOT_ACTIVE_CLOSED		1305
/*! log: slot joins yield time (usecs) */
#define	WT_STAT_CONN_LOG_SLOT_YIELD_DURATION		1306
/*! log: slot transitions unable to find free slot */
#define	WT_STAT_CONN_LOG_SLOT_NO_FREE_SLOTS		1307
/*! log: slot unbuffered writes */
#define	WT_STAT_CONN_LOG_SLOT_UNBUFFERED		1308
/*! log: total in-memory size of compressed records */
#define	WT_STAT_CONN_LOG_COMPRESS_MEM			1309
/*! log: total log buffer size */
#define	WT_STAT_CONN_LOG_BUFFER_SIZE			1310
/*! log: total size of compressed records */
#define	WT_STAT_CONN_LOG_COMPRESS_LEN			1311
/*! log: written slots coalesced */
#define	WT_STAT_CONN_LOG_SLOT_COALESCED			1312
/*! log: yields waiting for previous log file close */
#define	WT_STAT_CONN_LOG_CLOSE_YIELDS			1313
/*! perf: file system read latency histogram (bucket 1) - 10-49ms */
#define	WT_STAT_CONN_PERF_HIST_FSREAD_LATENCY_LT50	1314
/*! perf: file system read latency histogram (bucket 2) - 50-99ms */
#define	WT_STAT_CONN_PERF_HIST_FSREAD_LATENCY_LT100	1315
/*! perf: file system read latency histogram (bucket 3) - 100-249ms */
#define	WT_STAT_CONN_PERF_HIST_FSREAD_LATENCY_LT250	1316
/*! perf: file system read latency histogram (bucket 4) - 250-499ms */
#define	WT_STAT_CONN_PERF_HIST_FSREAD_LATENCY_LT500	1317
/*! perf: file system read latency histogram (bucket 5) - 500-999ms */
#define	WT_STAT_CONN_PERF_HIST_FSREAD_LATENCY_LT1000	1318
/*! perf: file system read latency histogram (bucket 6) - 1000ms+ */
#define	WT_STAT_CONN_PERF_HIST_FSREAD_LATENCY_GT1000	1319
/*! perf: file system write latency histogram (bucket 1) - 10-49ms */
#define	WT_STAT_CONN_PERF_HIST_FSWRITE_LATENCY_LT50	1320
/*! perf: file system write latency histogram (bucket 2) - 50-99ms */
#define	WT_STAT_CONN_PERF_HIST_FSWRITE_LATENCY_LT100	1321
/*! perf: file system write latency histogram (bucket 3) - 100-249ms */
#define	WT_STAT_CONN_PERF_HIST_FSWRITE_LATENCY_LT250	1322
/*! perf: file system write latency histogram (bucket 4) - 250-499ms */
#define	WT_STAT_CONN_PERF_HIST_FSWRITE_LATENCY_LT500	1323
/*! perf: file system write latency histogram (bucket 5) - 500-999ms */
#define	WT_STAT_CONN_PERF_HIST_FSWRITE_LATENCY_LT1000	1324
/*! perf: file system write latency histogram (bucket 6) - 1000ms+ */
#define	WT_STAT_CONN_PERF_HIST_FSWRITE_LATENCY_GT1000	1325
/*! perf: operation read latency histogram (bucket 1) - 100-249us */
#define	WT_STAT_CONN_PERF_HIST_OPREAD_LATENCY_LT250	1326
/*! perf: operation read latency histogram (bucket 2) - 250-499us */
#define	WT_STAT_CONN_PERF_HIST_OPREAD_LATENCY_LT500	1327
/*! perf: operation read latency histogram (bucket 3) - 500-999us */
#define	WT_STAT_CONN_PERF_HIST_OPREAD_LATENCY_LT1000	1328
/*! perf: operation read latency histogram (bucket 4) - 1000-9999us */
#define	WT_STAT_CONN_PERF_HIST_OPREAD_LATENCY_LT10000	1329
/*! perf: operation read latency histogram (bucket 5) - 10000us+ */
#define	WT_STAT_CONN_PERF_HIST_OPREAD_LATENCY_GT10000	1330
/*! perf: operation write latency histogram (bucket 1) - 100-249us */
#define	WT_STAT_CONN_PERF_HIST_OPWRITE_LATENCY_LT250	1331
/*! perf: operation write latency histogram (bucket 2) - 250-499us */
#define	WT_STAT_CONN_PERF_HIST_OPWRITE_LATENCY_LT500	1332
/*! perf: operation write latency histogram (bucket 3) - 500-999us */
#define	WT_STAT_CONN_PERF_HIST_OPWRITE_LATENCY_LT1000	1333
/*! perf: operation write latency histogram (bucket 4) - 1000-9999us */
#define	WT_STAT_CONN_PERF_HIST_OPWRITE_LATENCY_LT10000	1334
/*! perf: operation write latency histogram (bucket 5) - 10000us+ */
#define	WT_STAT_CONN_PERF_HIST_OPWRITE_LATENCY_GT10000	1335
/*! reconciliation: approximate byte size of timestamps in pages written */
#define	WT_STAT_CONN_REC_TIME_WINDOW_BYTES_TS		1336
/*!
 * reconciliation: approximate byte size of transaction IDs in pages
 * written
 */
#define	WT_STAT_CONN_REC_TIME_WINDOW_BYTES_TXN		1337
/*! reconciliation: fast-path pages deleted */
#define	WT_STAT_CONN_REC_PAGE_DELETE_FAST		1338
/*! reconciliation: maximum seconds spent in a reconciliation call */
#define	WT_STAT_CONN_REC_MAXIMUM_SECONDS		1339
/*! reconciliation: page reconciliation calls */
#define	WT_STAT_CONN_REC_PAGES				1340
/*! reconciliation: page reconciliation calls for eviction */
#define	WT_STAT_CONN_REC_PAGES_EVICTION			1341
/*!
 * reconciliation: page reconciliation calls that resulted in values with
 * prepared transaction metadata
 */
#define	WT_STAT_CONN_REC_PAGES_WITH_PREPARE		1342
/*!
 * reconciliation: page reconciliation calls that resulted in values with
 * timestamps
 */
#define	WT_STAT_CONN_REC_PAGES_WITH_TS			1343
/*!
 * reconciliation: page reconciliation calls that resulted in values with
 * transaction ids
 */
#define	WT_STAT_CONN_REC_PAGES_WITH_TXN			1344
/*! reconciliation: pages deleted */
#define	WT_STAT_CONN_REC_PAGE_DELETE			1345
/*!
 * reconciliation: pages written including an aggregated newest start
 * durable timestamp
 */
#define	WT_STAT_CONN_REC_TIME_AGGR_NEWEST_START_DURABLE_TS	1346
/*!
 * reconciliation: pages written including an aggregated newest stop
 * durable timestamp
 */
#define	WT_STAT_CONN_REC_TIME_AGGR_NEWEST_STOP_DURABLE_TS	1347
/*!
 * reconciliation: pages written including an aggregated newest stop
 * timestamp
 */
#define	WT_STAT_CONN_REC_TIME_AGGR_NEWEST_STOP_TS	1348
/*!
 * reconciliation: pages written including an aggregated newest stop
 * transaction ID
 */
#define	WT_STAT_CONN_REC_TIME_AGGR_NEWEST_STOP_TXN	1349
/*!
 * reconciliation: pages written including an aggregated oldest start
 * timestamp
 */
#define	WT_STAT_CONN_REC_TIME_AGGR_OLDEST_START_TS	1350
/*!
 * reconciliation: pages written including an aggregated oldest start
 * transaction ID
 */
#define	WT_STAT_CONN_REC_TIME_AGGR_OLDEST_START_TXN	1351
/*! reconciliation: pages written including an aggregated prepare */
#define	WT_STAT_CONN_REC_TIME_AGGR_PREPARED		1352
/*! reconciliation: pages written including at least one prepare state */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PAGES_PREPARED	1353
/*!
 * reconciliation: pages written including at least one start durable
 * timestamp
 */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PAGES_DURABLE_START_TS	1354
/*! reconciliation: pages written including at least one start timestamp */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PAGES_START_TS	1355
/*!
 * reconciliation: pages written including at least one start transaction
 * ID
 */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PAGES_START_TXN	1356
/*!
 * reconciliation: pages written including at least one stop durable
 * timestamp
 */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PAGES_DURABLE_STOP_TS	1357
/*! reconciliation: pages written including at least one stop timestamp */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PAGES_STOP_TS	1358
/*!
 * reconciliation: pages written including at least one stop transaction
 * ID
 */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PAGES_STOP_TXN	1359
/*! reconciliation: records written including a prepare state */
#define	WT_STAT_CONN_REC_TIME_WINDOW_PREPARED		1360
/*! reconciliation: records written including a start durable timestamp */
#define	WT_STAT_CONN_REC_TIME_WINDOW_DURABLE_START_TS	1361
/*! reconciliation: records written including a start timestamp */
#define	WT_STAT_CONN_REC_TIME_WINDOW_START_TS		1362
/*! reconciliation: records written including a start transaction ID */
#define	WT_STAT_CONN_REC_TIME_WINDOW_START_TXN		1363
/*! reconciliation: records written including a stop durable timestamp */
#define	WT_STAT_CONN_REC_TIME_WINDOW_DURABLE_STOP_TS	1364
/*! reconciliation: records written including a stop timestamp */
#define	WT_STAT_CONN_REC_TIME_WINDOW_STOP_TS		1365
/*! reconciliation: records written including a stop transaction ID */
#define	WT_STAT_CONN_REC_TIME_WINDOW_STOP_TXN		1366
/*! reconciliation: split bytes currently awaiting free */
#define	WT_STAT_CONN_REC_SPLIT_STASHED_BYTES		1367
/*! reconciliation: split objects currently awaiting free */
#define	WT_STAT_CONN_REC_SPLIT_STASHED_OBJECTS		1368
/*! session: open session count */
#define	WT_STAT_CONN_SESSION_OPEN			1369
/*! session: session query timestamp calls */
#define	WT_STAT_CONN_SESSION_QUERY_TS			1370
/*! session: table alter failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_ALTER_FAIL		1371
/*! session: table alter successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_ALTER_SUCCESS	1372
/*! session: table alter unchanged and skipped */
#define	WT_STAT_CONN_SESSION_TABLE_ALTER_SKIP		1373
/*! session: table compact failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_COMPACT_FAIL		1374
/*! session: table compact successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_COMPACT_SUCCESS	1375
/*! session: table create failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_CREATE_FAIL		1376
/*! session: table create successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_CREATE_SUCCESS	1377
/*! session: table drop failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_DROP_FAIL		1378
/*! session: table drop successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_DROP_SUCCESS		1379
/*! session: table import failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_IMPORT_FAIL		1380
/*! session: table import successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_IMPORT_SUCCESS	1381
/*! session: table rebalance failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_REBALANCE_FAIL	1382
/*! session: table rebalance successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_REBALANCE_SUCCESS	1383
/*! session: table rename failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_RENAME_FAIL		1384
/*! session: table rename successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_RENAME_SUCCESS	1385
/*! session: table salvage failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_SALVAGE_FAIL		1386
/*! session: table salvage successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_SALVAGE_SUCCESS	1387
/*! session: table truncate failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_TRUNCATE_FAIL	1388
/*! session: table truncate successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_TRUNCATE_SUCCESS	1389
/*! session: table verify failed calls */
#define	WT_STAT_CONN_SESSION_TABLE_VERIFY_FAIL		1390
/*! session: table verify successful calls */
#define	WT_STAT_CONN_SESSION_TABLE_VERIFY_SUCCESS	1391
/*! thread-state: active filesystem fsync calls */
#define	WT_STAT_CONN_THREAD_FSYNC_ACTIVE		1392
/*! thread-state: active filesystem read calls */
#define	WT_STAT_CONN_THREAD_READ_ACTIVE			1393
/*! thread-state: active filesystem write calls */
#define	WT_STAT_CONN_THREAD_WRITE_ACTIVE		1394
/*! thread-yield: application thread time evicting (usecs) */
#define	WT_STAT_CONN_APPLICATION_EVICT_TIME		1395
/*! thread-yield: application thread time waiting for cache (usecs) */
#define	WT_STAT_CONN_APPLICATION_CACHE_TIME		1396
/*!
 * thread-yield: connection close blocked waiting for transaction state
 * stabilization
 */
#define	WT_STAT_CONN_TXN_RELEASE_BLOCKED		1397
/*! thread-yield: connection close yielded for lsm manager shutdown */
#define	WT_STAT_CONN_CONN_CLOSE_BLOCKED_LSM		1398
/*! thread-yield: data handle lock yielded */
#define	WT_STAT_CONN_DHANDLE_LOCK_BLOCKED		1399
/*!
 * thread-yield: get reference for page index and slot time sleeping
 * (usecs)
 */
#define	WT_STAT_CONN_PAGE_INDEX_SLOT_REF_BLOCKED	1400
/*! thread-yield: log server sync yielded for log write */
#define	WT_STAT_CONN_LOG_SERVER_SYNC_BLOCKED		1401
/*! thread-yield: page access yielded due to prepare state change */
#define	WT_STAT_CONN_PREPARED_TRANSITION_BLOCKED_PAGE	1402
/*! thread-yield: page acquire busy blocked */
#define	WT_STAT_CONN_PAGE_BUSY_BLOCKED			1403
/*! thread-yield: page acquire eviction blocked */
#define	WT_STAT_CONN_PAGE_FORCIBLE_EVICT_BLOCKED	1404
/*! thread-yield: page acquire locked blocked */
#define	WT_STAT_CONN_PAGE_LOCKED_BLOCKED		1405
/*! thread-yield: page acquire read blocked */
#define	WT_STAT_CONN_PAGE_READ_BLOCKED			1406
/*! thread-yield: page acquire time sleeping (usecs) */
#define	WT_STAT_CONN_PAGE_SLEEP				1407
/*!
 * thread-yield: page delete rollback time sleeping for state change
 * (usecs)
 */
#define	WT_STAT_CONN_PAGE_DEL_ROLLBACK_BLOCKED		1408
/*! thread-yield: page reconciliation yielded due to child modification */
#define	WT_STAT_CONN_CHILD_MODIFY_BLOCKED_PAGE		1409
/*! transaction: Number of prepared updates */
#define	WT_STAT_CONN_TXN_PREPARED_UPDATES_COUNT		1410
/*! transaction: durable timestamp queue entries walked */
#define	WT_STAT_CONN_TXN_DURABLE_QUEUE_WALKED		1411
/*! transaction: durable timestamp queue insert to empty */
#define	WT_STAT_CONN_TXN_DURABLE_QUEUE_EMPTY		1412
/*! transaction: durable timestamp queue inserts to head */
#define	WT_STAT_CONN_TXN_DURABLE_QUEUE_HEAD		1413
/*! transaction: durable timestamp queue inserts total */
#define	WT_STAT_CONN_TXN_DURABLE_QUEUE_INSERTS		1414
/*! transaction: durable timestamp queue length */
#define	WT_STAT_CONN_TXN_DURABLE_QUEUE_LEN		1415
/*! transaction: prepared transactions */
#define	WT_STAT_CONN_TXN_PREPARE			1416
/*! transaction: prepared transactions committed */
#define	WT_STAT_CONN_TXN_PREPARE_COMMIT			1417
/*! transaction: prepared transactions currently active */
#define	WT_STAT_CONN_TXN_PREPARE_ACTIVE			1418
/*! transaction: prepared transactions rolled back */
#define	WT_STAT_CONN_TXN_PREPARE_ROLLBACK		1419
/*! transaction: query timestamp calls */
#define	WT_STAT_CONN_TXN_QUERY_TS			1420
/*! transaction: read timestamp queue entries walked */
#define	WT_STAT_CONN_TXN_READ_QUEUE_WALKED		1421
/*! transaction: read timestamp queue insert to empty */
#define	WT_STAT_CONN_TXN_READ_QUEUE_EMPTY		1422
/*! transaction: read timestamp queue inserts to head */
#define	WT_STAT_CONN_TXN_READ_QUEUE_HEAD		1423
/*! transaction: read timestamp queue inserts total */
#define	WT_STAT_CONN_TXN_READ_QUEUE_INSERTS		1424
/*! transaction: read timestamp queue length */
#define	WT_STAT_CONN_TXN_READ_QUEUE_LEN			1425
/*! transaction: rollback to stable calls */
#define	WT_STAT_CONN_TXN_RTS				1426
/*!
 * transaction: rollback to stable hs records with stop timestamps older
 * than newer records
 */
#define	WT_STAT_CONN_TXN_RTS_HS_STOP_OLDER_THAN_NEWER_START	1427
/*! transaction: rollback to stable keys removed */
#define	WT_STAT_CONN_TXN_RTS_KEYS_REMOVED		1428
/*! transaction: rollback to stable keys restored */
#define	WT_STAT_CONN_TXN_RTS_KEYS_RESTORED		1429
/*! transaction: rollback to stable pages visited */
#define	WT_STAT_CONN_TXN_RTS_PAGES_VISITED		1430
/*! transaction: rollback to stable restored tombstones from history store */
#define	WT_STAT_CONN_TXN_RTS_HS_RESTORE_TOMBSTONES	1431
/*! transaction: rollback to stable sweeping history store keys */
#define	WT_STAT_CONN_TXN_RTS_SWEEP_HS_KEYS		1432
/*! transaction: rollback to stable tree walk skipping pages */
#define	WT_STAT_CONN_TXN_RTS_TREE_WALK_SKIP_PAGES	1433
/*! transaction: rollback to stable updates aborted */
#define	WT_STAT_CONN_TXN_RTS_UPD_ABORTED		1434
/*! transaction: rollback to stable updates removed from history store */
#define	WT_STAT_CONN_TXN_RTS_HS_REMOVED			1435
/*! transaction: set timestamp calls */
#define	WT_STAT_CONN_TXN_SET_TS				1436
/*! transaction: set timestamp durable calls */
#define	WT_STAT_CONN_TXN_SET_TS_DURABLE			1437
/*! transaction: set timestamp durable updates */
#define	WT_STAT_CONN_TXN_SET_TS_DURABLE_UPD		1438
/*! transaction: set timestamp oldest calls */
#define	WT_STAT_CONN_TXN_SET_TS_OLDEST			1439
/*! transaction: set timestamp oldest updates */
#define	WT_STAT_CONN_TXN_SET_TS_OLDEST_UPD		1440
/*! transaction: set timestamp stable calls */
#define	WT_STAT_CONN_TXN_SET_TS_STABLE			1441
/*! transaction: set timestamp stable updates */
#define	WT_STAT_CONN_TXN_SET_TS_STABLE_UPD		1442
/*! transaction: transaction begins */
#define	WT_STAT_CONN_TXN_BEGIN				1443
/*! transaction: transaction checkpoint currently running */
#define	WT_STAT_CONN_TXN_CHECKPOINT_RUNNING		1444
/*! transaction: transaction checkpoint generation */
#define	WT_STAT_CONN_TXN_CHECKPOINT_GENERATION		1445
/*!
 * transaction: transaction checkpoint history store file duration
 * (usecs)
 */
#define	WT_STAT_CONN_TXN_HS_CKPT_DURATION		1446
/*! transaction: transaction checkpoint max time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_TIME_MAX		1447
/*! transaction: transaction checkpoint min time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_TIME_MIN		1448
/*! transaction: transaction checkpoint most recent time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_TIME_RECENT		1449
/*! transaction: transaction checkpoint prepare currently running */
#define	WT_STAT_CONN_TXN_CHECKPOINT_PREP_RUNNING	1450
/*! transaction: transaction checkpoint prepare max time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_PREP_MAX		1451
/*! transaction: transaction checkpoint prepare min time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_PREP_MIN		1452
/*! transaction: transaction checkpoint prepare most recent time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_PREP_RECENT		1453
/*! transaction: transaction checkpoint prepare total time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_PREP_TOTAL		1454
/*! transaction: transaction checkpoint scrub dirty target */
#define	WT_STAT_CONN_TXN_CHECKPOINT_SCRUB_TARGET	1455
/*! transaction: transaction checkpoint scrub time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_SCRUB_TIME		1456
/*! transaction: transaction checkpoint total time (msecs) */
#define	WT_STAT_CONN_TXN_CHECKPOINT_TIME_TOTAL		1457
/*! transaction: transaction checkpoints */
#define	WT_STAT_CONN_TXN_CHECKPOINT			1458
/*!
 * transaction: transaction checkpoints skipped because database was
 * clean
 */
#define	WT_STAT_CONN_TXN_CHECKPOINT_SKIPPED		1459
/*! transaction: transaction failures due to history store */
#define	WT_STAT_CONN_TXN_FAIL_CACHE			1460
/*!
 * transaction: transaction fsync calls for checkpoint after allocating
 * the transaction ID
 */
#define	WT_STAT_CONN_TXN_CHECKPOINT_FSYNC_POST		1461
/*!
 * transaction: transaction fsync duration for checkpoint after
 * allocating the transaction ID (usecs)
 */
#define	WT_STAT_CONN_TXN_CHECKPOINT_FSYNC_POST_DURATION	1462
/*! transaction: transaction range of IDs currently pinned */
#define	WT_STAT_CONN_TXN_PINNED_RANGE			1463
/*! transaction: transaction range of IDs currently pinned by a checkpoint */
#define	WT_STAT_CONN_TXN_PINNED_CHECKPOINT_RANGE	1464
/*! transaction: transaction range of timestamps currently pinned */
#define	WT_STAT_CONN_TXN_PINNED_TIMESTAMP		1465
/*! transaction: transaction range of timestamps pinned by a checkpoint */
#define	WT_STAT_CONN_TXN_PINNED_TIMESTAMP_CHECKPOINT	1466
/*!
 * transaction: transaction range of timestamps pinned by the oldest
 * active read timestamp
 */
#define	WT_STAT_CONN_TXN_PINNED_TIMESTAMP_READER	1467
/*!
 * transaction: transaction range of timestamps pinned by the oldest
 * timestamp
 */
#define	WT_STAT_CONN_TXN_PINNED_TIMESTAMP_OLDEST	1468
/*! transaction: transaction read timestamp of the oldest active reader */
#define	WT_STAT_CONN_TXN_TIMESTAMP_OLDEST_ACTIVE_READ	1469
/*! transaction: transaction sync calls */
#define	WT_STAT_CONN_TXN_SYNC				1470
/*! transaction: transactions committed */
#define	WT_STAT_CONN_TXN_COMMIT				1471
/*! transaction: transactions rolled back */
#define	WT_STAT_CONN_TXN_ROLLBACK			1472
/*! transaction: update conflicts */
#define	WT_STAT_CONN_TXN_UPDATE_CONFLICT		1473

/*!
 * @}
 * @name Statistics for data sources
 * @anchor statistics_dsrc
 * @{
 */
/*! LSM: bloom filter false positives */
#define	WT_STAT_DSRC_BLOOM_FALSE_POSITIVE		2000
/*! LSM: bloom filter hits */
#define	WT_STAT_DSRC_BLOOM_HIT				2001
/*! LSM: bloom filter misses */
#define	WT_STAT_DSRC_BLOOM_MISS				2002
/*! LSM: bloom filter pages evicted from cache */
#define	WT_STAT_DSRC_BLOOM_PAGE_EVICT			2003
/*! LSM: bloom filter pages read into cache */
#define	WT_STAT_DSRC_BLOOM_PAGE_READ			2004
/*! LSM: bloom filters in the LSM tree */
#define	WT_STAT_DSRC_BLOOM_COUNT			2005
/*! LSM: chunks in the LSM tree */
#define	WT_STAT_DSRC_LSM_CHUNK_COUNT			2006
/*! LSM: highest merge generation in the LSM tree */
#define	WT_STAT_DSRC_LSM_GENERATION_MAX			2007
/*!
 * LSM: queries that could have benefited from a Bloom filter that did
 * not exist
 */
#define	WT_STAT_DSRC_LSM_LOOKUP_NO_BLOOM		2008
/*! LSM: sleep for LSM checkpoint throttle */
#define	WT_STAT_DSRC_LSM_CHECKPOINT_THROTTLE		2009
/*! LSM: sleep for LSM merge throttle */
#define	WT_STAT_DSRC_LSM_MERGE_THROTTLE			2010
/*! LSM: total size of bloom filters */
#define	WT_STAT_DSRC_BLOOM_SIZE				2011
/*! block-manager: allocations requiring file extension */
#define	WT_STAT_DSRC_BLOCK_EXTENSION			2012
/*! block-manager: blocks allocated */
#define	WT_STAT_DSRC_BLOCK_ALLOC			2013
/*! block-manager: blocks freed */
#define	WT_STAT_DSRC_BLOCK_FREE				2014
/*! block-manager: checkpoint size */
#define	WT_STAT_DSRC_BLOCK_CHECKPOINT_SIZE		2015
/*! block-manager: file allocation unit size */
#define	WT_STAT_DSRC_ALLOCATION_SIZE			2016
/*! block-manager: file bytes available for reuse */
#define	WT_STAT_DSRC_BLOCK_REUSE_BYTES			2017
/*! block-manager: file magic number */
#define	WT_STAT_DSRC_BLOCK_MAGIC			2018
/*! block-manager: file major version number */
#define	WT_STAT_DSRC_BLOCK_MAJOR			2019
/*! block-manager: file size in bytes */
#define	WT_STAT_DSRC_BLOCK_SIZE				2020
/*! block-manager: minor version number */
#define	WT_STAT_DSRC_BLOCK_MINOR			2021
/*! btree: btree checkpoint generation */
#define	WT_STAT_DSRC_BTREE_CHECKPOINT_GENERATION	2022
/*!
 * btree: column-store fixed-size leaf pages, only reported if tree_walk
 * or all statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_COLUMN_FIX			2023
/*!
 * btree: column-store internal pages, only reported if tree_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_COLUMN_INTERNAL		2024
/*!
 * btree: column-store variable-size RLE encoded values, only reported if
 * tree_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_COLUMN_RLE			2025
/*!
 * btree: column-store variable-size deleted values, only reported if
 * tree_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_COLUMN_DELETED		2026
/*!
 * btree: column-store variable-size leaf pages, only reported if
 * tree_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_COLUMN_VARIABLE		2027
/*! btree: fixed-record size */
#define	WT_STAT_DSRC_BTREE_FIXED_LEN			2028
/*! btree: maximum internal page key size */
#define	WT_STAT_DSRC_BTREE_MAXINTLKEY			2029
/*! btree: maximum internal page size */
#define	WT_STAT_DSRC_BTREE_MAXINTLPAGE			2030
/*! btree: maximum leaf page key size */
#define	WT_STAT_DSRC_BTREE_MAXLEAFKEY			2031
/*! btree: maximum leaf page size */
#define	WT_STAT_DSRC_BTREE_MAXLEAFPAGE			2032
/*! btree: maximum leaf page value size */
#define	WT_STAT_DSRC_BTREE_MAXLEAFVALUE			2033
/*! btree: maximum tree depth */
#define	WT_STAT_DSRC_BTREE_MAXIMUM_DEPTH		2034
/*!
 * btree: number of key/value pairs, only reported if tree_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_ENTRIES			2035
/*!
 * btree: overflow pages, only reported if tree_walk or all statistics
 * are enabled
 */
#define	WT_STAT_DSRC_BTREE_OVERFLOW			2036
/*! btree: pages rewritten by compaction */
#define	WT_STAT_DSRC_BTREE_COMPACT_REWRITE		2037
/*!
 * btree: row-store empty values, only reported if tree_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_ROW_EMPTY_VALUES		2038
/*!
 * btree: row-store internal pages, only reported if tree_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_ROW_INTERNAL			2039
/*!
 * btree: row-store leaf pages, only reported if tree_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_BTREE_ROW_LEAF			2040
/*! cache: bytes currently in the cache */
#define	WT_STAT_DSRC_CACHE_BYTES_INUSE			2041
/*! cache: bytes dirty in the cache cumulative */
#define	WT_STAT_DSRC_CACHE_BYTES_DIRTY_TOTAL		2042
/*! cache: bytes read into cache */
#define	WT_STAT_DSRC_CACHE_BYTES_READ			2043
/*! cache: bytes written from cache */
#define	WT_STAT_DSRC_CACHE_BYTES_WRITE			2044
/*! cache: checkpoint blocked page eviction */
#define	WT_STAT_DSRC_CACHE_EVICTION_CHECKPOINT		2045
/*! cache: data source pages selected for eviction unable to be evicted */
#define	WT_STAT_DSRC_CACHE_EVICTION_FAIL		2046
/*! cache: eviction walk passes of a file */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALK_PASSES		2047
/*! cache: eviction walk target pages histogram - 0-9 */
#define	WT_STAT_DSRC_CACHE_EVICTION_TARGET_PAGE_LT10	2048
/*! cache: eviction walk target pages histogram - 10-31 */
#define	WT_STAT_DSRC_CACHE_EVICTION_TARGET_PAGE_LT32	2049
/*! cache: eviction walk target pages histogram - 128 and higher */
#define	WT_STAT_DSRC_CACHE_EVICTION_TARGET_PAGE_GE128	2050
/*! cache: eviction walk target pages histogram - 32-63 */
#define	WT_STAT_DSRC_CACHE_EVICTION_TARGET_PAGE_LT64	2051
/*! cache: eviction walk target pages histogram - 64-128 */
#define	WT_STAT_DSRC_CACHE_EVICTION_TARGET_PAGE_LT128	2052
/*! cache: eviction walks abandoned */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALKS_ABANDONED	2053
/*! cache: eviction walks gave up because they restarted their walk twice */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALKS_STOPPED	2054
/*!
 * cache: eviction walks gave up because they saw too many pages and
 * found no candidates
 */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALKS_GAVE_UP_NO_TARGETS	2055
/*!
 * cache: eviction walks gave up because they saw too many pages and
 * found too few candidates
 */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALKS_GAVE_UP_RATIO	2056
/*! cache: eviction walks reached end of tree */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALKS_ENDED		2057
/*! cache: eviction walks started from root of tree */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALK_FROM_ROOT	2058
/*! cache: eviction walks started from saved location in tree */
#define	WT_STAT_DSRC_CACHE_EVICTION_WALK_SAVED_POS	2059
/*! cache: hazard pointer blocked page eviction */
#define	WT_STAT_DSRC_CACHE_EVICTION_HAZARD		2060
/*! cache: history store table reads */
#define	WT_STAT_DSRC_CACHE_HS_READ			2061
/*! cache: in-memory page passed criteria to be split */
#define	WT_STAT_DSRC_CACHE_INMEM_SPLITTABLE		2062
/*! cache: in-memory page splits */
#define	WT_STAT_DSRC_CACHE_INMEM_SPLIT			2063
/*! cache: internal pages evicted */
#define	WT_STAT_DSRC_CACHE_EVICTION_INTERNAL		2064
/*! cache: internal pages split during eviction */
#define	WT_STAT_DSRC_CACHE_EVICTION_SPLIT_INTERNAL	2065
/*! cache: leaf pages split during eviction */
#define	WT_STAT_DSRC_CACHE_EVICTION_SPLIT_LEAF		2066
/*! cache: modified pages evicted */
#define	WT_STAT_DSRC_CACHE_EVICTION_DIRTY		2067
/*! cache: overflow pages read into cache */
#define	WT_STAT_DSRC_CACHE_READ_OVERFLOW		2068
/*! cache: page split during eviction deepened the tree */
#define	WT_STAT_DSRC_CACHE_EVICTION_DEEPEN		2069
/*! cache: page written requiring history store records */
#define	WT_STAT_DSRC_CACHE_WRITE_HS			2070
/*! cache: pages read into cache */
#define	WT_STAT_DSRC_CACHE_READ				2071
/*! cache: pages read into cache after truncate */
#define	WT_STAT_DSRC_CACHE_READ_DELETED			2072
/*! cache: pages read into cache after truncate in prepare state */
#define	WT_STAT_DSRC_CACHE_READ_DELETED_PREPARED	2073
/*! cache: pages requested from the cache */
#define	WT_STAT_DSRC_CACHE_PAGES_REQUESTED		2074
/*! cache: pages seen by eviction walk */
#define	WT_STAT_DSRC_CACHE_EVICTION_PAGES_SEEN		2075
/*! cache: pages written from cache */
#define	WT_STAT_DSRC_CACHE_WRITE			2076
/*! cache: pages written requiring in-memory restoration */
#define	WT_STAT_DSRC_CACHE_WRITE_RESTORE		2077
/*! cache: tracked dirty bytes in the cache */
#define	WT_STAT_DSRC_CACHE_BYTES_DIRTY			2078
/*! cache: unmodified pages evicted */
#define	WT_STAT_DSRC_CACHE_EVICTION_CLEAN		2079
/*!
 * cache_walk: Average difference between current eviction generation
 * when the page was last considered, only reported if cache_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_GEN_AVG_GAP		2080
/*!
 * cache_walk: Average on-disk page image size seen, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_AVG_WRITTEN_SIZE	2081
/*!
 * cache_walk: Average time in cache for pages that have been visited by
 * the eviction server, only reported if cache_walk or all statistics are
 * enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_AVG_VISITED_AGE	2082
/*!
 * cache_walk: Average time in cache for pages that have not been visited
 * by the eviction server, only reported if cache_walk or all statistics
 * are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_AVG_UNVISITED_AGE	2083
/*!
 * cache_walk: Clean pages currently in cache, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_PAGES_CLEAN		2084
/*!
 * cache_walk: Current eviction generation, only reported if cache_walk
 * or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_GEN_CURRENT		2085
/*!
 * cache_walk: Dirty pages currently in cache, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_PAGES_DIRTY		2086
/*!
 * cache_walk: Entries in the root page, only reported if cache_walk or
 * all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_ROOT_ENTRIES		2087
/*!
 * cache_walk: Internal pages currently in cache, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_PAGES_INTERNAL		2088
/*!
 * cache_walk: Leaf pages currently in cache, only reported if cache_walk
 * or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_PAGES_LEAF		2089
/*!
 * cache_walk: Maximum difference between current eviction generation
 * when the page was last considered, only reported if cache_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_GEN_MAX_GAP		2090
/*!
 * cache_walk: Maximum page size seen, only reported if cache_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_MAX_PAGESIZE		2091
/*!
 * cache_walk: Minimum on-disk page image size seen, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_MIN_WRITTEN_SIZE	2092
/*!
 * cache_walk: Number of pages never visited by eviction server, only
 * reported if cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_UNVISITED_COUNT	2093
/*!
 * cache_walk: On-disk page image sizes smaller than a single allocation
 * unit, only reported if cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_SMALLER_ALLOC_SIZE	2094
/*!
 * cache_walk: Pages created in memory and never written, only reported
 * if cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_MEMORY			2095
/*!
 * cache_walk: Pages currently queued for eviction, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_QUEUED			2096
/*!
 * cache_walk: Pages that could not be queued for eviction, only reported
 * if cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_NOT_QUEUEABLE		2097
/*!
 * cache_walk: Refs skipped during cache traversal, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_REFS_SKIPPED		2098
/*!
 * cache_walk: Size of the root page, only reported if cache_walk or all
 * statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_ROOT_SIZE		2099
/*!
 * cache_walk: Total number of pages currently in cache, only reported if
 * cache_walk or all statistics are enabled
 */
#define	WT_STAT_DSRC_CACHE_STATE_PAGES			2100
/*! checkpoint-cleanup: pages added for eviction */
#define	WT_STAT_DSRC_CC_PAGES_EVICT			2101
/*! checkpoint-cleanup: pages removed */
#define	WT_STAT_DSRC_CC_PAGES_REMOVED			2102
/*! checkpoint-cleanup: pages skipped during tree walk */
#define	WT_STAT_DSRC_CC_PAGES_WALK_SKIPPED		2103
/*! checkpoint-cleanup: pages visited */
#define	WT_STAT_DSRC_CC_PAGES_VISITED			2104
/*!
 * compression: compressed page maximum internal page size prior to
 * compression
 */
#define	WT_STAT_DSRC_COMPRESS_PRECOMP_INTL_MAX_PAGE_SIZE	2105
/*!
 * compression: compressed page maximum leaf page size prior to
 * compression
 */
#define	WT_STAT_DSRC_COMPRESS_PRECOMP_LEAF_MAX_PAGE_SIZE	2106
/*! compression: compressed pages read */
#define	WT_STAT_DSRC_COMPRESS_READ			2107
/*! compression: compressed pages written */
#define	WT_STAT_DSRC_COMPRESS_WRITE			2108
/*! compression: page written failed to compress */
#define	WT_STAT_DSRC_COMPRESS_WRITE_FAIL		2109
/*! compression: page written was too small to compress */
#define	WT_STAT_DSRC_COMPRESS_WRITE_TOO_SMALL		2110
/*! cursor: Total number of entries skipped by cursor next calls */
#define	WT_STAT_DSRC_CURSOR_NEXT_SKIP_TOTAL		2111
/*! cursor: Total number of entries skipped by cursor prev calls */
#define	WT_STAT_DSRC_CURSOR_PREV_SKIP_TOTAL		2112
/*!
 * cursor: Total number of entries skipped to position the history store
 * cursor
 */
#define	WT_STAT_DSRC_CURSOR_SKIP_HS_CUR_POSITION	2113
/*! cursor: bulk loaded cursor insert calls */
#define	WT_STAT_DSRC_CURSOR_INSERT_BULK			2114
/*! cursor: cache cursors reuse count */
#define	WT_STAT_DSRC_CURSOR_REOPEN			2115
/*! cursor: close calls that result in cache */
#define	WT_STAT_DSRC_CURSOR_CACHE			2116
/*! cursor: create calls */
#define	WT_STAT_DSRC_CURSOR_CREATE			2117
/*!
 * cursor: cursor next calls that skip greater than or equal to 100
 * entries
 */
#define	WT_STAT_DSRC_CURSOR_NEXT_SKIP_GE_100		2118
/*! cursor: cursor next calls that skip less than 100 entries */
#define	WT_STAT_DSRC_CURSOR_NEXT_SKIP_LT_100		2119
/*!
 * cursor: cursor prev calls that skip greater than or equal to 100
 * entries
 */
#define	WT_STAT_DSRC_CURSOR_PREV_SKIP_GE_100		2120
/*! cursor: cursor prev calls that skip less than 100 entries */
#define	WT_STAT_DSRC_CURSOR_PREV_SKIP_LT_100		2121
/*! cursor: insert calls */
#define	WT_STAT_DSRC_CURSOR_INSERT			2122
/*! cursor: insert key and value bytes */
#define	WT_STAT_DSRC_CURSOR_INSERT_BYTES		2123
/*! cursor: modify */
#define	WT_STAT_DSRC_CURSOR_MODIFY			2124
/*! cursor: modify key and value bytes affected */
#define	WT_STAT_DSRC_CURSOR_MODIFY_BYTES		2125
/*! cursor: modify value bytes modified */
#define	WT_STAT_DSRC_CURSOR_MODIFY_BYTES_TOUCH		2126
/*! cursor: next calls */
#define	WT_STAT_DSRC_CURSOR_NEXT			2127
/*! cursor: open cursor count */
#define	WT_STAT_DSRC_CURSOR_OPEN_COUNT			2128
/*! cursor: operation restarted */
#define	WT_STAT_DSRC_CURSOR_RESTART			2129
/*! cursor: prev calls */
#define	WT_STAT_DSRC_CURSOR_PREV			2130
/*! cursor: remove calls */
#define	WT_STAT_DSRC_CURSOR_REMOVE			2131
/*! cursor: remove key bytes removed */
#define	WT_STAT_DSRC_CURSOR_REMOVE_BYTES		2132
/*! cursor: reserve calls */
#define	WT_STAT_DSRC_CURSOR_RESERVE			2133
/*! cursor: reset calls */
#define	WT_STAT_DSRC_CURSOR_RESET			2134
/*! cursor: search calls */
#define	WT_STAT_DSRC_CURSOR_SEARCH			2135
/*! cursor: search history store calls */
#define	WT_STAT_DSRC_CURSOR_SEARCH_HS			2136
/*! cursor: search near calls */
#define	WT_STAT_DSRC_CURSOR_SEARCH_NEAR			2137
/*! cursor: truncate calls */
#define	WT_STAT_DSRC_CURSOR_TRUNCATE			2138
/*! cursor: update calls */
#define	WT_STAT_DSRC_CURSOR_UPDATE			2139
/*! cursor: update key and value bytes */
#define	WT_STAT_DSRC_CURSOR_UPDATE_BYTES		2140
/*! cursor: update value size change */
#define	WT_STAT_DSRC_CURSOR_UPDATE_BYTES_CHANGED	2141
/*! reconciliation: approximate byte size of timestamps in pages written */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_BYTES_TS		2142
/*!
 * reconciliation: approximate byte size of transaction IDs in pages
 * written
 */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_BYTES_TXN		2143
/*! reconciliation: dictionary matches */
#define	WT_STAT_DSRC_REC_DICTIONARY			2144
/*! reconciliation: fast-path pages deleted */
#define	WT_STAT_DSRC_REC_PAGE_DELETE_FAST		2145
/*!
 * reconciliation: internal page key bytes discarded using suffix
 * compression
 */
#define	WT_STAT_DSRC_REC_SUFFIX_COMPRESSION		2146
/*! reconciliation: internal page multi-block writes */
#define	WT_STAT_DSRC_REC_MULTIBLOCK_INTERNAL		2147
/*! reconciliation: internal-page overflow keys */
#define	WT_STAT_DSRC_REC_OVERFLOW_KEY_INTERNAL		2148
/*! reconciliation: leaf page key bytes discarded using prefix compression */
#define	WT_STAT_DSRC_REC_PREFIX_COMPRESSION		2149
/*! reconciliation: leaf page multi-block writes */
#define	WT_STAT_DSRC_REC_MULTIBLOCK_LEAF		2150
/*! reconciliation: leaf-page overflow keys */
#define	WT_STAT_DSRC_REC_OVERFLOW_KEY_LEAF		2151
/*! reconciliation: maximum blocks required for a page */
#define	WT_STAT_DSRC_REC_MULTIBLOCK_MAX			2152
/*! reconciliation: overflow values written */
#define	WT_STAT_DSRC_REC_OVERFLOW_VALUE			2153
/*! reconciliation: page checksum matches */
#define	WT_STAT_DSRC_REC_PAGE_MATCH			2154
/*! reconciliation: page reconciliation calls */
#define	WT_STAT_DSRC_REC_PAGES				2155
/*! reconciliation: page reconciliation calls for eviction */
#define	WT_STAT_DSRC_REC_PAGES_EVICTION			2156
/*! reconciliation: pages deleted */
#define	WT_STAT_DSRC_REC_PAGE_DELETE			2157
/*!
 * reconciliation: pages written including an aggregated newest start
 * durable timestamp
 */
#define	WT_STAT_DSRC_REC_TIME_AGGR_NEWEST_START_DURABLE_TS	2158
/*!
 * reconciliation: pages written including an aggregated newest stop
 * durable timestamp
 */
#define	WT_STAT_DSRC_REC_TIME_AGGR_NEWEST_STOP_DURABLE_TS	2159
/*!
 * reconciliation: pages written including an aggregated newest stop
 * timestamp
 */
#define	WT_STAT_DSRC_REC_TIME_AGGR_NEWEST_STOP_TS	2160
/*!
 * reconciliation: pages written including an aggregated newest stop
 * transaction ID
 */
#define	WT_STAT_DSRC_REC_TIME_AGGR_NEWEST_STOP_TXN	2161
/*!
 * reconciliation: pages written including an aggregated oldest start
 * timestamp
 */
#define	WT_STAT_DSRC_REC_TIME_AGGR_OLDEST_START_TS	2162
/*!
 * reconciliation: pages written including an aggregated oldest start
 * transaction ID
 */
#define	WT_STAT_DSRC_REC_TIME_AGGR_OLDEST_START_TXN	2163
/*! reconciliation: pages written including an aggregated prepare */
#define	WT_STAT_DSRC_REC_TIME_AGGR_PREPARED		2164
/*! reconciliation: pages written including at least one prepare */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PAGES_PREPARED	2165
/*!
 * reconciliation: pages written including at least one start durable
 * timestamp
 */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PAGES_DURABLE_START_TS	2166
/*! reconciliation: pages written including at least one start timestamp */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PAGES_START_TS	2167
/*!
 * reconciliation: pages written including at least one start transaction
 * ID
 */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PAGES_START_TXN	2168
/*!
 * reconciliation: pages written including at least one stop durable
 * timestamp
 */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PAGES_DURABLE_STOP_TS	2169
/*! reconciliation: pages written including at least one stop timestamp */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PAGES_STOP_TS	2170
/*!
 * reconciliation: pages written including at least one stop transaction
 * ID
 */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PAGES_STOP_TXN	2171
/*! reconciliation: records written including a prepare */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_PREPARED		2172
/*! reconciliation: records written including a start durable timestamp */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_DURABLE_START_TS	2173
/*! reconciliation: records written including a start timestamp */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_START_TS		2174
/*! reconciliation: records written including a start transaction ID */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_START_TXN		2175
/*! reconciliation: records written including a stop durable timestamp */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_DURABLE_STOP_TS	2176
/*! reconciliation: records written including a stop timestamp */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_STOP_TS		2177
/*! reconciliation: records written including a stop transaction ID */
#define	WT_STAT_DSRC_REC_TIME_WINDOW_STOP_TXN		2178
/*! session: object compaction */
#define	WT_STAT_DSRC_SESSION_COMPACT			2179
/*! transaction: update conflicts */
#define	WT_STAT_DSRC_TXN_UPDATE_CONFLICT		2180

/*!
 * @}
 * @name Statistics for join cursors
 * @anchor statistics_join
 * @{
 */
/*! : accesses to the main table */
#define	WT_STAT_JOIN_MAIN_ACCESS			3000
/*! : bloom filter false positives */
#define	WT_STAT_JOIN_BLOOM_FALSE_POSITIVE		3001
/*! : checks that conditions of membership are satisfied */
#define	WT_STAT_JOIN_MEMBERSHIP_CHECK			3002
/*! : items inserted into a bloom filter */
#define	WT_STAT_JOIN_BLOOM_INSERT			3003
/*! : items iterated */
#define	WT_STAT_JOIN_ITERATED				3004

/*!
 * @}
 * @name Statistics for session
 * @anchor statistics_session
 * @{
 */
/*! session: bytes read into cache */
#define	WT_STAT_SESSION_BYTES_READ			4000
/*! session: bytes written from cache */
#define	WT_STAT_SESSION_BYTES_WRITE			4001
/*! session: dhandle lock wait time (usecs) */
#define	WT_STAT_SESSION_LOCK_DHANDLE_WAIT		4002
/*! session: page read from disk to cache time (usecs) */
#define	WT_STAT_SESSION_READ_TIME			4003
/*! session: page write from cache to disk time (usecs) */
#define	WT_STAT_SESSION_WRITE_TIME			4004
/*! session: schema lock wait time (usecs) */
#define	WT_STAT_SESSION_LOCK_SCHEMA_WAIT		4005
/*! session: time waiting for cache (usecs) */
#define	WT_STAT_SESSION_CACHE_TIME			4006
/*! @} */
/*
 * Statistics section: END
 * DO NOT EDIT: automatically built by dist/stat.py.
 */
/*! @} */

#undef __F

#if defined(__cplusplus)
}
#endif
#endif /* __WIREDTIGER_H_ */
