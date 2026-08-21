/*
 * wt_btree_bpf: XRP resubmission function for WiredTiger row-store B-tree
 * point lookups.
 *
 * The program walks internal pages exactly like the LSM version, but instead
 * of returning the traversed pages it searches the leaf page in kernel space
 * and returns only the lookup result through the scratch buffer.
 *
 * Supported on-disk subset: row-store pages, 512-byte blocks, plain and short
 * keys and values, no prefix compression, no overflow items, no value
 * dictionary, no RLE, no prepared updates.
 */
#include <linux/bpf.h>
#include <asm-generic/types.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define __inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, value, n) __builtin_memset((dest), (value), (n))

/*
 * Type definitions for ebpf
 */
#define uint64_t __u64
#define uint32_t __u32
#define uint8_t __u8
#define int64_t __s64
#define int32_t __s32
#define int8_t __s8
#define bool short
#define NULL 0
#define true 1
#define false 0

/*
 * Config definitions
 */
#define EBPF_BLOCK_SIZE 512
#define EBPF_MAX_DEPTH 6
#define EBPF_KEY_MAX_LEN 18
#define EBPF_VALUE_MAX_LEN 128
#define EBPF_CONTEXT_MASK 0xfff

/*
 * Error numbers
 */
#define EBPF_EINVAL 22

/*
 * Lookup states reported through the scratch buffer
 */
#define EBPF_BTREE_FOUND 0
#define EBPF_BTREE_NOTFOUND 1

/*
 * Page layout
 */
struct ebpf_page_header {
    uint64_t recno;
    uint64_t write_gen;
    uint32_t mem_size;
    union {
        uint32_t entries;
        uint32_t datalen;
    } u;
    uint8_t type;
    uint8_t flags;
    uint8_t unused;
    uint8_t version;
};
#define EBPF_PAGE_HEADER_SIZE 28
#define EBPF_BLOCK_HEADER_SIZE 12

#define EBPF_PAGE_ROW_INT 6
#define EBPF_PAGE_ROW_LEAF 7

/*
 * Cell types & macros
 */
#define EBPF_CELL_KEY_SHORT 0x01
#define EBPF_CELL_KEY_SHORT_PFX 0x02
#define EBPF_CELL_VALUE_SHORT 0x03
#define EBPF_CELL_SHORT_TYPE(v) ((v)&0x03U)

#define EBPF_CELL_SHORT_MAX 63
#define EBPF_CELL_SHORT_SHIFT 2
#define EBPF_CELL_SIZE_ADJUST (EBPF_CELL_SHORT_MAX + 1)

#define EBPF_CELL_64V 0x04
#define EBPF_CELL_SECOND_DESC 0x08

#define EBPF_CELL_ADDR_DEL (0)
#define EBPF_CELL_ADDR_INT (1 << 4)
#define EBPF_CELL_ADDR_LEAF (2 << 4)
#define EBPF_CELL_ADDR_LEAF_NO (3 << 4)
#define EBPF_CELL_DEL (4 << 4)
#define EBPF_CELL_KEY (5 << 4)
#define EBPF_CELL_KEY_OVFL (6 << 4)
#define EBPF_CELL_KEY_PFX (7 << 4)
#define EBPF_CELL_VALUE (8 << 4)
#define EBPF_CELL_VALUE_COPY (9 << 4)
#define EBPF_CELL_VALUE_OVFL (10 << 4)

#define EBPF_CELL_TYPE_MASK (0x0fU << 4)
#define EBPF_CELL_TYPE(v) ((v)&EBPF_CELL_TYPE_MASK)

/*
 * Validity window flags in the second descriptor byte
 */
#define EBPF_TW_PREPARE 0x01
#define EBPF_TW_TS_DURABLE_START 0x02
#define EBPF_TW_TS_DURABLE_STOP 0x04
#define EBPF_TW_TS_START 0x08
#define EBPF_TW_TS_STOP 0x10
#define EBPF_TW_TXN_START 0x20
#define EBPF_TW_TXN_STOP 0x40

/*
 * Variable-sized unpacking for unsigned integers
 */
#define EBPF_POS_1BYTE_MARKER (uint8_t)0x80
#define EBPF_POS_2BYTE_MARKER (uint8_t)0xc0
#define EBPF_POS_MULTI_MARKER (uint8_t)0xe0
#define EBPF_POS_1BYTE_MAX ((1 << 6) - 1)
#define EBPF_POS_2BYTE_MAX ((1 << 13) + EBPF_POS_1BYTE_MAX)

struct wt_btree_scratch {
    uint64_t key_size;
    char key[EBPF_KEY_MAX_LEN];

    int32_t state;
    int32_t nr_page;
    uint64_t value_size;
    char value[EBPF_VALUE_MAX_LEN];
};

/* Extract bits <start> to <end> from a value (counting from LSB == 0). */
#define GET_BITS(x, start, end) (((uint64_t)(x) & ((1U << (start)) - 1U)) >> (end))

__noinline int ebpf_lex_compare(struct bpf_xrp *context, uint64_t key_offset_1, uint64_t key_len_1,
                                uint64_t key_offset_2, uint64_t key_len_2) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t *k_base = (uint8_t *) context->scratch;
    uint8_t b1, b2;
    uint64_t len = (key_len_1 > key_len_2) ? key_len_2 : key_len_1;
    uint64_t max_len = EBPF_KEY_MAX_LEN;
    for (; len > 0 && max_len > 0; --len, --max_len, ++key_offset_1, ++key_offset_2) {
        b1 = *(k_base + (key_offset_1 & EBPF_CONTEXT_MASK));
        b2 = *(p_base + (key_offset_2 & EBPF_CONTEXT_MASK));
        if (b1 != b2)
            return (b1 < b2 ? -1 : 1);
    }
    return ((key_len_1 == key_len_2) ? 0 : (key_len_1 < key_len_2) ? -1 : 1);
}

__noinline int ebpf_unpack_posint(struct bpf_xrp *context, uint64_t p_offset,
                                  uint64_t *retp, uint64_t *p_delta) {
    uint64_t x = 0;
    uint8_t max_len = 15;  /* max_len is set to pass the ebpf verifier */
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t b;
    uint8_t len;

    if (retp == NULL || p_delta == NULL)
        return -EBPF_EINVAL;

    /* There are four length bits in the first byte. */
    b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
    len = (b & 0xf);
    ++p_offset;
    ++(*p_delta);

    for (; len > 0 && max_len > 0; --len, --max_len) {
        b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
        x = (x << 8) | b;
        ++p_offset;
        ++(*p_delta);
    }

    *retp = x;
    return 0;
}

__noinline int ebpf_vunpack_uint(struct bpf_xrp *context, uint64_t p_offset,
                                 uint64_t *xp, uint64_t *p_delta) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t b;
    int ret;

    if (xp == NULL || p_delta == NULL)
        return -EBPF_EINVAL;

    b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
    switch (b & 0xf0) {
    case EBPF_POS_1BYTE_MARKER:
    case EBPF_POS_1BYTE_MARKER | 0x10:
    case EBPF_POS_1BYTE_MARKER | 0x20:
    case EBPF_POS_1BYTE_MARKER | 0x30:
        /* higher 2 bits of the first byte is 10 */
        *xp = GET_BITS(b, 6, 0);
        ++p_offset;
        ++(*p_delta);
        break;
    case EBPF_POS_2BYTE_MARKER:
    case EBPF_POS_2BYTE_MARKER | 0x10:
        /* higher 3 bits of the first byte is 110 */
        *xp = GET_BITS(b, 5, 0) << 8;
        ++p_offset;
        ++(*p_delta);
        b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
        *xp |= b;
        *xp += EBPF_POS_1BYTE_MAX + 1;
        ++(*p_delta);
        ++p_offset;
        break;
    case EBPF_POS_MULTI_MARKER:
        /* higher 4 bits of the first byte is 1110 */
        ret = ebpf_unpack_posint(context, p_offset, xp, p_delta);
        if (ret != 0) {
            return ret;
        }
        *xp += EBPF_POS_2BYTE_MAX + 1;
        return 0;
    default:
        return -EBPF_EINVAL;
    }

    return 0;
}

__noinline int ebpf_addr_to_offset(struct bpf_xrp *context, uint64_t p_offset,
                                   uint64_t *offset, uint64_t *size) {
    int ret = 0;
    uint64_t p_delta = 0;
    uint64_t raw_offset = 0, raw_size = 0, raw_checksum = 0;

    if (offset == NULL || size == NULL)
        return -EBPF_EINVAL;

    ret = ebpf_vunpack_uint(context, p_offset, &raw_offset, &p_delta);
    if (ret < 0) {
        return ret;
    }
    p_offset += p_delta;
    p_delta = 0;

    ret = ebpf_vunpack_uint(context, p_offset, &raw_size, &p_delta);
    if (ret < 0) {
        return ret;
    }
    p_offset += p_delta;
    p_delta = 0;

    ret = ebpf_vunpack_uint(context, p_offset, &raw_checksum, &p_delta);  /* checksum is not used */
    if (ret < 0) {
        return ret;
    }

    if (raw_size == 0) {
        *offset = 0;
        *size = 0;
    } else {
        /* assumption: allocation size is EBPF_BLOCK_SIZE */
        *offset = EBPF_BLOCK_SIZE * (raw_offset + 1);
        *size = EBPF_BLOCK_SIZE * raw_size;
    }
    return 0;
}

static __inline int ebpf_get_cell_type(uint8_t cell_desc) {
    return EBPF_CELL_SHORT_TYPE(cell_desc) ? EBPF_CELL_SHORT_TYPE(cell_desc) : EBPF_CELL_TYPE(cell_desc);
}

__noinline int ebpf_parse_cell_addr(struct bpf_xrp *context, uint64_t p_offset,
                                    uint64_t *offset, uint64_t *size, uint64_t *p_delta) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t b;
    uint64_t local_p_delta = 0;
    uint8_t cell_desc, flags;
    uint64_t addr_len = 0;
    int ret;

    if (offset == NULL || size == NULL || p_delta == NULL)
        return -EBPF_EINVAL;

    /* read the first cell descriptor byte (cell type, RLE count) */
    b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
    cell_desc = b;
    if ((ebpf_get_cell_type(cell_desc) != EBPF_CELL_ADDR_INT
         && ebpf_get_cell_type(cell_desc) != EBPF_CELL_ADDR_LEAF
         && ebpf_get_cell_type(cell_desc) != EBPF_CELL_ADDR_LEAF_NO)
        || ((cell_desc & EBPF_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    ++p_offset;
    ++(*p_delta);

    /* read the second cell descriptor byte (if present) */
    if ((cell_desc & EBPF_CELL_SECOND_DESC) != 0) {
        b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
        flags = b;
        ++p_offset;
        ++(*p_delta);
        if (flags != 0) {
            return -EBPF_EINVAL;
        }
    }

    /* the cell is followed by data length and a chunk of data */
    ret = ebpf_vunpack_uint(context, p_offset, &addr_len, &local_p_delta);
    if (ret != 0) {
        return ret;
    }
    p_offset += local_p_delta;
    (*p_delta) += local_p_delta;
    local_p_delta = 0;

    /* convert addr to file offset */
    ret = ebpf_addr_to_offset(context, p_offset, offset, size);
    if (ret != 0) {
        return ret;
    }

    (*p_delta) += addr_len;
    return 0;
}

__noinline int ebpf_parse_cell_key(struct bpf_xrp *context, uint64_t p_offset,
                                   uint64_t *key_offset, uint64_t *key_size, uint64_t *p_delta) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t b;
    uint64_t local_p_delta = 0;
    uint64_t data_len = 0;
    int ret;

    if (key_offset == NULL || key_size == NULL || p_delta == NULL)
        return -EBPF_EINVAL;
    (*key_offset) = 0;

    /* read the first cell descriptor byte (cell type, RLE count) */
    b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
    if ((ebpf_get_cell_type(b) != EBPF_CELL_KEY)
        || ((b & EBPF_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    ++p_offset;
    ++(*p_delta);
    ++(*key_offset);

    /* key cell does not have the second descriptor byte */

    /* the cell is followed by data length and a chunk of data */
    ret = ebpf_vunpack_uint(context, p_offset, &data_len, &local_p_delta);
    if (ret != 0) {
        return ret;
    }
    data_len += EBPF_CELL_SIZE_ADJUST;
    p_offset += local_p_delta;
    (*p_delta) += local_p_delta;
    (*key_offset) += local_p_delta;
    local_p_delta = 0;

    *key_size = data_len;
    (*p_delta) += data_len;
    return 0;
}

__noinline int ebpf_parse_cell_short_key(struct bpf_xrp *context, uint64_t p_offset,
                                         uint64_t *key_offset, uint64_t *key_size, uint64_t *p_delta) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t b;
    uint64_t data_len;

    if (key_offset == NULL || key_size == NULL || p_delta == NULL)
        return -EBPF_EINVAL;
    (*key_offset) = 0;

    /* read the first cell descriptor byte */
    b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
    if (ebpf_get_cell_type(b) != EBPF_CELL_KEY_SHORT) {
        return -EBPF_EINVAL;
    }
    data_len = (b) >> EBPF_CELL_SHORT_SHIFT;
    *key_size = data_len;

    ++p_offset;
    ++(*p_delta);
    ++(*key_offset);

    (*p_delta) += data_len;
    return 0;
}

/*
 * Parse a VALUE or VALUE_SHORT cell. An optional validity window after the
 * descriptor byte is skipped, prepared updates are rejected.
 */
__noinline int ebpf_parse_cell_value(struct bpf_xrp *context, uint64_t p_offset,
                                     uint64_t *value_offset, uint64_t *value_size, uint64_t *p_delta) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t b, cell_desc, flags;
    uint64_t local_p_delta = 0;
    uint64_t data_len = 0;
    uint64_t unused = 0;
    int ret;

    if (value_offset == NULL || value_size == NULL || p_delta == NULL)
        return -EBPF_EINVAL;
    (*value_offset) = 0;

    b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
    cell_desc = b;

    if (ebpf_get_cell_type(cell_desc) == EBPF_CELL_VALUE_SHORT) {
        data_len = cell_desc >> EBPF_CELL_SHORT_SHIFT;
        ++p_offset;
        ++(*p_delta);
        ++(*value_offset);
        *value_size = data_len;
        (*p_delta) += data_len;
        return 0;
    }

    if (ebpf_get_cell_type(cell_desc) != EBPF_CELL_VALUE
        || ((cell_desc & EBPF_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    ++p_offset;
    ++(*p_delta);
    ++(*value_offset);

    /* skip the validity window if present */
    if ((cell_desc & EBPF_CELL_SECOND_DESC) != 0) {
        b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
        flags = b;
        ++p_offset;
        ++(*p_delta);
        ++(*value_offset);
        if ((flags & EBPF_TW_PREPARE) != 0) {
            return -EBPF_EINVAL;
        }
        if ((flags & EBPF_TW_TS_START) != 0) {
            ret = ebpf_vunpack_uint(context, p_offset, &unused, &local_p_delta);
            if (ret != 0)
                return ret;
            p_offset += local_p_delta;
            (*p_delta) += local_p_delta;
            (*value_offset) += local_p_delta;
            local_p_delta = 0;
        }
        if ((flags & EBPF_TW_TXN_START) != 0) {
            ret = ebpf_vunpack_uint(context, p_offset, &unused, &local_p_delta);
            if (ret != 0)
                return ret;
            p_offset += local_p_delta;
            (*p_delta) += local_p_delta;
            (*value_offset) += local_p_delta;
            local_p_delta = 0;
        }
        if ((flags & EBPF_TW_TS_DURABLE_START) != 0) {
            ret = ebpf_vunpack_uint(context, p_offset, &unused, &local_p_delta);
            if (ret != 0)
                return ret;
            p_offset += local_p_delta;
            (*p_delta) += local_p_delta;
            (*value_offset) += local_p_delta;
            local_p_delta = 0;
        }
        if ((flags & EBPF_TW_TS_STOP) != 0) {
            ret = ebpf_vunpack_uint(context, p_offset, &unused, &local_p_delta);
            if (ret != 0)
                return ret;
            p_offset += local_p_delta;
            (*p_delta) += local_p_delta;
            (*value_offset) += local_p_delta;
            local_p_delta = 0;
        }
        if ((flags & EBPF_TW_TXN_STOP) != 0) {
            ret = ebpf_vunpack_uint(context, p_offset, &unused, &local_p_delta);
            if (ret != 0)
                return ret;
            p_offset += local_p_delta;
            (*p_delta) += local_p_delta;
            (*value_offset) += local_p_delta;
            local_p_delta = 0;
        }
        if ((flags & EBPF_TW_TS_DURABLE_STOP) != 0) {
            ret = ebpf_vunpack_uint(context, p_offset, &unused, &local_p_delta);
            if (ret != 0)
                return ret;
            p_offset += local_p_delta;
            (*p_delta) += local_p_delta;
            (*value_offset) += local_p_delta;
            local_p_delta = 0;
        }
    }

    /* the cell is followed by data length and a chunk of data */
    ret = ebpf_vunpack_uint(context, p_offset, &data_len, &local_p_delta);
    if (ret != 0) {
        return ret;
    }
    /* the size adjustment only applies without a validity window */
    if ((cell_desc & EBPF_CELL_SECOND_DESC) == 0)
        data_len += EBPF_CELL_SIZE_ADJUST;
    p_offset += local_p_delta;
    (*p_delta) += local_p_delta;
    (*value_offset) += local_p_delta;
    local_p_delta = 0;

    *value_size = data_len;
    (*p_delta) += data_len;
    return 0;
}

__noinline int ebpf_search_int_page(struct bpf_xrp *context,
                                    uint64_t user_key_offset, uint64_t user_key_size,
                                    uint64_t *descent_offset) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t b;
    uint64_t p_offset = 0;
    uint64_t local_p_delta = 0;

    struct ebpf_page_header *header = (struct ebpf_page_header *) context->data;
    uint32_t nr_kv = header->u.entries / 2, i = 0, ii = 0;
    uint64_t prev_cell_descent_offset = 0;
    int ret = 0;

    asm volatile("r0 = 0" ::: "r0");

    if (descent_offset == NULL) {
        bpf_printk("ebpf_search_int_page: invalid arguments");
        return -EBPF_EINVAL;
    }

    /* skip page header + block header */
    p_offset += (EBPF_PAGE_HEADER_SIZE + EBPF_BLOCK_HEADER_SIZE);

    /* traverse all key value pairs */
    for (i = 0, ii = EBPF_BLOCK_SIZE; i < nr_kv && ii > 0; ++i, --ii) {
        uint64_t cell_key_offset = 0, cell_key_size = 0;
        uint64_t cell_descent_offset = 0, cell_descent_size = 0;
        int cmp = 0;

        /* parse key cell */
        b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
        switch (ebpf_get_cell_type(b)) {
        case EBPF_CELL_KEY:
            ret = ebpf_parse_cell_key(context, p_offset, &cell_key_offset, &cell_key_size, &local_p_delta);
            if (ret < 0) {
                bpf_printk("ebpf_search_int_page: ebpf_parse_cell_key failed, kv %d, ret %d", i, ret);
                return ret;
            }
            break;
        case EBPF_CELL_KEY_SHORT:
            ret = ebpf_parse_cell_short_key(context, p_offset, &cell_key_offset, &cell_key_size, &local_p_delta);
            if (ret < 0) {
                bpf_printk("ebpf_search_int_page: ebpf_parse_cell_short_key failed, kv %d ret %d", i, ret);
                return ret;
            }
            break;
        default:
            bpf_printk("ebpf_search_int_page: invalid cell type %d, kv %d", ebpf_get_cell_type(b), i);
            return -EBPF_EINVAL;
        }
        cell_key_offset += p_offset;
        p_offset += local_p_delta;
        local_p_delta = 0;

        /* parse addr cell */
        ret = ebpf_parse_cell_addr(context, p_offset, &cell_descent_offset, &cell_descent_size, &local_p_delta);
        if (ret < 0) {
            bpf_printk("ebpf_search_int_page: ebpf_parse_cell_addr failed, kv %d, ret %d", i, ret);
            return ret;
        }
        if (cell_descent_size != EBPF_BLOCK_SIZE) {
            bpf_printk("ebpf_search_int_page: descent size mismatch, expected %lld, got %lld", EBPF_BLOCK_SIZE, cell_descent_size);
            return -EBPF_EINVAL;
        }
        p_offset += local_p_delta;
        local_p_delta = 0;

        /* the 0-th key on an internal page sorts before any key */
        if (i == 0)
            cmp = 1;
        else
            cmp = ebpf_lex_compare(context, user_key_offset, user_key_size, cell_key_offset, cell_key_size);
        if (cmp == 0) {
            /* user key = cell key */
            *descent_offset = cell_descent_offset;
            return 0;
        } else if (cmp < 0) {
            /* user key < cell key */
            *descent_offset = prev_cell_descent_offset;
            return 0;
        }
        prev_cell_descent_offset = cell_descent_offset;
    }
    *descent_offset = prev_cell_descent_offset;
    return 0;
}

/*
 * Search a leaf page for an exact match and store the result in the scratch
 * buffer. Returns 0 when a verdict was reached (found or not found), negative
 * on unsupported or corrupt input.
 */
__noinline int ebpf_search_leaf_page(struct bpf_xrp *context,
                                     uint64_t user_key_offset, uint64_t user_key_size) {
    uint8_t *p_base = (uint8_t *) context->data;
    uint8_t *s_base = (uint8_t *) context->scratch;
    struct wt_btree_scratch *scratch = (struct wt_btree_scratch *) context->scratch;
    struct ebpf_page_header *header = (struct ebpf_page_header *) context->data;
    uint8_t b;
    uint64_t p_offset = 0;
    uint64_t local_p_delta = 0;
    uint32_t entries = header->u.entries, consumed = 0, ii = 0;
    uint64_t value_dst = 0;
    int cmp = 0, ret = 0, matched = 0;

    asm volatile("r0 = 0" ::: "r0");

    p_offset += (EBPF_PAGE_HEADER_SIZE + EBPF_BLOCK_HEADER_SIZE);

    for (consumed = 0, ii = EBPF_BLOCK_SIZE; consumed < entries && ii > 0; --ii) {
        uint64_t cell_key_offset = 0, cell_key_size = 0;
        uint64_t cell_value_offset = 0, cell_value_size = 0;

        b = *(p_base + (p_offset & EBPF_CONTEXT_MASK));
        switch (ebpf_get_cell_type(b)) {
        case EBPF_CELL_KEY:
        case EBPF_CELL_KEY_SHORT:
            if (matched) {
                /* the matched key has no value cell, the value is empty */
                scratch->state = EBPF_BTREE_FOUND;
                scratch->value_size = 0;
                return 0;
            }
            if (ebpf_get_cell_type(b) == EBPF_CELL_KEY)
                ret = ebpf_parse_cell_key(context, p_offset, &cell_key_offset, &cell_key_size, &local_p_delta);
            else
                ret = ebpf_parse_cell_short_key(context, p_offset, &cell_key_offset, &cell_key_size, &local_p_delta);
            if (ret < 0) {
                bpf_printk("ebpf_search_leaf_page: key parse failed, cell %d, ret %d", consumed, ret);
                return ret;
            }
            cell_key_offset += p_offset;
            p_offset += local_p_delta;
            local_p_delta = 0;
            ++consumed;

            cmp = ebpf_lex_compare(context, user_key_offset, user_key_size, cell_key_offset, cell_key_size);
            if (cmp < 0) {
                /* keys on the page are sorted, no match exists */
                scratch->state = EBPF_BTREE_NOTFOUND;
                return 0;
            }
            if (cmp == 0)
                matched = 1;
            break;
        case EBPF_CELL_VALUE:
        case EBPF_CELL_VALUE_SHORT:
            ret = ebpf_parse_cell_value(context, p_offset, &cell_value_offset, &cell_value_size, &local_p_delta);
            if (ret < 0) {
                bpf_printk("ebpf_search_leaf_page: value parse failed, cell %d, ret %d", consumed, ret);
                return ret;
            }
            cell_value_offset += p_offset;
            p_offset += local_p_delta;
            local_p_delta = 0;
            ++consumed;

            if (matched) {
                if (cell_value_size > EBPF_VALUE_MAX_LEN) {
                    bpf_printk("ebpf_search_leaf_page: value too large %lld", cell_value_size);
                    return -EBPF_EINVAL;
                }
                value_dst = offsetof(struct wt_btree_scratch, value);
                for (ii = 0; ii < EBPF_VALUE_MAX_LEN; ++ii) {
                    if (ii >= cell_value_size)
                        break;
                    *(s_base + ((value_dst + ii) & EBPF_CONTEXT_MASK)) =
                        *(p_base + ((cell_value_offset + ii) & EBPF_CONTEXT_MASK));
                }
                scratch->state = EBPF_BTREE_FOUND;
                scratch->value_size = cell_value_size;
                return 0;
            }
            break;
        default:
            bpf_printk("ebpf_search_leaf_page: unsupported cell type %d, cell %d", ebpf_get_cell_type(b), consumed);
            return -EBPF_EINVAL;
        }
    }

    if (matched) {
        /* the matched key was the last cell, the value is empty */
        scratch->state = EBPF_BTREE_FOUND;
        scratch->value_size = 0;
        return 0;
    }
    scratch->state = EBPF_BTREE_NOTFOUND;
    return 0;
}

SEC("xrp_prog")
__u32 wt_btree_lookup(struct bpf_xrp *context) {
    struct wt_btree_scratch *scratch = (struct wt_btree_scratch *) context->scratch;
    struct ebpf_page_header *header = (struct ebpf_page_header *) context->data;
    uint64_t descent_offset = 0;
    int ret;

    ++scratch->nr_page;

    switch (header->type) {
    case EBPF_PAGE_ROW_INT:
        if (scratch->nr_page >= EBPF_MAX_DEPTH) {
            bpf_printk("wt_btree_lookup: max depth exceeded");
            ret = -EBPF_EINVAL;
            break;
        }
        ret = ebpf_search_int_page(context, offsetof(struct wt_btree_scratch, key), scratch->key_size, &descent_offset);
        if (ret == 0) {
            context->done = false;
            context->next_addr[0] = descent_offset;
            context->size[0] = EBPF_BLOCK_SIZE;
            /* resubmission stays on the file the request started on */
            context->fd_arr[0] = context->cur_fd;
        } else {
            bpf_printk("wt_btree_lookup: ebpf_search_int_page failed, ret %d", ret);
        }
        break;
    case EBPF_PAGE_ROW_LEAF:
        ret = ebpf_search_leaf_page(context, offsetof(struct wt_btree_scratch, key), scratch->key_size);
        if (ret == 0) {
            context->done = true;
            context->next_addr[0] = 0;
            context->size[0] = 0;
        }
        break;
    default:
        bpf_printk("wt_btree_lookup: unknown page type %d", header->type);
        ret = -EBPF_EINVAL;
    }
    return -1 * ret;
}
