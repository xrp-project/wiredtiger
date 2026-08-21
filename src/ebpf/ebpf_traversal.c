#include "wt_internal.h"

int ebpf_unpack_posint(uint8_t **pp, uint64_t *retp) {
    uint64_t x;
    uint8_t len, max_len = 16;  /* max_len is set to pass the ebpf verifier */
    uint8_t *p;

    /* There are four length bits in the first byte. */
    p = *pp;
    len = (*p++ & 0xf);

    for (x = 0; len != 0 && max_len != 0; --len, --max_len)
        x = (x << 8) | *p++;

    *retp = x;
    *pp = p;
    return 0;
}

int ebpf_vunpack_uint(uint8_t **pp, uint64_t *xp) {
    uint8_t *p;
    int ret;

    /* encoding scheme: https://github.com/wiredtiger/wiredtiger/blob/mongodb-4.4.0/src/include/intpack.i#L10 */
    p = *pp;
    switch (*p & 0xf0) {
    case EBPF_POS_1BYTE_MARKER:
    case EBPF_POS_1BYTE_MARKER | 0x10:
    case EBPF_POS_1BYTE_MARKER | 0x20:
    case EBPF_POS_1BYTE_MARKER | 0x30:
        /* higher 2 bits of the first byte is 10 */
        *xp = GET_BITS(*p, 6, 0);  /* extract integer from the remaining (8 - 2) = 6 bites */
        p += 1;
        break;
    case EBPF_POS_2BYTE_MARKER:
    case EBPF_POS_2BYTE_MARKER | 0x10:
        /* higher 3 bits of the first byte is 110 */
        *xp = GET_BITS(*p++, 5, 0) << 8;
        *xp |= *p++;
        *xp += EBPF_POS_1BYTE_MAX + 1;
        break;
    case EBPF_POS_MULTI_MARKER:
        /* higher 4 bits of the first byte is 1110 */
        ret = ebpf_unpack_posint(pp, xp);
        if (ret != 0) {
            return ret;
        }
        *xp += EBPF_POS_2BYTE_MAX + 1;
        return 0;
    default:
        return -EBPF_EINVAL;
    }

    *pp = p;
    return 0;
}

int ebpf_addr_to_offset(uint8_t *addr, uint64_t *offset, uint64_t *size) {
    int ret;
    uint64_t raw_offset, raw_size, raw_checksum;

    ret = ebpf_vunpack_uint(&addr, &raw_offset);
    if (ret < 0)
        return ret;
    ret = ebpf_vunpack_uint(&addr, &raw_size);
    if (ret < 0)
        return ret;
    ret = ebpf_vunpack_uint(&addr, &raw_checksum);  /* checksum is not used */
    if (ret < 0)
        return ret;
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

int ebpf_get_cell_type(uint8_t *cell) {
    return EBPF_CELL_SHORT_TYPE(cell[0]) ? EBPF_CELL_SHORT_TYPE(cell[0]) : EBPF_CELL_TYPE(cell[0]);
}

int ebpf_parse_cell_addr(uint8_t **cellp, uint64_t *offset, uint64_t *size, 
                         bool update_pointer) {
    uint8_t *cell = *cellp, *p = *cellp, *addr;
    uint8_t flags;
    uint64_t addr_len;
    int ret;

    /* read the first cell descriptor byte (cell type, RLE count) */
    if ((ebpf_get_cell_type(cell) != EBPF_CELL_ADDR_INT
         && ebpf_get_cell_type(cell) != EBPF_CELL_ADDR_LEAF
         && ebpf_get_cell_type(cell) != EBPF_CELL_ADDR_LEAF_NO)
        || ((cell[0] & EBPF_CELL_64V) != 0)) {
        return -EBPF_EINVAL;
    }
    p += 1;

    /* read the second cell descriptor byte (if present) */
    if ((cell[0] & EBPF_CELL_SECOND_DESC) != 0) {
        flags = *p;
        p += 1;
        if (flags != 0) {
            return -EBPF_EINVAL;
        }
    }

    /* the cell is followed by data length and a chunk of data */
    ret = ebpf_vunpack_uint(&p, &addr_len);
    if (ret != 0) {
        return ret;
    }
    addr = p;

    /* convert addr to file offset */
    ret = ebpf_addr_to_offset(addr, offset, size);
    if (ret != 0) {
        return ret;
    }

    if (update_pointer)
        *cellp = p + addr_len;
    return 0;
}

int bpf_fd;

int ebpf_lookup(int fd, uint64_t offset, uint8_t *key_buf, uint64_t key_size, 
                uint8_t *data_buf, uint8_t *scratch_buf, uint8_t **page_data_arr_p,
                uint64_t *child_index_arr, int *nr_page) {
    struct wt_ebpf_scratch *scratch = (struct wt_ebpf_scratch *) scratch_buf;
    int i, ret;
    struct timespec start_ts, end_ts;
    if (clock_gettime(CLOCK_REALTIME, &start_ts) == -1) {
        printf("clock_gettime failed\n");
    }

    if (key_size > EBPF_KEY_MAX_LEN) {
        printf("ebpf_lookup: key size is too large\n");
        return -EBPF_EINVAL;
    }

    /* initialize data buf & scratch buf */
    memset(data_buf, 0, 4096);
    memset(scratch_buf, 0, 4096);
    scratch->key_size = key_size;
    memcpy(scratch->key, key_buf, key_size);

    /* call xrp read */
    ret = syscall(__NR_read_xrp, fd, data_buf, EBPF_BLOCK_SIZE, offset, bpf_fd, scratch_buf);
    if (ret != EBPF_BLOCK_SIZE) {
        printf("ebpf_lookup: read_xrp failed, ret %d\n", ret);
        return ret;
    }

    /* parse result */
    *page_data_arr_p = scratch_buf + 1024;
    *nr_page = scratch->nr_page;
    for (i = 0; i < *nr_page; ++i) {
        child_index_arr[i] = scratch->descent_index_arr[i];
    }
    if (clock_gettime(CLOCK_REALTIME, &end_ts) == -1) {
        printf("clock_gettime failed\n");
    }
    atomic_fetch_add(&bpf_io_time, (end_ts.tv_sec * 1000000000L + end_ts.tv_nsec) - (start_ts.tv_sec * 1000000000L + start_ts.tv_nsec));
    atomic_fetch_add(&bpf_io_count, 1);
    return 0;
}

int bpf_btree_fd = -1;

/*
 * Over NVMe-oF the read_xrp syscall is not wired up; only read_bpfof carries
 * the serialized command config the target parses, and the BPF program runs
 * target-side from its pinned copy. WT_BPF_BTREE_BPFOF=1 selects that path.
 */
#define SYS_read_bpfof 447
static int bpf_btree_use_bpfof = -1;
atomic_long bpf_btree_page_count;

/*
 * Cache sampling: one in every bpf_btree_sample_rate eligible searches runs
 * through the normal read path instead of XRP. The sampled searches publish
 * pages into the cache, letting the resident prefix of the tree regrow, which
 * result-only XRP lookups can never do on their own. Zero disables sampling.
 */
int bpf_btree_sample_rate = 100;
atomic_long bpf_btree_sample_counter;
atomic_long bpf_btree_sample_count;
atomic_long bpf_btree_fallback_count;

/*
 * ebpf_btree_lookup --
 *     Run a full B-tree point lookup through XRP, starting from the given
 *     block offset. On success the caller reads the verdict and value from
 *     the scratch buffer.
 */
int ebpf_btree_lookup(int fd, uint64_t offset, uint8_t *key_buf, uint64_t key_size,
                      uint8_t *data_buf, uint8_t *scratch_buf) {
    struct wt_btree_scratch *scratch = (struct wt_btree_scratch *) scratch_buf;
    int ret;
    struct timespec start_ts, end_ts;
    if (clock_gettime(CLOCK_REALTIME, &start_ts) == -1) {
        printf("clock_gettime failed\n");
    }

    if (key_size > EBPF_KEY_MAX_LEN) {
        return -EBPF_EINVAL;
    }

    /* initialize data buf & scratch buf */
    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
    scratch->key_size = key_size;
    memcpy(scratch->key, key_buf, key_size);
    /* sentinel, detects the BPF program never running */
    scratch->state = -1;

    if (bpf_btree_use_bpfof < 0)
        bpf_btree_use_bpfof = getenv("WT_BPF_BTREE_BPFOF") != NULL;
    if (bpf_btree_use_bpfof) {
        unsigned int fds_arr[16];
        memset(fds_arr, 0, sizeof(fds_arr));
        fds_arr[0] = (unsigned int)fd;
        ret = (int)syscall(SYS_read_bpfof, fds_arr, (size_t)1, (size_t)EBPF_BLOCK_SIZE,
          (off_t)offset, scratch_buf, (size_t)EBPF_SCRATCH_BUFFER_SIZE);
        if (ret < 0) {
            return -EBPF_EINVAL;
        }
    } else {
        ret = syscall(__NR_read_xrp, fd, data_buf, EBPF_BLOCK_SIZE, offset, bpf_btree_fd, scratch_buf);
        if (ret != EBPF_BLOCK_SIZE) {
            return -EBPF_EINVAL;
        }
    }
    if (scratch->state != EBPF_BTREE_FOUND && scratch->state != EBPF_BTREE_NOTFOUND) {
        return -EBPF_EINVAL;
    }
    if (scratch->state == EBPF_BTREE_FOUND && scratch->value_size > EBPF_BTREE_VALUE_MAX_LEN) {
        return -EBPF_EINVAL;
    }
    atomic_fetch_add(&bpf_btree_page_count, scratch->nr_page);

    if (clock_gettime(CLOCK_REALTIME, &end_ts) == -1) {
        printf("clock_gettime failed\n");
    }
    atomic_fetch_add(&bpf_io_time, (end_ts.tv_sec * 1000000000L + end_ts.tv_nsec) - (start_ts.tv_sec * 1000000000L + start_ts.tv_nsec));
    atomic_fetch_add(&bpf_io_count, 1);
    return 0;
}
