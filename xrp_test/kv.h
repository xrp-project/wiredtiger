/*
 * kv.h: shared key/value generation for the XRP test tools.
 *
 * Every tool that creates or validates records includes this header so the
 * on-disk format has exactly one definition. Keys are 8-digit zero-padded
 * decimals (lexicographic order == numeric order, required for bulk load).
 * Values carry a 16-char self-identifying header followed by a deterministic
 * fill pattern, so a validator can recompute the full expected value from the
 * key index alone.
 *
 * The value length is runtime-configurable through XRP_VALUE_LEN (default 16,
 * which is exactly the bare header and matches the original toy format). All
 * tools read the same variable, so creator and validators stay in sync as
 * long as they run with the same environment.
 */
#ifndef XRP_TEST_KV_H
#define XRP_TEST_KV_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define KV_VALUE_HDR_LEN 16
#define KV_VALUE_MAX 2048

static inline uint32_t
kv_value_len(void)
{
    static uint32_t len;
    const char *s;

    if (len == 0) {
        len = KV_VALUE_HDR_LEN;
        if ((s = getenv("XRP_VALUE_LEN")) != NULL) {
            long v = strtol(s, NULL, 10);
            if (v >= KV_VALUE_HDR_LEN && v < KV_VALUE_MAX)
                len = (uint32_t)v;
        }
    }
    return (len);
}

static inline void
kv_make_key(char *buf, uint32_t i)
{
    sprintf(buf, "%08u", i);
}

static inline void
kv_make_value(char *buf, uint32_t i)
{
    uint32_t j, len;

    len = kv_value_len();
    sprintf(buf, "V%08u-%06x", i, i * 7919u);
    for (j = KV_VALUE_HDR_LEN; j < len; ++j)
        buf[j] = (char)('a' + (i * 31u + j) % 26u);
    buf[len] = '\0';
}

#endif
