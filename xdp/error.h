// Misc

#define bpf_printk(...)  \
    printf(__VA_ARGS__)

#define __wt_err(session, error, ...) \
    WT_UNUSED(session);               \
    WT_UNUSED(error);                 \
    bpf_printk(__VA_ARGS__)


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
        printf(__VA_ARGS__);                \
        goto err;                            \
    } while (0)


#define RET_MSG(ret, ...)          \
    do {                                \
        int __ret = (ret);              \
        printf("Error code: %d", __ret);  \
        printf(__VA_ARGS__);            \
        printf("\n");                   \
        return (__ret);                 \
    } while (0)

#define WT_TRET(a)                                                                             \
    do {                                                                                       \
        int __ret;                                                                             \
        if ((__ret = (a)) != 0 && (__ret == WT_PANIC || ret == 0 || ret == WT_DUPLICATE_KEY || \
                                    ret == WT_NOTFOUND || ret == WT_RESTART))                  \
            ret = __ret;                                                                       \
    } while (0)

#define WT_ERR_TEST(a, v, keep) \
    do {                        \
        if (a) {                \
            ret = (v);          \
            goto err;           \
        } else if (!(keep))     \
            ret = 0;            \
    } while (0)
#define WT_ERR_ERROR_OK(a, e, keep) WT_ERR_TEST((ret = (a)) != 0 && ret != (e), ret, keep)
#define WT_ERR_NOTFOUND_OK(a, keep) WT_ERR_ERROR_OK(a, WT_NOTFOUND, keep)
