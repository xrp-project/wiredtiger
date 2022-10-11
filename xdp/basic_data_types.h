//////////
// Ints //
//////////

#ifndef	_STDLIB_H

typedef signed char int8_t;
typedef short int16_t;
typedef long int32_t;
typedef long long int64_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
typedef unsigned long long uint64_t;

typedef unsigned int __u_int;
typedef __u_int u_int;
typedef unsigned char __u_char;
typedef __u_char u_char;
typedef long unsigned int size_t;
typedef long int ssize_t;

typedef long int off_t;

#define bool _Bool
#define true 1
#define false 0

typedef long int		intptr_t;
typedef unsigned long int	uintptr_t;

#  define __INT64_C(c)	c ## L
#  define __UINT64_C(c)	c ## UL

/* Maximum of unsigned integral types.  */
# define UINT8_MAX		(255)
# define UINT16_MAX		(65535)
# define UINT32_MAX		(4294967295U)
# define UINT64_MAX		(__UINT64_C(18446744073709551615))

typedef unsigned long int pthread_t;

//////////
// Time //
//////////

typedef long int __syscall_slong_t;
typedef long int __time_t;

/* POSIX.1b structure for a time value.  This is like a `struct timeval' but
   has nanoseconds instead of microseconds.  */
# define __WORDSIZE	64
struct timespec
{
  __time_t tv_sec;		/* Seconds.  */
#if __WORDSIZE == 64 \
  || (defined __SYSCALL_WORDSIZE && __SYSCALL_WORDSIZE == 64) \
  || __TIMESIZE == 32
  __syscall_slong_t tv_nsec;	/* Nanoseconds.  */
#else
# if __BYTE_ORDER == __BIG_ENDIAN
  int: 32;           /* Padding.  */
  long int tv_nsec;  /* Nanoseconds.  */
# else
  long int tv_nsec;  /* Nanoseconds.  */
  int: 32;           /* Padding.  */
# endif
#endif
};

#endif  // -- _STDLIB_H

////////////
// Errors //
////////////

#define EINVAL 22
#define ENOTSUP 95


/////////////////
// Concurrency //
/////////////////

#define WT_SPINLOCK_SIZE 64 // TODO: Find out sizes!
#define WT_MUTEX_SIZE 40
#define WT_COND_T_SIZE 48

struct __wt_spinlock_stub {
    uint8_t stub[WT_SPINLOCK_SIZE];
};

struct __wt_mutex_stub {
    uint8_t stub[WT_MUTEX_SIZE];
};

struct wt_cond_t_stub {
    uint8_t stub[WT_COND_T_SIZE];
};

typedef struct __wt_spinlock_stub WT_SPINLOCK;
typedef struct __wt_mutex_stub wt_mutex_t;
typedef struct wt_cond_t_stub wt_cond_t;

typedef struct {
    bool created;
    pthread_t id;
} wt_thread_t;
