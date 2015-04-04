/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2015 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_H_
#define _FUSE_H_

#include <fuse_param.h>
#include <fuse_version.h>

#include <IOKit/IOLib.h>
#include <libkern/OSMalloc.h>
#include <mach/mach_types.h>
#include <sys/kernel_types.h>
#include <sys/types.h>
#include <vfs/vfs_support.h>

#ifndef _FUSE_KERNEL_H_
    #define _FUSE_KERNEL_H_
    #include "fuse_kernel.h"
#endif

#define FUSE_INLINE static __inline__

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
    #define FUSE_VNOP_EXPORT __private_extern__
#else
    #define FUSE_VNOP_EXPORT static
#endif

#define FUSE_COUNT_MEMORY     1
// #define FUSE_DEBUG         1
// #define FUSE_KDEBUG        1
// #define FUSE_KTRACE_OP     1
// #define FUSE_TRACE         1
// #define FUSE_TRACE_LK      1
// #define FUSE_TRACE_MSLEEP  1
// #define FUSE_TRACE_OP      1
// #define FUSE_TRACE_VNCACHE 1

#define FUSEFS_SIGNATURE 0x55464553 // 'FUSE'

/* sysctl  */

extern int32_t  fuse_admin_group;
extern int32_t  fuse_allow_other;
extern int32_t  fuse_fh_current;
extern uint32_t fuse_fh_reuse_count;
extern uint32_t fuse_fh_upcall_count;
extern uint32_t fuse_fh_zombies;
extern int32_t  fuse_iov_credit;
extern int32_t  fuse_iov_current;
extern uint32_t fuse_iov_permanent_bufsize;
extern uint32_t fuse_lookup_cache_hits;
extern uint32_t fuse_lookup_cache_misses;
extern uint32_t fuse_lookup_cache_overrides;
extern uint32_t fuse_max_tickets;
extern uint32_t fuse_max_freetickets;
extern int32_t  fuse_memory_allocated;
extern int32_t  fuse_mount_count;
extern int32_t  fuse_realloc_count;
extern int32_t  fuse_tickets_current;
extern uint32_t fuse_userkernel_bufsize;
extern int32_t  fuse_vnodes_current;

/* trace */

#ifdef FUSE_TRACE
#  define fuse_trace_printf(fmt, ...) IOLog(fmt, ## __VA_ARGS__)
#  define fuse_trace_printf_func()    IOLog("%s\n", __FUNCTION__)
#else /* !FUSE_TRACE */
#  define fuse_trace_printf(fmt, ...) {}
#  define fuse_trace_printf_func()    {}
#endif /* FUSE_TRACE */

#ifdef FUSE_TRACE_OP
#  define fuse_trace_printf_vfsop()     IOLog("%s\n", __FUNCTION__)
#  define fuse_trace_printf_vnop_novp() IOLog("%s\n", __FUNCTION__)
#  define fuse_trace_printf_vnop()      IOLog("%s vp=%p\n", __FUNCTION__, vp)
#else
#  define fuse_trace_printf_vfsop()     {}
#  define fuse_trace_printf_vnop()      {}
#  define fuse_trace_printf_vnop_novp() {}
#endif

#ifdef FUSE_KTRACE_OP
#  undef  fuse_trace_printf_vfsop
#  undef  fuse_trace_printf_vnop
#  define fuse_trace_printf_vfsop() kprintf("%s\n", __FUNCTION__)
#  define fuse_trace_printf_vnop()  kprintf("%s\n", __FUNCTION__)
#endif

#ifdef FUSE_DEBUG
#  define debug_printf(fmt, ...) \
       IOLog("%s[%s:%d]: " fmt, __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#  define debug_printf(fmt, ...) {}
#endif

#ifdef FUSE_KDEBUG
#  undef debug_printf
#  define debug_printf(fmt, ...) \
       IOLog("%s[%s:%d]: " fmt, __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__);\
       kprintf("%s[%s:%d]: " fmt, __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)
#  define kdebug_printf(fmt, ...) debug_printf(fmt, ## __VA_ARGS__)
#else
#  define kdebug_printf(fmt, ...) {}
#endif

#define FUSE_ASSERT(a)                                                    \
    {                                                                     \
        if (!(a)) {                                                       \
            IOLog("File "__FILE__", line %d: assertion ' %s ' failed.\n", \
                  __LINE__, #a);                                          \
        }                                                                 \
    }

#define fuse_round_page_32(x) \
    (((uint32_t)(x) + 0x1000 - 1) & ~(0x1000 - 1))

#define FUSE_ZERO_SIZE 0x0000000000000000ULL
#define FUSE_ROOT_SIZE 0xFFFFFFFFFFFFFFFFULL

extern OSMallocTag fuse_malloc_tag;

#ifdef FUSE_COUNT_MEMORY
#  define FUSE_OSAddAtomic(amount, value) OSAddAtomic((amount), (value))

extern int32_t fuse_memory_allocated;

FUSE_INLINE
void *
FUSE_OSMalloc(size_t size, OSMallocTag tag)
{
    void *addr = OSMalloc((uint32_t)size, tag);

    if (!addr) {
        panic("osxfuse: memory allocation failed (size=%lu)", size);
    }

    FUSE_OSAddAtomic((UInt32)size, (SInt32 *)&fuse_memory_allocated);

    return addr;
}

FUSE_INLINE
void
FUSE_OSFree(void *addr, size_t size, OSMallocTag tag)
{
    OSFree(addr, (uint32_t)size, tag);

    FUSE_OSAddAtomic(-(UInt32)(size), (SInt32 *)&fuse_memory_allocated);
}

#else /* !FUSE_COUNT_MEMORY */
#  define FUSE_OSAddAtomic(amount, value)    {}
#  define FUSE_OSMalloc(size, tag)           OSMalloc((uint32_t)(size), (tag))
#  define FUSE_OSFree(addr, size, tag)       OSFree((addr), (size), (tag))
#endif /* FUSE_COUNT_MEMORY */

FUSE_INLINE
void *
FUSE_OSRealloc_nocopy(void *oldptr, size_t oldsize, size_t newsize)
{
    void *data;

    data = FUSE_OSMalloc(newsize, fuse_malloc_tag);
    if (!data) {
        panic("osxfuse: OSMalloc failed in realloc");
    }

    FUSE_OSFree(oldptr, oldsize, fuse_malloc_tag);
    FUSE_OSAddAtomic(1, (SInt32 *)&fuse_realloc_count);

    return data;
}

FUSE_INLINE
void *
FUSE_OSRealloc_nocopy_canfail(void *oldptr, size_t oldsize, size_t newsize)
{
    void *data;

    data = FUSE_OSMalloc(newsize, fuse_malloc_tag);
    if (!data) {
        goto out;
    } else {
        FUSE_OSFree(oldptr, oldsize, fuse_malloc_tag);
        FUSE_OSAddAtomic(1, (SInt32 *)&fuse_realloc_count);
    }

out:
    return data;
}

typedef enum fuse_op_waitfor {
    FUSE_OP_BACKGROUNDED = 0,
    FUSE_OP_FOREGROUNDED = 1,
} fuse_op_waitfor_t;

struct fuse_abi_data {
    int   fad_version;
    void *fad_data;
};

#endif /* _FUSE_H_ */
