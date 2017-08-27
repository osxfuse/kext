/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2012-2017 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_LOCKING_H_
#define _FUSE_LOCKING_H_

#include "fuse.h"

#include "fuse_node.h"

#include <libkern/locks.h>

#ifdef FUSE_TRACE_LK
#  include <sys/vm.h>
#endif

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
#  include <kern/thread.h>
#endif

enum fusefslocktype {
    FUSEFS_SHARED_LOCK    = 1,
    FUSEFS_EXCLUSIVE_LOCK = 2,
    FUSEFS_FORCE_LOCK     = 3
};

#if __LP64__
#  define FUSEFS_SHARED_OWNER (void *)0xffffffffffffffff
#else
#  define FUSEFS_SHARED_OWNER (void *)0xffffffff
#endif

/* Locking */
extern int fusefs_lock(fusenode_t, enum fusefslocktype);
extern int fusefs_lockpair(fusenode_t, fusenode_t, enum fusefslocktype);
extern int fusefs_lockfour(fusenode_t, fusenode_t, fusenode_t, fusenode_t,
                           enum fusefslocktype);
extern void fusefs_lock_truncate(fusenode_t, lck_rw_type_t);

/* Unlocking */
extern void fusefs_unlock(fusenode_t);
extern void fusefs_unlockpair(fusenode_t, fusenode_t);
extern void fusefs_unlockfour(fusenode_t, fusenode_t, fusenode_t, fusenode_t);
extern void fusefs_unlock_truncate(fusenode_t);

/* Wish the kernel exported lck_rw_done()... */
extern void fusefs_lck_rw_done(lck_rw_t *);

extern lck_attr_t     *fuse_lock_attr;
extern lck_grp_attr_t *fuse_group_attr;
extern lck_grp_t      *fuse_lock_group;
extern lck_mtx_t      *fuse_device_mutex;

#ifdef FUSE_TRACE_LK

#define fuse_lck_mtx_lock(m)                                                  \
    {                                                                         \
        proc_t __FUNCTION__ ## p = current_proc();                            \
        IOLog("0: lck_mtx_lock(%p): %s@%d by %d\n", (m), __FUNCTION__,        \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
        lck_mtx_lock((m));                                                    \
        IOLog("1: lck_mtx_lock(%p): %s@%d by %d\n", (m), __FUNCTION__,        \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
    }

#define fuse_lck_mtx_unlock(m)                                                \
    {                                                                         \
        proc_t __FUNCTION__ ## p = current_proc();                            \
        IOLog("1: lck_mtx_unlock(%p): %s@%d by %d\n", (m), __FUNCTION__,      \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
        lck_mtx_unlock((m));                                                  \
        IOLog("0: lck_mtx_unlock(%p): %s@%d by %d\n", (m), __FUNCTION__,      \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
    }

#define fuse_lck_rw_lock_shared(l)      lck_rw_lock_shared((l))
#define fuse_lck_rw_lock_exclusive(l)   lck_rw_lock_exclusive((l))
#define fuse_lck_rw_unlock_shared(l)    lck_rw_unlock_shared((l))
#define fuse_lck_rw_unlock_exclusive(l) lck_rw_unlock_exclusive((l))

#else /* !FUSE_TRACE_LK */

#define fuse_lck_mtx_lock(m)            lck_mtx_lock((m))
#define fuse_lck_mtx_unlock(m)          lck_mtx_unlock((m))

#define fuse_lck_rw_lock_shared(l)      lck_rw_lock_shared((l))
#define fuse_lck_rw_lock_exclusive(l)   lck_rw_lock_exclusive((l))
#define fuse_lck_rw_unlock_shared(l)    lck_rw_unlock_shared((l))
#define fuse_lck_rw_unlock_exclusive(l) lck_rw_unlock_exclusive((l))

#define fuse_lck_mtx_try_lock(l)        IOLockTryLock((IOLock *)l)

#endif /* FUSE_TRACE_LK */

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

typedef struct _fusefs_recursive_lock fusefs_recursive_lock;

extern fusefs_recursive_lock* fusefs_recursive_lock_alloc(void);
extern fusefs_recursive_lock* fusefs_recursive_lock_alloc_with_maxcount(UInt32);
extern void fusefs_recursive_lock_free(fusefs_recursive_lock *lock);
extern void fusefs_recursive_lock_lock(fusefs_recursive_lock *lock);
extern void fusefs_recursive_lock_unlock(fusefs_recursive_lock *lock);
extern bool fusefs_recursive_lock_have_lock(fusefs_recursive_lock *lock);

#if M_OSXFUSE_ENABLE_LOCK_LOGGING

extern lck_mtx_t *fuse_log_lock;

#define rawlog(msg, args...) IOLog(msg, ##args)

#define log(fmt, args...) \
	do { \
		lck_mtx_lock(fuse_log_lock); \
		rawlog(fmt, ##args); \
		rawlog("\n"); \
		lck_mtx_unlock(fuse_log_lock); \
	} while(0)

#define log_enter(params_format, args...) \
	do { \
		lck_mtx_lock(fuse_log_lock); \
		rawlog("[%s:%d] Entering %s: ", __FILE__, __LINE__, __FUNCTION__); \
		rawlog(params_format, ##args); \
		rawlog("\n"); \
		lck_mtx_unlock(fuse_log_lock); \
	} while(0)

#define log_leave(return_format, args...) \
	do { \
		lck_mtx_lock(fuse_log_lock); \
		rawlog("[%s:%d] Leaving %s: ", __FILE__, __LINE__, __FUNCTION__); \
		rawlog(return_format, ##args); \
		rawlog("\n"); \
		lck_mtx_unlock(fuse_log_lock); \
	} while(0)
#else /* !M_OSXFUSE_ENABLE_LOCK_LOGGING */
#define log(fmt, args...) do {} while(0)
#define log_enter(params_format, args...) do {} while(0)
#define log_leave(return_format, args...) do {} while(0)
#endif /* M_OSXFUSE_ENABLE_LOCK_LOGGING */

#if M_OSXFUSE_ENABLE_HUGE_LOCK

extern fusefs_recursive_lock *fuse_huge_lock;

#define fuse_hugelock_lock() \
	do { \
		log("%s thread=%p: Aquiring huge lock %p...", __FUNCTION__, current_thread(), fuse_huge_lock); \
		fusefs_recursive_lock_lock(fuse_huge_lock); \
		log("%s thread=%p: huge lock %p aquired!", __FUNCTION__, current_thread(), fuse_huge_lock); \
	} while(0)

#define fuse_hugelock_unlock() \
	do { \
		log("%s thread=%p: Releasing huge lock %p...", __FUNCTION__, current_thread(), fuse_huge_lock); \
		fusefs_recursive_lock_unlock(fuse_huge_lock); \
		log("%s thread=%p: huge lock %p released!", __FUNCTION__, current_thread(), fuse_huge_lock); \
	} while(0)

#define fuse_hugelock_have_lock() fusefs_recursive_lock_have_lock(fuse_huge_lock)

#define fuse_biglock_lock(lock) fuse_hugelock_lock()
#define fuse_biglock_unlock(lock) fuse_hugelock_unlock()
#define fuse_biglock_have_lock(lock) fuse_hugelock_have_lock()

#elif M_OSXFUSE_ENABLE_BIG_LOCK

typedef fusefs_recursive_lock fuse_biglock_t;

#define fuse_biglock_alloc() fusefs_recursive_lock_alloc_with_maxcount(1)
#define fuse_biglock_free(lock) fusefs_recursive_lock_free(lock)

#define fuse_biglock_lock(lock) \
	do { \
		log("%s thread=%p: Aquiring biglock %p...", __FUNCTION__, current_thread(), lock); \
		fusefs_recursive_lock_lock(lock); \
		log("%s thread=%p: biglock %p aquired!", __FUNCTION__, current_thread(), lock); \
	} while(0)

#define fuse_biglock_unlock(lock) \
	do { \
		log("%s thread=%p: Releasing biglock %p...", __FUNCTION__, current_thread(), lock); \
		fusefs_recursive_lock_unlock(lock); \
		log("%s thread=%p: biglock %p released!", __FUNCTION__, current_thread(), lock); \
	} while(0)

#define fuse_biglock_have_lock(lock) fusefs_recursive_lock_have_lock(lock)

#else /* !M_OSXFUSE_ENABLE_HUGO_LOCK && !M_OSXFUSE_ENABLE_BIG_LOCK */

#define fuse_biglock_lock(lock) do {} while(0)
#define fuse_biglock_unlock(lock) do {} while(0)
#define fuse_biglock_have_lock(lock) false

#endif /* M_OSXFUSE_ENABLE_HUGE_LOCK, M_OSXFUSE_ENABLE_BIG_LOCK */

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */

#endif /* _FUSE_LOCKING_H_ */
