/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_LOCKING_H_
#define _FUSE_LOCKING_H_

#include "fuse_node.h"
#include <IOKit/IOLocks.h>

enum fusefslocktype {
    FUSEFS_SHARED_LOCK    = 1,
    FUSEFS_EXCLUSIVE_LOCK = 2,
    FUSEFS_FORCE_LOCK     = 3
};

#define FUSEFS_SHARED_OWNER (void *)0xffffffff

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

#endif /* _FUSE_LOCKING_H_ */
