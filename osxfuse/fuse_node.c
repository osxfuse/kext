/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2011-2017 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_node.h"

#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_locking.h"

#if M_OSXFUSE_ENABLE_BIG_LOCK
#  include "fuse_biglock_vnops.h"
#endif

#include <stdbool.h>

void
FSNodeScrub(struct fuse_vnode_data *fvdat)
{
    lck_mtx_free(fvdat->createlock, fuse_lock_group);
    lck_mtx_free(fvdat->getattr_lock, fuse_lock_group);
#if M_OSXFUSE_ENABLE_TSLOCKING
    lck_rw_free(fvdat->nodelock, fuse_lock_group);
    lck_rw_free(fvdat->truncatelock, fuse_lock_group);
#endif
}

errno_t
FSNodeGetOrCreateFileVNodeByID(vnode_t              *vnPtr,
                               uint32_t              flags,
                               struct fuse_abi_data *feo,
                               mount_t               mp,
                               vnode_t               dvp,
                               vfs_context_t         context,
                               uint32_t             *oflags)
{
    int   err;

    vnode_t  vn    = NULLVP;
    HNodeRef hn    = NULL;

    struct fuse_vnode_data *fvdat   = NULL;
    struct fuse_data       *mntdata = NULL;
    fuse_device_t           dummy_device;

    struct fuse_abi_data fa;

    enum vtype vtyp;

    fuse_abi_data_init(&fa, feo->fad_version, fuse_entry_out_get_attr(feo));

    vtyp = IFTOVT(fuse_attr_get_mode(&fa));

    if ((vtyp >= VBAD) || (vtyp == VNON)) {
        return EINVAL;
    }

    int      markroot   = (flags & FN_IS_ROOT) ? 1 : 0;
    uint64_t size       = (flags & FN_IS_ROOT) ? 0 : fuse_attr_get_size(&fa);
    uint32_t rdev       = (flags & FN_IS_ROOT) ? 0 : fuse_attr_get_rdev(&fa);
    uint64_t generation = fuse_entry_out_get_generation(feo);

    mntdata = fuse_get_mpdata(mp);
    dummy_device = mntdata->fdev;

    err = HNodeLookupCreatingIfNecessary(dummy_device, fuse_entry_out_get_nodeid(feo),
                                         0 /* fork index */, &hn, &vn);
    if ((err == 0) && (vn == NULL)) {

        struct vnode_fsparam params;

        fvdat = (struct fuse_vnode_data *)FSNodeGenericFromHNode(hn);

        if (!fvdat->fInitialised) {

            fvdat->fInitialised = true;

            /* self */
            fvdat->vp           = NULLVP; /* hold on */
            fvdat->nodeid       = fuse_entry_out_get_nodeid(feo);
            fvdat->generation   = generation;

            /* parent */
            fvdat->parentvp     = dvp;
            if (dvp) {
                fvdat->parent_nodeid = VTOI(dvp);
            } else {
                fvdat->parent_nodeid = 0;
            }

            /* I/O */
            {
                int k;
                for (k = 0; k < FUFH_MAXTYPE; k++) {
                    FUFH_USE_RESET(&(fvdat->fufh[k]));
                }
            }

            /* flags */
            fvdat->flag         = flags;
            fvdat->c_flag       = 0;

            /* meta */

            /* XXX: truncation */
            fvdat->entry_valid.tv_sec  = (time_t)fuse_entry_out_get_entry_valid(feo);

            fvdat->entry_valid.tv_nsec = fuse_entry_out_get_entry_valid_nsec(feo);

            /* XXX: truncation */
            fvdat->attr_valid.tv_sec   = 0;

            fvdat->attr_valid.tv_nsec  = 0;

            /* XXX: truncation */
            fvdat->modify_time.tv_sec  = (time_t)fuse_attr_get_mtime(&fa);

            fvdat->modify_time.tv_nsec = fuse_attr_get_mtimensec(&fa);

            fvdat->filesize            = size;
            fvdat->nlookup             = 0;
            fvdat->vtype               = vtyp;

            /* locking */
            fvdat->createlock = lck_mtx_alloc_init(fuse_lock_group,
                                                   fuse_lock_attr);
            fvdat->creator = current_thread();
            fvdat->getattr_lock = lck_mtx_alloc_init(fuse_lock_group,
                                                     fuse_lock_attr);
#if M_OSXFUSE_ENABLE_TSLOCKING
            fvdat->nodelock = lck_rw_alloc_init(fuse_lock_group,
                                                fuse_lock_attr);
            fvdat->nodelockowner = NULL;
            fvdat->truncatelock  = lck_rw_alloc_init(fuse_lock_group,
                                                     fuse_lock_attr);
#endif
        }

        if (err == 0) {
            params.vnfs_mp     = mp;
            params.vnfs_vtype  = vtyp;
            params.vnfs_str    = NULL;
            params.vnfs_dvp    = dvp; /* NULLVP for the root vnode */
            params.vnfs_fsnode = hn;

#if M_OSXFUSE_ENABLE_SPECFS
            if ((vtyp == VBLK) || (vtyp == VCHR)) {
                params.vnfs_vops = fuse_spec_operations;
                params.vnfs_rdev = (dev_t)rdev;
#else
            if (0) {
#endif
#if M_OSXFUSE_ENABLE_FIFOFS
            } else if (vtyp == VFIFO) {
                params.vnfs_vops = fuse_fifo_operations;
                params.vnfs_rdev = 0;
                (void)rdev;
#else
            } else if (0) {
#endif
            } else {
                params.vnfs_vops = fuse_vnode_operations;
                params.vnfs_rdev = 0;
                (void)rdev;
            }

            params.vnfs_marksystem = 0;
            params.vnfs_cnp        = NULL;
            params.vnfs_flags      = VNFS_NOCACHE | VNFS_CANTCACHE;
            params.vnfs_filesize   = size;
            params.vnfs_markroot   = markroot;

#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(mntdata->biglock);
#endif
            err = vnode_create(VNCREATE_FLAVOR, (uint32_t)sizeof(params),
                               &params, &vn);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(mntdata->biglock);
#endif
        }

        if (err == 0) {
            if (markroot) {
                fvdat->parentvp = vn;
            } else {
                fvdat->parentvp = dvp;
            }
            if (oflags) {
                *oflags |= MAKEENTRY;
            }

            /* Need VT_OSXFUSE from xnu */
            vnode_settag(vn, VT_OTHER);

            cache_attrs(vn, fuse_entry_out, feo);

            HNodeAttachVNodeSucceeded(hn, 0 /* forkIndex */, vn);
            FUSE_OSAddAtomic(1, (SInt32 *)&fuse_vnodes_current);
        } else {
            if (HNodeAttachVNodeFailed(hn, 0 /* forkIndex */)) {
                FSNodeScrub(fvdat);
                HNodeScrubDone(hn);
            }
        }
    }

    if (err == 0) {
        if (vnode_vtype(vn) != vtyp) {
            IOLog("osxfuse: vnode changed type behind us (old=%d, new=%d)\n",
                  vnode_vtype(vn), vtyp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(mntdata->biglock);
#endif
            fuse_internal_vnode_disappear(vn, context, REVOKE_SOFT);
            vnode_put(vn);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(mntdata->biglock);
#endif
            err = EIO;
        } else if (VTOFUD(vn)->generation != generation) {
            IOLog("osxfuse: vnode changed generation\n");
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(mntdata->biglock);
#endif
            fuse_internal_vnode_disappear(vn, context, REVOKE_SOFT);
            vnode_put(vn);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(mntdata->biglock);
#endif
            err = ESTALE;
        }
    }

    if (err == 0) {
        *vnPtr = vn;
    }

    /* assert((err == 0) == (*vnPtr != NULL); */

    return err;
}

int
fuse_vget_i(vnode_t              *vpp,
            uint32_t              flags,
            struct fuse_abi_data *feo,
            struct componentname *cnp,
            vnode_t               dvp,
            mount_t               mp,
            vfs_context_t         context)
{
    int err = 0;

    if (!feo || !feo->fad_data) {
        return EINVAL;
    }

    err = FSNodeGetOrCreateFileVNodeByID(vpp, flags, feo, mp, dvp,
                                         context, NULL);
    if (err) {
        return err;
    }

    if (!fuse_isnovncache_mp(mp) && (cnp->cn_flags & MAKEENTRY)) {
        fuse_vncache_enter(dvp, *vpp, cnp);
    }

/* found: */

    VTOFUD(*vpp)->nlookup++;

    return 0;
}

void
fuse_vncache_enter(vnode_t dvp, vnode_t vp, struct componentname *cnp)
{
#if FUSE_TRACE_VNCACHE
    IOLog("osxfuse: cache enter dvp=%p, vp=%p, %s\n", dvp, vp, cnp->cn_nameptr);
#endif

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(dvp));
    bool biglock_locked = fuse_biglock_have_lock(data->biglock);

    if (biglock_locked) {
        fuse_biglock_unlock(data->biglock);
    }
#endif /* M_OSXFUSE_ENABLE_BIG_LOCK */
    cache_enter(dvp, vp, cnp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    if (biglock_locked) {
        fuse_biglock_lock(data->biglock);
    }
#endif
}

void
fuse_vncache_purge(vnode_t vp)
{
#if FUSE_TRACE_VNCACHE
    IOLog("osxfuse: cache purge vp=%p\n", vp);
#endif

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));
    bool biglock_locked = fuse_biglock_have_lock(data->biglock);

    if (biglock_locked) {
        fuse_biglock_unlock(data->biglock);
    }
#endif /* M_OSXFUSE_ENABLE_BIG_LOCK */
    cache_purge(vp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    if (biglock_locked) {
        fuse_biglock_lock(data->biglock);
    }
#endif
}

int
fuse_vncache_lookup(vnode_t dvp, vnode_t *vpp, struct componentname *cnp)
{
#if M_OSXFUSE_ENABLE_BIG_LOCK
    /*
     * Make sure that biglock is actually held by the thread calling us before
     * trying to unlock it. fuse_vncache_lookup is called by notification
     * handlers that do not hold biglock. Trying to unlock it in this case would
     * result in a kernel panic.
     */

    struct fuse_data *data = fuse_get_mpdata(vnode_mount(dvp));
    bool biglock_locked = fuse_biglock_have_lock(data->biglock);

    if (biglock_locked) {
        fuse_biglock_unlock(data->biglock);
    }
#endif /* M_OSXFUSE_ENABLE_BIG_LOCK */
    int ret = cache_lookup(dvp, vpp, cnp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    if (biglock_locked) {
        fuse_biglock_lock(data->biglock);
    }
#endif

#if FUSE_TRACE_VNCACHE
    IOLog("osxfuse: cache lookup ret=%d, dvp=%p, *vpp=%p, %s\n",
          ret, dvp, *vpp, cnp->cn_nameptr);
#endif
    return ret;
}
