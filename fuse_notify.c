/*
 * Copyright (c) 2012 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_notify.h"

#include "fuse_biglock_vnops.h"
#include "fuse_ipc.h"
#include "fuse_knote.h"
#include "fuse_node.h"

#include <sys/ubc.h>

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

int
fuse_notify_inval_entry(struct fuse_data *data, struct fuse_iov *iov) {
    int err = 0;

    struct fuse_notify_inval_entry_out fnieo;
    char name[FUSE_MAXNAMLEN + 1];
    void *next;

    HNodeRef dhp;
    vnode_t dvp;
    vnode_t vp;
    struct componentname cn;

    next = fuse_abi_out(fuse_notify_inval_entry_out, DTOABI(data), iov->base,
                       &fnieo);
    if (fnieo.namelen > iov->len - ((char *)next - (char *)iov->base)) {
        return EINVAL;
    }
    if (fnieo.namelen > FUSE_MAXNAMLEN) {
        return ENAMETOOLONG;
    }
    memcpy(name, next, fnieo.namelen);
    name[fnieo.namelen] = '\0';

    err = (int)HNodeLookupRealQuickIfExists(data->fdev, (ino_t)fnieo.parent,
                                            0 /* fork index */, &dhp, &dvp);
    if (err) {
        return err;
    }
    assert(dvp != NULL);

    /*
     * We have to look up the vnode for the specified name in the vnode cache,
     * to purge it from the cache.
     *
     * Note: Without flag MAKEENTRY cache_lookup does not return the vnode.
     */
    memset(&cn, 0, sizeof(cn));
    cn.cn_nameiop = LOOKUP;
    cn.cn_flags = MAKEENTRY;
    cn.cn_namelen = fnieo.namelen;
    cn.cn_nameptr = name;

    fuse_nodelock_lock(VTOFUD(dvp), FUSEFS_EXCLUSIVE_LOCK);

    err = fuse_vncache_lookup(dvp, &vp, &cn);
    switch (err) {
        case -1:
            /* positive match */
            err = 0;
            fuse_vncache_purge(vp);
            vnode_put(vp);
        case 0:
            /* no match in cache */
            break;
        case ENOENT:
            /* negative match */
        default:
            goto out;
    }

    fuse_invalidate_attr(dvp);
    FUSE_KNOTE(dvp, NOTE_ATTRIB);

out:
    fuse_nodelock_unlock(VTOFUD(dvp));

    vnode_put(dvp);
    return err;
}

int
fuse_notify_inval_inode(struct fuse_data *data, struct fuse_iov *iov) {
    int err = 0;

    struct fuse_notify_inval_inode_out fniio;

    HNodeRef hp;
    vnode_t vp;

    fuse_abi_out(fuse_notify_inval_inode_out, DTOABI(data), iov->base, &fniio);

    err = (int)HNodeLookupRealQuickIfExists(data->fdev, (ino_t)fniio.ino,
                                            0 /* fork index */, &hp, &vp);
    if (err) {
        return err;
    }
    assert(vp != NULL);

    fuse_nodelock_lock(VTOFUD(vp), FUSEFS_EXCLUSIVE_LOCK);

    fuse_invalidate_attr(vp);
    if (fniio.off >= 0) {
        off_t end_off;

        if (fniio.len > 0) {
            end_off = (off_t) min(fniio.off + fniio.len, ubc_getsize(vp));
        } else {
            end_off = ubc_getsize(vp);
        }

        ubc_msync(vp, (off_t)fniio.off, end_off, NULL,
                  UBC_PUSHDIRTY | UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
    }

    FUSE_KNOTE(vp, NOTE_ATTRIB);
    fuse_nodelock_unlock(VTOFUD(vp));

    vnode_put(vp);
    return err;
}

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */
