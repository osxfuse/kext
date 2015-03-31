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

    struct fuse_abi_data fnieo;
    char name[FUSE_MAXNAMLEN + 1];
    void *next;

    uint32_t namelen;

    HNodeRef dhp;
    vnode_t dvp;
    vnode_t vp;
    struct componentname cn;

    fuse_abi_data_init(&fnieo, DATOI(data), iov->base);
    next = (char *)iov->base + fuse_notify_inval_entry_out_sizeof(DATOI(data));

    namelen = fuse_notify_inval_entry_out_get_namelen(&fnieo);
    if (namelen > iov->len - ((char *)next - (char *)iov->base)) {
        return EINVAL;
    }
    if (namelen > FUSE_MAXNAMLEN) {
        return ENAMETOOLONG;
    }
    memcpy(name, next, namelen);
    name[namelen] = '\0';

    err = (int)HNodeLookupRealQuickIfExists(data->fdev, (ino_t)fuse_notify_inval_entry_out_get_parent(&fnieo),
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
    cn.cn_namelen = namelen;
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

    struct fuse_abi_data fniio;

    ino_t ino;
    int64_t off;
    int64_t len;

    HNodeRef hp;
    vnode_t vp;

    fuse_abi_data_init(&fniio, DATOI(data), iov->base);

    ino = (ino_t)fuse_notify_inval_inode_out_get_ino(&fniio);
    off = fuse_notify_inval_inode_out_get_off(&fniio);
    len = fuse_notify_inval_inode_out_get_len(&fniio);

    err = (int)HNodeLookupRealQuickIfExists(data->fdev, ino, 0 /* fork index */,
                                            &hp, &vp);
    if (err) {
        return err;
    }
    assert(vp != NULL);

    fuse_nodelock_lock(VTOFUD(vp), FUSEFS_EXCLUSIVE_LOCK);

    fuse_invalidate_attr(vp);
    if (off >= 0) {
        off_t end_off;

        if (len > 0) {
            end_off = (off_t) min(off + len, ubc_getsize(vp));
        } else {
            end_off = ubc_getsize(vp);
        }

        ubc_msync(vp, (off_t)off, end_off, NULL,
                  UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
    }

    FUSE_KNOTE(vp, NOTE_ATTRIB);
    fuse_nodelock_unlock(VTOFUD(vp));

    vnode_put(vp);
    return err;
}

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */
