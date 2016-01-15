/*
 * Copyright (c) 2012-2016 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_notify.h"

#include "fuse_biglock_vnops.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_knote.h"
#include "fuse_node.h"

#include <sys/ubc.h>

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

static
void
fuse_notify_getattr(void *parameter, __unused wait_result_t wait_result)
{
    int err;

    vnode_t vp = (vnode_t)parameter;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

    struct fuse_dispatcher fdi;
    struct fuse_abi_data fgi;
    struct fuse_abi_data fao;
    struct fuse_abi_data fa;

    off_t old_filesize;
    off_t new_filesize;

    fuse_biglock_lock(data->biglock);

    if (fuse_isdeadfs(vp)) {
        goto out;
    }

    fdisp_init_abi(&fdi, fuse_getattr_in, data);
    fdisp_make_vp(&fdi, FUSE_GETATTR, vp, vfs_context_current());
    fuse_abi_data_init(&fgi, DATOI(data), fdi.indata);

    fuse_getattr_in_set_fh(&fgi, 0);
    fuse_getattr_in_set_getattr_flags(&fgi, 0);

    err = fdisp_wait_answ(&fdi);
    if (err) {
        if (err == ENOENT) {
            fuse_biglock_unlock(data->biglock);
            fuse_internal_vnode_disappear(vp, vfs_context_current(), REVOKE_SOFT);
            fuse_biglock_lock(data->biglock);
        }
        goto out;
    }

    fuse_abi_data_init(&fao, DATOI(data), fdi.answ);
    fuse_abi_data_init(&fa, fao.fad_version, fuse_attr_out_get_attr(&fao));

    cache_attrs(vp, fuse_attr_out, &fao);

    old_filesize = fvdat->filesize;
    new_filesize = fuse_attr_get_size(&fa);

    if (old_filesize != new_filesize) {
        fvdat->filesize = new_filesize;

        fuse_biglock_unlock(data->biglock);

        ubc_setsize(vp, new_filesize);

        if (new_filesize > old_filesize) {
            /*
             * Note: Unless the file did end on a page boundary we need to invalidate the
             * last page of the file's unified buffer cache maunally. ubc_setsize does not
             * take care of this when expanding files.
             */

            off_t end_off = round_page_64(old_filesize);
            if (end_off != old_filesize) {
                ubc_msync(vp, trunc_page_64(old_filesize), end_off, NULL, UBC_INVALIDATE);
            }
        }

        fuse_biglock_lock(data->biglock);
    }

out:
    FUSE_KNOTE(vp, NOTE_ATTRIB);

    /*
     * Note: We need to unlock the node and decrement the vnode's iocount. See
     * fuse_notify_inval_inode for details.
     */

    fuse_biglock_unlock(data->biglock);
    fuse_nodelock_unlock(VTOFUD(vp));
    vnode_put(vp);

    thread_terminate(current_thread());
}

int
fuse_notify_inval_entry(struct fuse_data *data, struct fuse_iov *iov)
{
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

    err = (int)HNodeLookupRealQuickIfExists(data->fdev,
                                            (ino_t)fuse_notify_inval_entry_out_get_parent(&fnieo),
                                            0 /* fork index */,
                                            &dhp,
                                            &dvp);
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
fuse_notify_inval_inode(struct fuse_data *data, struct fuse_iov *iov)
{
    int err = 0;

    struct fuse_abi_data fniio;

    ino_t ino;
    int64_t off;
    int64_t len;

    HNodeRef hp;
    vnode_t vp;

    kern_return_t kr;
    thread_t getattr_thread;

    if (!vfs_issynchronous(data->mp)) {
        /*
         * Enabling asynchronous writes for distributed file systems is not supported.
         * Files might end up in an inconsitent state. Therefore we do the only sane
         * thing and ignore this notification.
         */
        err = ENOSYS;
        goto out;
    }

    fuse_abi_data_init(&fniio, DATOI(data), iov->base);

    ino = (ino_t)fuse_notify_inval_inode_out_get_ino(&fniio);
    off = fuse_notify_inval_inode_out_get_off(&fniio);
    len = fuse_notify_inval_inode_out_get_len(&fniio);

    err = (int)HNodeLookupRealQuickIfExists(data->fdev, ino, 0 /* fork index */, &hp, &vp);
    if (err) {
        return err;
    }
    assert(vp != NULL);

    fuse_nodelock_lock(VTOFUD(vp), FUSEFS_EXCLUSIVE_LOCK);
    fuse_biglock_lock(data->biglock);

    fuse_invalidate_attr(vp);

    fuse_biglock_unlock(data->biglock);

    if (off >= 0) {
        off_t end_off;

        if (len > 0) {
            end_off = (off_t) min(off + len, ubc_getsize(vp));
        } else {
            end_off = ubc_getsize(vp);
        }

        ubc_msync(vp, (off_t)off, end_off, NULL, UBC_INVALIDATE);
    }

    if (vnode_isreg(vp)) {
        // Update the file's attributes to detect file size changes
        kr = kernel_thread_start(fuse_notify_getattr, vp, &getattr_thread);

        if (kr == KERN_SUCCESS) {
            /*
             * Note: We will unlock the node and derement the vnode's iocount after updating
             * the file's attributes in fuse_notify_getattr.
             */

            thread_deallocate(getattr_thread);
            goto out;

        } else {
            err = EIO;
            IOLog("osxfuse: could not start getattr thread\n");
        }
    }

    FUSE_KNOTE(vp, NOTE_ATTRIB);
    fuse_nodelock_unlock(VTOFUD(vp));
    vnode_put(vp);

out:
    return err;
}

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */
