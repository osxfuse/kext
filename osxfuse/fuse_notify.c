/*
 * Copyright (c) 2012-2018 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_notify.h"

#include "fuse_biglock_vnops.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_knote.h"
#include "fuse_node.h"

#include <sys/ubc.h>

__private_extern__
int
fuse_vnode_notify(vnode_t vp, uint32_t events)
{
#if M_OSXFUSE_ENABLE_VNODE_NOTIFY
    struct vnode_attr va;
    struct vnode_attr *vap = &va;
    struct vnode_attr *cached_vap = VTOVA(vp);

    (void)vfs_get_notify_attributes(vap);

    VATTR_RETURN(vap, va_fsid, cached_vap->va_fsid);
    VATTR_RETURN(vap, va_fileid, cached_vap->va_fileid);
    VATTR_RETURN(vap, va_mode, cached_vap->va_mode);
    VATTR_RETURN(vap, va_uid, cached_vap->va_uid);
    VATTR_RETURN(vap, va_gid, cached_vap->va_gid);
    VATTR_RETURN(vap, va_nlink, cached_vap->va_nlink);

    return vnode_notify(vp, events, vap);

#else /* M_OSXFUSE_ENABLE_VNODE_NOTIFY */
    (void)vp;
    (void)events;

    return 0;
#endif /* M_OSXFUSE_ENABLE_VNODE_NOTIFY */
}

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

static
int
fuse_notify_getattr(vnode_t vp)
{
    int err;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

    vfs_context_t context;

    struct fuse_dispatcher fdi;
    struct fuse_abi_data fgi;
    struct fuse_abi_data fao;
    struct fuse_abi_data fa;

    uint32_t events = 0;
    off_t old_filesize;
    off_t new_filesize;

    fuse_nodelock_lock(fvdat, FUSEFS_EXCLUSIVE_LOCK);
    fuse_biglock_lock(data->biglock);

    context = vfs_context_create(NULL);

    if (fuse_isdeadfs(vp)) {
        err = ENXIO;
        goto out;
    }

    fdisp_init_abi(&fdi, fuse_getattr_in, data);
    fdisp_make_vp(&fdi, FUSE_GETATTR, vp, context);
    fuse_abi_data_init(&fgi, DATOI(data), fdi.indata);

    fuse_getattr_in_set_fh(&fgi, 0);
    fuse_getattr_in_set_getattr_flags(&fgi, 0);

    err = fdisp_wait_answ(&fdi);
    if (err) {
        if (err == ENOENT) {
            events |= FUSE_VNODE_EVENT_DELETE;

            fuse_biglock_unlock(data->biglock);
            fuse_internal_vnode_disappear(vp, context, REVOKE_SOFT);
            fuse_biglock_lock(data->biglock);
        }
        goto out;
    }

    fuse_abi_data_init(&fao, DATOI(data), fdi.answ);
    fuse_abi_data_init(&fa, fao.fad_version, fuse_attr_out_get_attr(&fao));

    /*
     * Note: Actually we don't know if file attributes or contents have changed
     * but we send out the notification anyway.
     */
    events = FUSE_VNODE_EVENT_ATTRIB | FUSE_VNODE_EVENT_WRITE;

    cache_attrs(vp, fuse_attr_out, &fao);

    old_filesize = fvdat->filesize;
    new_filesize = fuse_attr_get_size(&fa);

    if (old_filesize != new_filesize) {
        fvdat->filesize = new_filesize;

        fuse_biglock_unlock(data->biglock);

        ubc_setsize(vp, new_filesize);

        if (new_filesize > old_filesize) {
            events |= FUSE_VNODE_EVENT_EXTEND;

            /*
             * Note: Unless the file did end on a page boundary we need to
             * invalidate the last page of the file's unified buffer cache
             * maunally. ubc_setsize() does not take care of this when expanding
             * files.
             */

            off_t end_off = round_page_64(old_filesize);
            if (end_off != old_filesize) {
                ubc_msync(vp, trunc_page_64(old_filesize), end_off, NULL,
                          UBC_INVALIDATE);
            }
        }

        fuse_biglock_lock(data->biglock);
    }

out:
    FUSE_KNOTE(vp, events);
    fuse_vnode_notify(vp, events);

    vfs_context_rele(context);

    /*
     * Note: We need to unlock the node and notify other waiting threads. See
     * fuse_notify_inval_inode for details.
     */

    fvdat->flag &= ~FN_GETATTR;
    fuse_lck_mtx_lock(fvdat->getattr_lock);

    fuse_biglock_unlock(data->biglock);
    fuse_nodelock_unlock(VTOFUD(vp));

    wakeup(fvdat->getattr_thread);
    fuse_lck_mtx_unlock(fvdat->getattr_lock);

    return err;
}

static
void
fuse_notify_getattr_thread(void *parameter, __unused wait_result_t wait_result)
{
    vnode_t vp = (vnode_t)parameter;

    (void)fuse_notify_getattr(vp);

    vnode_put(vp);
    thread_terminate(current_thread());
}

typedef int (*fuse_notify_lookup_callback)(vnode_t, uint64_t);

static
int
fuse_notify_lookup(struct fuse_data *data, uint64_t parentid, uint64_t fileid,
                   char *name, size_t namelen,
                   fuse_notify_lookup_callback parent_callback,
                   fuse_notify_lookup_callback file_callback)
{
    int err = 0;

    HNodeRef dhp;
    vnode_t dvp;
    struct componentname cn;
    vnode_t vp;

    struct fuse_vnode_data *fdvdat;

    err = HNodeLookupRealQuickIfExists(data->fdev, parentid, 0 /* fork index */,
                                       &dhp, &dvp);
    if (err) {
        return err;
    }
    assert(dvp != NULL);

    fdvdat = VTOFUD(dvp);

    /*
     * We have to look up the vnode for the specified name in the vnode cache,
     * to purge it from the cache.
     *
     * Note: Without flag MAKEENTRY cache_lookup() does not return the vnode.
     */

    memset(&cn, 0, sizeof(cn));
    cn.cn_nameiop = LOOKUP;
    cn.cn_flags = MAKEENTRY;
    cn.cn_namelen = (int)namelen;
    cn.cn_nameptr = name;

    fuse_nodelock_lock(fdvdat, FUSEFS_EXCLUSIVE_LOCK);

    err = fuse_vncache_lookup(dvp, &vp, &cn);
    switch (err) {
        case -1:
            /* Positive match */
            err = 0;
            (void)file_callback(vp, fileid);
            vnode_put(vp);
            break;

        case 0:
            /* No match in cache */
            break;

        case ENOENT:
            /* Negative match */
            goto out;
    }

    (void)parent_callback(dvp, parentid);

out:
    fuse_nodelock_unlock(fdvdat);

    vnode_put(dvp);
    return err;
}

static
int
fuse_notify_inval_entry_parent_callback(vnode_t dvp, uint64_t parentid)
{
    fuse_invalidate_attr(dvp);

    FUSE_KNOTE(dvp, NOTE_ATTRIB);
    fuse_vnode_notify(dvp, FUSE_VNODE_EVENT_ATTRIB);

    return 0;
}

static
int
fuse_notify_inval_entry_file_callback(vnode_t vp, uint64_t fileid)
{
    fuse_vncache_purge(vp);
    return 0;
}

__private_extern__
int
fuse_notify_inval_entry(struct fuse_data *data, struct fuse_iov *iov)
{
    struct fuse_abi_data fnieo;
    void *next;

    uint64_t parentid;
    size_t namelen;
    char name[FUSE_MAXNAMLEN + 1];

    fuse_abi_data_init(&fnieo, DATOI(data), iov->base);
    next = (char *)iov->base + fuse_notify_inval_entry_out_sizeof(DATOI(data));

    parentid = fuse_notify_inval_entry_out_get_parent(&fnieo);

    namelen = fuse_notify_inval_entry_out_get_namelen(&fnieo);
    if (namelen > iov->len - ((char *)next - (char *)iov->base)) {
        return EINVAL;
    }
    if (namelen > FUSE_MAXNAMLEN) {
        return ENAMETOOLONG;
    }
    memcpy(name, next, namelen);
    name[namelen] = '\0';

    return fuse_notify_lookup(data, parentid, 0 /* fileid */, name, namelen,
                              &fuse_notify_inval_entry_parent_callback,
                              &fuse_notify_inval_entry_file_callback);
}

__private_extern__
int
fuse_notify_inval_inode(struct fuse_data *data, struct fuse_iov *iov)
{
    int err = 0;

    struct fuse_abi_data fniio;

    ino_t fileid;
    int64_t off;
    int64_t len;

    HNodeRef hp;
    vnode_t vp;
    struct fuse_vnode_data *fvdat;

    kern_return_t kr;
    thread_t getattr_thread;

    if (!vfs_issynchronous(data->mp)) {
        /*
         * Enabling asynchronous writes for distributed file systems is not
         * supported. Files might end up in an inconsitent state. Therefore we
         * do the only sane thing and ignore this notification.
         */
        err = ENOSYS;
        goto out;
    }

    fuse_abi_data_init(&fniio, DATOI(data), iov->base);

    fileid = (ino_t)fuse_notify_inval_inode_out_get_ino(&fniio);
    off = fuse_notify_inval_inode_out_get_off(&fniio);
    len = fuse_notify_inval_inode_out_get_len(&fniio);

    err = HNodeLookupRealQuickIfExists(data->fdev, fileid, 0 /* fork index */,
                                       &hp, &vp);
    if (err) {
        return err;
    }
    assert(vp != NULL);

    fvdat = VTOFUD(vp);
    fuse_nodelock_lock(fvdat, FUSEFS_EXCLUSIVE_LOCK);
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
        kr = kernel_thread_start(fuse_notify_getattr_thread, vp,
                                 &getattr_thread);

        if (kr == KERN_SUCCESS) {
            /*
             * Note: We will decrement the vnode's iocount after updating the
             * file's attributes in fuse_notify_getattr_thread().
             */

            fvdat->flag |= FN_GETATTR;
            fvdat->getattr_thread = getattr_thread;

            fuse_nodelock_unlock(fvdat);
            thread_deallocate(getattr_thread);
            goto out;

        } else {
            err = EIO;
            IOLog("osxfuse: could not start getattr thread\n");
        }
    }

    FUSE_KNOTE(vp, NOTE_WRITE | NOTE_ATTRIB);
    fuse_vnode_notify(vp, FUSE_VNODE_EVENT_WRITE | FUSE_VNODE_EVENT_ATTRIB);

    fuse_nodelock_unlock(fvdat);
    vnode_put(vp);

out:
    return err;
}

static
int
fuse_notify_delete_parent_callback(vnode_t dvp, uint64_t parentid)
{
    fuse_invalidate_attr(dvp);

    FUSE_KNOTE(dvp, NOTE_WRITE | NOTE_ATTRIB);
    fuse_vnode_notify(dvp, FUSE_VNODE_EVENT_WRITE | FUSE_VNODE_EVENT_ATTRIB);

    return 0;
}

static
int
fuse_notify_delete_file_callback(vnode_t vp, uint64_t fileid)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    if (fileid == fvdat->nodeid) {
        vfs_context_t context = vfs_context_create(NULL);

        fuse_nodelock_lock(fvdat, FUSEFS_EXCLUSIVE_LOCK);
        fuse_internal_vnode_disappear(vp, context, REVOKE_SOFT);
        fuse_nodelock_unlock(fvdat);

        vfs_context_rele(context);

        FUSE_KNOTE(vp, NOTE_DELETE);
        fuse_vnode_notify(vp, FUSE_VNODE_EVENT_DELETE);

    } else {
        fuse_vncache_purge(vp);
    }

    return 0;
}

__private_extern__
int
fuse_notify_delete(struct fuse_data *data, struct fuse_iov *iov)
{
    struct fuse_abi_data fndo;
    void *next;

    uint64_t parentid;
    uint64_t fileid;
    size_t namelen;
    char name[FUSE_MAXNAMLEN + 1];

    fuse_abi_data_init(&fndo, DATOI(data), iov->base);
    next = (char *)iov->base + fuse_notify_delete_out_sizeof(DATOI(data));

    parentid = fuse_notify_delete_out_get_parent(&fndo);
    fileid = fuse_notify_delete_out_get_child(&fndo);

    namelen = fuse_notify_delete_out_get_namelen(&fndo);
    if (namelen > iov->len - ((char *)next - (char *)iov->base)) {
        return EINVAL;
    }
    if (namelen > FUSE_MAXNAMLEN) {
        return ENAMETOOLONG;
    }
    memcpy(name, next, namelen);
    name[namelen] = '\0';

    return fuse_notify_lookup(data, parentid, fileid, name, namelen,
                              &fuse_notify_delete_parent_callback,
                              &fuse_notify_delete_file_callback);
}

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */
