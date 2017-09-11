/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2011 Anatol Pomozov
 * Copyright (c) 2011-2017 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_INTERNAL_H_
#define _FUSE_INTERNAL_H_

#include "fuse.h"

#include "fuse_ipc.h"
#include "fuse_locking.h"
#include "fuse_node.h"
#include "fuse_notify.h"

#include <fuse_ioctl.h>

#include <libkern/version.h>
#include <stdbool.h>
#include <sys/ubc.h>

struct fuse_attr;
struct fuse_filehandle;

/* msleep */

int
fuse_internal_msleep(void *chan, lck_mtx_t *mtx, int pri, const char *wmesg,
                     struct timespec *ts, struct fuse_data *data);

#ifdef FUSE_TRACE_MSLEEP
FUSE_INLINE
int
fuse_msleep(void *chan, lck_mtx_t *mtx, int pri, const char *wmesg,
            struct timespec *ts, struct fuse_data *data)
{
    int ret;

    IOLog("0: msleep(%p, %s)\n", (chan), (wmesg));
    ret = fuse_internal_msleep(chan, mtx, pri, wmesg, ts, data);
    IOLog("1: msleep(%p, %s)\n", (chan), (wmesg));

    return ret;
}
#define fuse_wakeup(chan)                          \
{                                                  \
    IOLog("1: wakeup(%p)\n", (chan));              \
    wakeup((chan));                                \
    IOLog("0: wakeup(%p)\n", (chan));              \
}
#define fuse_wakeup_one(chan)                      \
{                                                  \
    IOLog("1: wakeup_one(%p)\n", (chan));          \
    wakeup_one((chan));                            \
    IOLog("0: wakeup_one(%p)\n", (chan));          \
}
#else /* !FUSE_TRACE_MSLEEP*/
#define fuse_msleep(chan, mtx, pri, wmesg, ts, data) \
    fuse_internal_msleep((chan), (mtx), (pri), (wmesg), (ts), (data))
#define fuse_wakeup(chan)     wakeup((chan))
#define fuse_wakeup_one(chan) wakeup_one((chan))
#endif /* FUSE_TRACE_MSLEEP */

/* time */

#define fuse_timespec_add(vvp, uvp)            \
    do {                                       \
           (vvp)->tv_sec += (uvp)->tv_sec;     \
           (vvp)->tv_nsec += (uvp)->tv_nsec;   \
           if ((vvp)->tv_nsec >= 1000000000) { \
               (vvp)->tv_sec++;                \
               (vvp)->tv_nsec -= 1000000000;   \
           }                                   \
    } while (0)

#define fuse_timespec_cmp(tvp, uvp, cmp)       \
        (((tvp)->tv_sec == (uvp)->tv_sec) ?    \
         ((tvp)->tv_nsec cmp (uvp)->tv_nsec) : \
         ((tvp)->tv_sec cmp (uvp)->tv_sec))

/* miscellaneous */

#if M_OSXFUSE_ENABLE_UNSUPPORTED
extern const char *vnode_getname(vnode_t vp);
extern void  vnode_putname(const char *name);
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

FUSE_INLINE
int
fuse_match_cred(kauth_cred_t daemoncred, kauth_cred_t requestcred)
{
    if ((kauth_cred_getuid(daemoncred) == kauth_cred_getuid(requestcred)) &&
        (kauth_cred_getgid(daemoncred) == kauth_cred_getgid(requestcred))) {
        return 0;
    }

    return EPERM;
}

FUSE_INLINE
int
fuse_vfs_context_issuser(vfs_context_t context)
{
    return (kauth_cred_getuid(vfs_context_ucred(context)) == 0);
}

FUSE_INLINE
int
fuse_isautocache_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_AUTO_CACHE);
}

FUSE_INLINE
bool
fuse_isdeadfs_mp(mount_t mp)
{
    return fdata_dead_get(fuse_get_mpdata(mp));
}

FUSE_INLINE
bool
fuse_isdeadfs(vnode_t vp)
{
    if (VTOFUD(vp)->flag & FN_REVOKED) {
        return true;
    }

    return fuse_isdeadfs_mp(vnode_mount(vp));
}

FUSE_INLINE
bool
fuse_isdeadfs_fs(vnode_t vp)
{
    return fuse_isdeadfs_mp(vnode_mount(vp));
}

FUSE_INLINE
int
fuse_isdirectio(vnode_t vp)
{
    /* Try global first. */
    if (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_DIRECT_IO) {
        return 1;
    }

    return (VTOFUD(vp)->flag & FN_DIRECT_IO);
}

FUSE_INLINE
int
fuse_isdirectio_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_DIRECT_IO);
}

FUSE_INLINE
int
fuse_isnoattrcache(vnode_t vp)
{
    /* Try global first. */
    if (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_NO_ATTRCACHE) {
        return 1;
    }

    return 0;
}

FUSE_INLINE
int
fuse_isnoattrcache_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_ATTRCACHE);
}

FUSE_INLINE
int
fuse_isnoreadahead(vnode_t vp)
{
    /* Try global first. */
    if (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_NO_READAHEAD) {
        return 1;
    }

    /* In our model, direct_io implies no readahead. */
    return fuse_isdirectio(vp);
}

FUSE_INLINE
int
fuse_isnosynconclose(vnode_t vp)
{
    if (fuse_isdirectio(vp)) {
        return 0;
    }

    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_NO_SYNCONCLOSE);
}

FUSE_INLINE
int
fuse_isnosyncwrites_mp(mount_t mp)
{
    /* direct_io implies we won't have nosyncwrites. */
    if (fuse_isdirectio_mp(mp)) {
        return 0;
    }

    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_SYNCWRITES);
}

FUSE_INLINE
void
fuse_setnosyncwrites_mp(mount_t mp)
{
    vfs_clearflags(mp, MNT_SYNCHRONOUS);
    vfs_setflags(mp, MNT_ASYNC);
    fuse_get_mpdata(mp)->dataflags |= FSESS_NO_SYNCWRITES;
}

FUSE_INLINE
void
fuse_clearnosyncwrites_mp(mount_t mp)
{
    if (!vfs_issynchronous(mp)) {
        vfs_clearflags(mp, MNT_ASYNC);
        vfs_setflags(mp, MNT_SYNCHRONOUS);
        fuse_get_mpdata(mp)->dataflags &= ~FSESS_NO_SYNCWRITES;
    }
}

FUSE_INLINE
int
fuse_isnoubc(vnode_t vp)
{
    /* Try global first. */
    if (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_NO_UBC) {
        return 1;
    }

    /* In our model, direct_io implies no UBC. */
    return fuse_isdirectio(vp);
}

FUSE_INLINE
int
fuse_isnoubc_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_UBC);
}

FUSE_INLINE
int
fuse_isnegativevncache_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NEGATIVE_VNCACHE);
}

FUSE_INLINE
int
fuse_isnovncache(vnode_t vp)
{
    /* Try global first. */
    if (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_NO_VNCACHE) {
        return 1;
    }

    /* In our model, direct_io implies no vncache for this vnode. */
    return fuse_isdirectio(vp);
}

FUSE_INLINE
int
fuse_isnovncache_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_VNCACHE);
}

FUSE_INLINE
int
fuse_isextendedsecurity(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & \
            FSESS_EXTENDED_SECURITY);
}

FUSE_INLINE
int
fuse_isextendedsecurity_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_EXTENDED_SECURITY);
}

FUSE_INLINE
int
fuse_isdefaultpermissions(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & \
            FSESS_DEFAULT_PERMISSIONS);
}

FUSE_INLINE
int
fuse_isdefaultpermissions_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_DEFAULT_PERMISSIONS);
}

FUSE_INLINE
int
fuse_isdeferpermissions(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & \
            FSESS_DEFER_PERMISSIONS);
}

FUSE_INLINE
int
fuse_isdeferpermissions_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_DEFER_PERMISSIONS);
}

FUSE_INLINE
int
fuse_isxtimes(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_XTIMES);
}

FUSE_INLINE
int
fuse_isxtimes_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_XTIMES);
}

FUSE_INLINE
int
fuse_issparse_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_SPARSE);
}

FUSE_INLINE
uint32_t
fuse_round_powerof2(uint32_t size)
{
    uint32_t result = 128;
    size = size & 0x7FFFFFFFU; /* clip at 2G */

    while (result < size) {
        result <<= 1;
    }

    return result;
}

FUSE_INLINE
uint32_t
fuse_round_size(uint32_t size, uint32_t b_min, uint32_t b_max)
{
    uint32_t candidate = fuse_round_powerof2(size);

    /* We assume that b_min and b_max will already be powers of 2. */

    if (candidate < b_min) {
        candidate = b_min;
    }

    if (candidate > b_max) {
        candidate = b_max;
    }

    return candidate;
}

FUSE_INLINE
uint32_t
fuse_round_iosize(uint32_t size)
{
    return fuse_round_size(size, FUSE_MIN_IOSIZE, FUSE_MAX_IOSIZE);
}

#define DS_STORE ".DS_Store"

FUSE_INLINE
int
fuse_skip_apple_double_mp(mount_t mp, char *nameptr, long namelen)
{
    int ismpoption = fuse_get_mpdata(mp)->dataflags & FSESS_NO_APPLEDOUBLE;

    if (ismpoption && nameptr) {
        /* This _will_ allow just "._", that is, a namelen of 2. */
        if (namelen > 2) {
            if ((namelen == ((sizeof(DS_STORE)/sizeof(char)) - 1)) &&
                (bcmp(nameptr, DS_STORE, sizeof(DS_STORE)) == 0)) {
                return 1;
            } else if (nameptr[0] == '.' && nameptr[1] == '_') {
                return 1;
            }
        }
    }

    return 0;
}

#undef DS_STORE

FUSE_INLINE
int
fuse_blanket_deny(vnode_t vp, vfs_context_t context)
{
    mount_t mp = vnode_mount(vp);
    struct fuse_data *data = fuse_get_mpdata(mp);
    int issuser = fuse_vfs_context_issuser(context);
    int isvroot = vnode_isvroot(vp);

    /* if allow_other is set */
    if (data->dataflags & FSESS_ALLOW_OTHER) {
        return 0;
    }

    /* if allow_root is set */
    if (issuser && (data->dataflags & FSESS_ALLOW_ROOT)) {
        return 0;
    }

    /* if this is the user who mounted the fs */
    if (fuse_match_cred(data->daemoncred, vfs_context_ucred(context)) == 0) {
        return 0;
    }

    if (!(data->dataflags & FSESS_INITED) && isvroot && issuser) {
        return 0;
    }

    if (fuse_isdeadfs(vp) && isvroot) {
        return 0;
    }

    /* If kernel itself, allow. */
    if (vfs_context_pid(context) == 0) {
        return 0;
    }

    return 1;
}

#define CHECK_BLANKET_DENIAL(vp, context, err) \
    { \
        if (fuse_blanket_deny(vp, context)) { \
            return err; \
        } \
    }

/* access */

int
fuse_internal_access(vnode_t                   vp,
                     int                       action,
                     vfs_context_t             context);

/* attributes */

int
fuse_internal_loadxtimes(vnode_t vp, struct vnode_attr *out_vap,
                         vfs_context_t context);

int
fuse_internal_attr_vat2fsai(mount_t               mp,
                            vnode_t               vp,
                            struct vnode_attr    *vap,
                            struct fuse_abi_data *fsai,
                            uint64_t             *newsize);

FUSE_INLINE
void
fuse_internal_attr_fat2vat(vnode_t               vp,
                           struct fuse_abi_data *fat,
                           struct vnode_attr    *vap)
{
    struct timespec t;
    mount_t mp = vnode_mount(vp);
    struct fuse_data *data = fuse_get_mpdata(mp);
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    VATTR_INIT(vap);

    uint64_t ino = fuse_attr_get_ino(fat);

    VATTR_RETURN(vap, va_fsid, vfs_statfs(mp)->f_fsid.val[0]);
    VATTR_RETURN(vap, va_fileid, ino);
    VATTR_RETURN(vap, va_linkid, ino);

    /*
     * If we have asynchronous writes enabled, our local in-kernel size
     * takes precedence over what the daemon thinks.
     */
    /* ATTR_FUDGE_CASE */
    if (!vfs_issynchronous(mp)) {
        fuse_attr_set_size(fat, fvdat->filesize);
    }
    VATTR_RETURN(vap, va_data_size, fuse_attr_get_size(fat));

    /*
     * The kernel will compute the following for us if we leave them
     * untouched (and have sane values in statvfs):
     *
     * va_total_size
     * va_data_alloc
     * va_total_alloc
     */
    if (fuse_issparse_mp(mp)) {
        VATTR_RETURN(vap, va_data_alloc, fuse_attr_get_blocks(fat) * 512);
    }

    t.tv_sec = (typeof(t.tv_sec))fuse_attr_get_atime(fat); /* XXX: truncation */
    t.tv_nsec = fuse_attr_get_atimensec(fat);
    VATTR_RETURN(vap, va_access_time, t);

    t.tv_sec = (typeof(t.tv_sec))fuse_attr_get_ctime(fat); /* XXX: truncation */
    t.tv_nsec = fuse_attr_get_ctimensec(fat);
    VATTR_RETURN(vap, va_change_time, t);

    t.tv_sec = (typeof(t.tv_sec))fuse_attr_get_mtime(fat); /* XXX: truncation */
    t.tv_nsec = fuse_attr_get_mtimensec(fat);
    VATTR_RETURN(vap, va_modify_time, t);

    t.tv_sec = (typeof(t.tv_sec))fuse_attr_get_crtime(fat); /* XXX: truncation */
    t.tv_nsec = fuse_attr_get_crtimensec(fat);
    VATTR_RETURN(vap, va_create_time, t);

    VATTR_RETURN(vap, va_mode, fuse_attr_get_mode(fat) & ~S_IFMT);
    VATTR_RETURN(vap, va_nlink, fuse_attr_get_nlink(fat));
    VATTR_RETURN(vap, va_uid, fuse_attr_get_uid(fat));
    VATTR_RETURN(vap, va_gid, fuse_attr_get_gid(fat));
    VATTR_RETURN(vap, va_rdev, fuse_attr_get_rdev(fat));

    VATTR_RETURN(vap, va_type, IFTOVT(fuse_attr_get_mode(fat)));

    uint32_t blksize = fuse_attr_get_blksize(fat);
    if (blksize != 0) {
        blksize = fuse_round_iosize(blksize);
        if (blksize < data->blocksize) {
            blksize = data->blocksize;
        }
    } else {
        blksize = data->iosize;
    }
    fuse_attr_set_blksize(fat, blksize);
    VATTR_RETURN(vap, va_iosize, blksize);

    VATTR_RETURN(vap, va_flags, fuse_attr_get_flags(fat));
}

FUSE_INLINE
void
fuse_internal_attr_loadvap(vnode_t vp, struct vnode_attr *out_vap,
                           vfs_context_t context)
{
    mount_t mp = vnode_mount(vp);
    struct vnode_attr *in_vap = VTOVA(vp);
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    int purged = 0;
    uint32_t events = 0;
#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data;
#endif

    if (in_vap == out_vap) {
        return;
    }

#if M_OSXFUSE_ENABLE_BIG_LOCK
    data = fuse_get_mpdata(vnode_mount(vp));
#endif

    VATTR_RETURN(out_vap, va_fsid, in_vap->va_fsid);

    VATTR_RETURN(out_vap, va_fileid, in_vap->va_fileid);
    VATTR_RETURN(out_vap, va_linkid, in_vap->va_linkid);
    VATTR_RETURN(out_vap, va_gen,
        (typeof(out_vap->va_gen))fvdat->generation); /* XXX: truncation */
    if (!vnode_isvroot(vp)) {
        /*
         * If we do return va_parentid for our root vnode, things get
         * a bit too interesting for the Finder.
         */
        VATTR_RETURN(out_vap, va_parentid, fvdat->parent_nodeid);
    }

    /*
     * If we have asynchronous writes enabled, our local in-kernel size
     * takes precedence over what the daemon thinks.
     */
    /* ATTR_FUDGE_CASE */
    if (!vfs_issynchronous(mp)) {
        /* Bring in_vap up to date if need be. */
        VATTR_RETURN(in_vap,  va_data_size, fvdat->filesize);
    } else {
        /* The size might have changed remotely. */
        if (fvdat->filesize != (off_t)in_vap->va_data_size) {
            events |= FUSE_VNODE_EVENT_WRITE;
            /* Remote size overrides what we have. */
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            (void)ubc_msync(vp, (off_t)0, fvdat->filesize, NULL,
                            UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
            purged = 1;
            if (fvdat->filesize > (off_t)in_vap->va_data_size) {
                events |= FUSE_VNODE_EVENT_EXTEND;
            }
            fvdat->filesize = in_vap->va_data_size;
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            ubc_setsize(vp, fvdat->filesize);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
        }
    }
    VATTR_RETURN(out_vap, va_data_size, in_vap->va_data_size);

    if (fuse_issparse_mp(mp)) {
        VATTR_RETURN(out_vap, va_data_alloc, in_vap->va_data_alloc);
    }

    VATTR_RETURN(out_vap, va_mode, in_vap->va_mode);
    VATTR_RETURN(out_vap, va_nlink, in_vap->va_nlink);
    VATTR_RETURN(out_vap, va_uid, in_vap->va_uid);
    VATTR_RETURN(out_vap, va_gid, in_vap->va_gid);
    VATTR_RETURN(out_vap, va_rdev, in_vap->va_rdev);

    VATTR_RETURN(out_vap, va_type, in_vap->va_type);

    VATTR_RETURN(out_vap, va_iosize, in_vap->va_iosize);

    VATTR_RETURN(out_vap, va_flags, in_vap->va_flags);

    VATTR_RETURN(out_vap, va_access_time, in_vap->va_access_time);
    VATTR_RETURN(out_vap, va_change_time, in_vap->va_change_time);
    VATTR_RETURN(out_vap, va_modify_time, in_vap->va_modify_time);

    /*
     * When _DARWIN_FEATURE_64_BIT_INODE is not enabled, the User library will
     * set va_create_time to -1. In that case, we will have to ask for it
     * separately, if necessary.
     */
    if (in_vap->va_create_time.tv_sec != (int64_t)-1) {
        VATTR_RETURN(out_vap, va_create_time, in_vap->va_create_time);
    }

    if ((fvdat->modify_time.tv_sec != in_vap->va_modify_time.tv_sec) ||
        (fvdat->modify_time.tv_nsec != in_vap->va_modify_time.tv_nsec)) {
        fvdat->modify_time.tv_sec = in_vap->va_modify_time.tv_sec;
        fvdat->modify_time.tv_nsec = in_vap->va_modify_time.tv_nsec;
        events |= FUSE_VNODE_EVENT_ATTRIB;
        if (fuse_isautocache_mp(mp) && !purged) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            (void)ubc_msync(vp, (off_t)0, fvdat->filesize, NULL,
                            UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
        }
    }

    if (VATTR_IS_ACTIVE(out_vap, va_backup_time) ||
        (VATTR_IS_ACTIVE(out_vap, va_create_time) &&
         !VATTR_IS_SUPPORTED(out_vap, va_create_time))) {
        (void)fuse_internal_loadxtimes(vp, out_vap, context);
    }

    if (events) {
        fuse_vnode_notify(vp, events);
    }
}

#define cache_attrs(vp, struct_name, fuse_out) \
    do { \
        struct timespec uptsp_ ## __funct__; \
        struct fuse_abi_data fa_ ## __func__; \
        \
        /* XXX: truncation; user space sends us a 64-bit tv_sec */ \
        VTOFUD(vp)->attr_valid.tv_sec = (time_t)struct_name ## _get_attr_valid(fuse_out); \
        VTOFUD(vp)->attr_valid.tv_nsec = struct_name ## _get_attr_valid_nsec(fuse_out); \
        nanouptime(&uptsp_ ## __funct__); \
        \
        fuse_timespec_add(&VTOFUD(vp)->attr_valid, &uptsp_ ## __funct__); \
        \
        fuse_abi_data_init(&fa_ ## __func__, (fuse_out)->fad_version, struct_name ## _get_attr(fuse_out)); \
        fuse_internal_attr_fat2vat(vp, &fa_ ## __func__, VTOVA(vp)); \
    } while (0)

#if M_OSXFUSE_ENABLE_EXCHANGE

/* exchange */

int
fuse_internal_exchange(vnode_t       fvp,
                       const char   *fname,
                       size_t        flen,
                       vnode_t       tvp,
                       const char   *tname,
                       size_t        tlen,
                       int           options,
                       vfs_context_t context);

#endif /* M_OSXFUSE_ENABLE_EXCHANGE */

/* fsync */

int
fuse_internal_fsync_fh_callback(struct fuse_ticket *ftick, uio_t uio);

int
fuse_internal_fsync_fh(vnode_t                 vp,
                       vfs_context_t           context,
                       struct fuse_filehandle *fufh,
                       fuse_op_waitfor_t       waitfor);

int
fuse_internal_fsync_vp(vnode_t       vp,
                       vfs_context_t context);

/* readdir */

int
fuse_internal_readdir(vnode_t                 vp,
                      uio_t                   uio,
                      int                     flags,
                      vfs_context_t           context,
                      struct fuse_filehandle *fufh,
                      struct fuse_iov        *cookediov,
                      int                    *numdirent);

int
fuse_internal_readdir_processdata(vnode_t          vp,
                                  uio_t            uio,
                                  int              flags,
                                  size_t           reqsize,
                                  void            *buf,
                                  size_t           bufsize,
                                  struct fuse_iov *cookediov,
                                  int             *numdirent);

/* remove */

int
fuse_internal_remove(vnode_t               dvp,
                     vnode_t               vp,
                     struct componentname *cnp,
                     enum fuse_opcode      op,
                     vfs_context_t         context);

/* rename */

int
fuse_internal_rename(vnode_t               fdvp,
                     vnode_t               fvp,
                     struct componentname *fcnp,
                     vnode_t               tdvp,
                     vnode_t               tvp,
                     struct componentname *tcnp,
                     vfs_context_t         context);

/* revoke */

int
fuse_internal_revoke(vnode_t vp, int flags, vfs_context_t context, int how);

void
fuse_internal_vnode_disappear(vnode_t vp, vfs_context_t context, int how);

/* strategy */

int
fuse_internal_strategy(vnode_t vp, buf_t bp);

errno_t
fuse_internal_strategy_buf(struct vnop_strategy_args *ap);

/* xattr */

#define COM_APPLE_ "com.apple."

FUSE_INLINE
bool
fuse_skip_apple_xattr_mp(mount_t mp, const char *name)
{
    return name &&
           (fuse_get_mpdata(mp)->dataflags & FSESS_NO_APPLEXATTR) &&
           (bcmp(name, COM_APPLE_, sizeof(COM_APPLE_) - 1) == 0);
}

/* entity creation */

FUSE_INLINE
int
fuse_internal_checkentry(struct fuse_abi_data *feo, enum vtype vtype)
{
    struct fuse_abi_data fa;

    fuse_abi_data_init(&fa, feo->fad_version, fuse_entry_out_get_attr(feo));

    if (vtype != IFTOVT(fuse_attr_get_mode(&fa))) {
        return EINVAL;
    }

    if (fuse_entry_out_get_nodeid(feo) == FUSE_NULL_ID) {
        return EINVAL;
    }

    if (fuse_entry_out_get_nodeid(feo) == FUSE_ROOT_ID) {
        return EINVAL;
    }

    return 0;
}

int
fuse_internal_newentry(vnode_t               dvp,
                       vnode_t              *vpp,
                       struct componentname *cnp,
                       enum fuse_opcode      op,
                       void                 *buf,
                       size_t                bufsize,
                       enum vtype            vtype,
                       vfs_context_t         context);

void
fuse_internal_newentry_makerequest(mount_t                 mp,
                                   uint64_t                dnid,
                                   struct componentname   *cnp,
                                   enum fuse_opcode        op,
                                   void                   *buf,
                                   size_t                  bufsize,
                                   struct fuse_dispatcher *fdip,
                                   vfs_context_t           context);


int
fuse_internal_newentry_core(vnode_t                 dvp,
                            vnode_t                *vpp,
                            struct componentname   *cnp,
                            enum vtype              vtyp,
                            struct fuse_dispatcher *fdip,
                            vfs_context_t           context);

/* entity destruction */

int
fuse_internal_forget_callback(struct fuse_ticket *ftick, uio_t uio);

void
fuse_internal_forget_send(mount_t                 mp,
                          vfs_context_t           context,
                          uint64_t                nodeid,
                          uint64_t                nlookup,
                          struct fuse_dispatcher *fdip);

void
fuse_internal_interrupt_send(struct fuse_ticket *ftick);

void
fuse_internal_interrupt_remove(struct fuse_ticket *interrupt);

enum {
    REVOKE_NONE = 0,
    REVOKE_SOFT = 1,
    REVOKE_HARD = 2,
};

/* fuse start/stop */

void fuse_internal_init(struct fuse_data *data, vfs_context_t context);

/* other */

FUSE_INLINE
int
fuse_implemented(struct fuse_data *data, uint64_t which)
{
    int result;

    /* FUSE_DATA_LOCK_SHARED(data); */
    result = (int)!(data->noimplflags & which);
    /* FUSE_DATA_UNLOCK_SHARED(data); */

    return result;
}

FUSE_INLINE
void
fuse_clear_implemented(struct fuse_data *data, uint64_t which)
{
    /* FUSE_DATA_LOCK_EXCLUSIVE(data); */
    data->noimplflags |= which;
    /* FUSE_DATA_UNLOCK_EXCLUSIVE(data); */
}

void
fuse_internal_print_vnodes(mount_t mp);

void
fuse_preflight_log(vnode_t vp, fufh_type_t fufh_type, int err, char *message);

#endif /* _FUSE_INTERNAL_H_ */
