/*
 * Copyright (C) 2006-2007 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_INTERNAL_H_
#define _FUSE_INTERNAL_H_

#include <kern/clock.h>
#include <sys/types.h>
#include <sys/kauth.h>
#include <sys/kernel_types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/xattr.h>

#include <fuse_ioctl.h>
#include "fuse_ipc.h"
#include "fuse_kludges.h"
#include "fuse_locking.h"
#include "fuse_node.h"

#if M_MACFUSE_ENABLE_KUNC
#include <UserNotification/KUNCUserNotifications.h>
#else
enum {
    kKUNCDefaultResponse   = 0,
    kKUNCAlternateResponse = 1,
    kKUNCOtherResponse     = 2,
    kKUNCCancelResponse    = 3
};
#endif

struct fuse_attr;
struct fuse_data;
struct fuse_dispatcher;
struct fuse_filehandle;
struct fuse_iov;
struct fuse_ticket;

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

#if M_MACFUSE_ENABLE_UNSUPPORTED
extern char *vnode_getname(vnode_t vp);
extern void  vnode_putname(char *name);
#endif /* M_MACFUSE_ENABLE_UNSUPPORTED */

static __inline__
int
fuse_match_cred(kauth_cred_t daemoncred, kauth_cred_t requestcred)
{
    if ((daemoncred->cr_uid == requestcred->cr_uid)             &&  
        (daemoncred->cr_uid == requestcred->cr_ruid)            &&  

        // THINK_ABOUT_THIS_LATER
        // (daemoncred->cr_uid == requestcred->cr_svuid)        &&  

        (daemoncred->cr_groups[0] == requestcred->cr_groups[0]) &&
        (daemoncred->cr_groups[0] == requestcred->cr_rgid)      &&  
        (daemoncred->cr_groups[0] == requestcred->cr_svgid)) {
        return 0;
    }   

    return EPERM;
}

static __inline__
int
fuse_vfs_context_issuser(vfs_context_t context)
{
    return (vfs_context_ucred(context)->cr_uid == 0);
}

#define fuse_isdeadfs_nop(vp) 0

static __inline__
int
fuse_isdeadfs_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_DEAD);
}

static __inline__
int
fuse_isdeadfs(vnode_t vp)
{
    if (VTOFUD(vp)->flag & FN_REVOKED) {
        return 1;
    }

    return fuse_isdeadfs_mp(vnode_mount(vp));
}

static __inline__
int
fuse_isdeadfs_fs(vnode_t vp)
{
    return fuse_isdeadfs_mp(vnode_mount(vp));
}

static __inline__
int
fuse_isdirectio(vnode_t vp)
{
    /* Try global first. */
    if (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_DIRECT_IO) {
        return 1;
    }

    return (VTOFUD(vp)->flag & FN_DIRECT_IO);
}

static __inline__
int
fuse_isdirectio_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_DIRECT_IO);
}

static __inline__
int
fuse_isnoattrcache(vnode_t vp)
{
    /* Try global first. */
    if (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_NO_ATTRCACHE) {
        return 1;
    }

    return 0;
}

static __inline__
int
fuse_isnoattrcache_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_ATTRCACHE);
}

static __inline__
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

static __inline__
int
fuse_isnosynconclose(vnode_t vp)
{
    if (fuse_isdirectio(vp)) {
        return 0;
    }

    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_NO_SYNCONCLOSE);
}

static __inline__
int
fuse_isnosyncwrites_mp(mount_t mp)
{
    /* direct_io implies we won't have nosyncwrites. */
    if (fuse_isdirectio_mp(mp)) {
        return 0;
    }

    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_SYNCWRITES);
}

static __inline__
void
fuse_setnosyncwrites_mp(mount_t mp)
{
    vfs_clearflags(mp, MNT_SYNCHRONOUS);
    vfs_setflags(mp, MNT_ASYNC);
    fuse_get_mpdata(mp)->dataflags |= FSESS_NO_SYNCWRITES;
}

static __inline__
void
fuse_clearnosyncwrites_mp(mount_t mp)
{
    if (!vfs_issynchronous(mp)) {
        vfs_clearflags(mp, MNT_ASYNC);
        vfs_setflags(mp, MNT_SYNCHRONOUS);
        fuse_get_mpdata(mp)->dataflags &= ~FSESS_NO_SYNCWRITES;
    }
}

static __inline__
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

static __inline__
int
fuse_isnoubc_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_UBC);
}

static __inline__
int
fuse_isnegativevncache_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NEGATIVE_VNCACHE);
}

static __inline__
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

static __inline__
int
fuse_isnovncache_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_NO_VNCACHE);
}

static __inline__
int
fuse_isextendedsecurity(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & \
            FSESS_EXTENDED_SECURITY);
}

static __inline__
int
fuse_isextendedsecurity_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_EXTENDED_SECURITY);
}

static __inline__
int
fuse_isdefaultpermissions(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & \
            FSESS_DEFAULT_PERMISSIONS);
}

static __inline__
int
fuse_isdefaultpermissions_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_DEFAULT_PERMISSIONS);
}

static __inline__
int
fuse_isdeferpermissions(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & \
            FSESS_DEFER_PERMISSIONS);
}

static __inline__
int
fuse_isdeferpermissions_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_DEFER_PERMISSIONS);
}

static __inline__
int
fuse_isxtimes(vnode_t vp)
{
    return (fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_XTIMES);
}

static __inline__
int
fuse_isxtimes_mp(mount_t mp)
{
    return (fuse_get_mpdata(mp)->dataflags & FSESS_XTIMES);
}

static __inline__
uint32_t
fuse_round_powerof2(uint32_t size)
{
    uint32_t result = 512;

    while (result < size) {
        result <<= 1;
    }

    return result;
}

static __inline__
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

static __inline__
int
fuse_skip_apple_double_mp(mount_t mp, char *nameptr, long namelen)
{
#define DS_STORE ".DS_Store"
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

static __inline__
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

    return 1;
}

#define CHECK_BLANKET_DENIAL(vp, context, err) \
    { \
        if (fuse_blanket_deny(vp, context)) { \
            return err; \
        } \
    }

/* access */

/* FN_ACCESS_NOOP is in fuse_node.h */

#define FACCESS_VA_VALID   0x00000001
#define FACCESS_DO_ACCESS  0x00000002
#define FACCESS_NOCHECKSPY 0x00000004
#define FACCESS_FROM_VNOP  0x00000008

struct fuse_access_param {
    uid_t    xuid;
    gid_t    xgid;
    uint32_t facc_flags;
};

int
fuse_internal_access(vnode_t                   vp,
                     int                       action,
                     vfs_context_t             context,
                     struct fuse_access_param *facp);

/* attributes */

int
fuse_internal_loadxtimes(vnode_t vp, struct vnode_attr *out_vap,
                         vfs_context_t context);

static __inline__
void
fuse_internal_attr_fat2vat(vnode_t            vp,
                           struct fuse_attr  *fat,
                           struct vnode_attr *vap)
{
    struct timespec t;
    mount_t mp = vnode_mount(vp);
    struct fuse_data *data = fuse_get_mpdata(mp);

    VATTR_INIT(vap);

    VATTR_RETURN(vap, va_fsid, vfs_statfs(mp)->f_fsid.val[0]);
    VATTR_RETURN(vap, va_fileid, fat->ino);
    VATTR_RETURN(vap, va_linkid, fat->ino);

    /*
     * If we have asynchronous writes enabled, our local in-kernel size
     * takes precedence over what the daemon thinks.
     */
    /* ATTR_FUDGE_CASE */
    if (!vfs_issynchronous(mp)) {
        struct fuse_vnode_data *fvdat = VTOFUD(vp);
        fat->size = fvdat->filesize;    
    }
    VATTR_RETURN(vap, va_data_size, fat->size);

    /*
     * The kernel will compute the following for us if we leave them
     * untouched (and have sane values in statvfs):
     *
     * va_total_size
     * va_data_alloc
     * va_total_alloc
     */

    t.tv_sec = (typeof(t.tv_sec))fat->atime; /* XXX: truncation */
    t.tv_nsec = fat->atimensec;
    VATTR_RETURN(vap, va_access_time, t);

    t.tv_sec = (typeof(t.tv_sec))fat->ctime; /* XXX: truncation */
    t.tv_nsec = fat->ctimensec;
    VATTR_RETURN(vap, va_change_time, t);

    t.tv_sec = (typeof(t.tv_sec))fat->mtime; /* XXX: truncation */
    t.tv_nsec = fat->mtimensec;
    VATTR_RETURN(vap, va_modify_time, t);

    VATTR_RETURN(vap, va_mode, fat->mode & ~S_IFMT);
    VATTR_RETURN(vap, va_nlink, fat->nlink);
    VATTR_RETURN(vap, va_uid, fat->uid);
    VATTR_RETURN(vap, va_gid, fat->gid);
    VATTR_RETURN(vap, va_rdev, fat->rdev);

    /*
     * If the file in question has ACLs, we record that knowledge here:
     *
     *    VTOFUD(vp)->flag |= FN_HAS_ACL;
     */

    VATTR_RETURN(vap, va_type, IFTOVT(fat->mode));

    VATTR_RETURN(vap, va_iosize, data->iosize);

    VATTR_RETURN(vap, va_flags, fat->flags);
}

static __inline__
void
fuse_internal_attr_loadvap(vnode_t vp, struct vnode_attr *out_vap,
                           vfs_context_t context)
{
    mount_t mp = vnode_mount(vp);
    struct vnode_attr *in_vap = VTOVA(vp);
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    if (in_vap == out_vap) {
        return;
    }

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
        VATTR_RETURN(out_vap, va_data_size, fvdat->filesize);
        VATTR_RETURN(in_vap,  va_data_size, fvdat->filesize);
    } else {
#if WORKS_ON_TIGER_BUT_NOT_ON_LEOPARD
        VATTR_RETURN(out_vap, va_data_size, in_vap->va_data_size);
#endif
        VATTR_RETURN(out_vap, va_data_size, fvdat->filesize);
        VATTR_RETURN(in_vap,  va_data_size, fvdat->filesize);
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

    (void)fuse_internal_loadxtimes(vp, out_vap, context);
}

/*
 * XXX: truncation
 * Note that user space sends us a 64-bit tv_sec.
 */
#define cache_attrs(vp, fuse_out) do {                               \
    struct timespec uptsp_ ## __func__;                              \
                                                                     \
    VTOFUD(vp)->attr_valid.tv_sec = (fuse_out)->attr_valid;          \
    VTOFUD(vp)->attr_valid.tv_nsec = (fuse_out)->attr_valid_nsec;    \
    nanouptime(&uptsp_ ## __func__);                                 \
                                                                     \
    fuse_timespec_add(&VTOFUD(vp)->attr_valid, &uptsp_ ## __func__); \
                                                                     \
    fuse_internal_attr_fat2vat(vp, &(fuse_out)->attr, VTOVA(vp));    \
} while (0)

#if M_MACFUSE_ENABLE_EXCHANGE

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

#endif /* M_MACFUSE_ENABLE_EXCHANGE */
                       
/* fsync */

int
fuse_internal_fsync(vnode_t                 vp,
                    vfs_context_t           context,
                    struct fuse_filehandle *fufh,
                    void                   *param,
                    fuse_op_waitfor_t       waitfor);

int
fuse_internal_fsync_callback(struct fuse_ticket *ftick, uio_t uio);

/* ioctl */

int
fuse_internal_ioctl_avfi(vnode_t                 vp,
                         vfs_context_t           context,
                         struct fuse_avfi_ioctl *avfi);

/* readdir */

struct pseudo_dirent {
    uint32_t d_namlen;
};

int
fuse_internal_readdir(vnode_t                 vp,
                      uio_t                   uio,
                      vfs_context_t           context,
                      struct fuse_filehandle *fufh,
                      struct fuse_iov        *cookediov,
                      int                    *numdirent);

int
fuse_internal_readdir_processdata(vnode_t          vp,
                                  uio_t            uio,
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

static __inline__
int
fuse_skip_apple_xattr_mp(mount_t mp, const char *name)
{
    int ismpoption = fuse_get_mpdata(mp)->dataflags & FSESS_NO_APPLEXATTR;

    if (ismpoption && name) {
         #define COM_APPLE_ "com.apple."
        if (bcmp(name, COM_APPLE_, sizeof(COM_APPLE_) - 1) == 0) {
            return 1;
        }
    }

    return 0;
}


/* entity creation */

static __inline__
int
fuse_internal_checkentry(struct fuse_entry_out *feo, enum vtype vtype)
{
    if (vtype != IFTOVT(feo->attr.mode)) {
        return EINVAL;
    }

    if (feo->nodeid == FUSE_NULL_ID) {
        return EINVAL;
    }

    if (feo->nodeid == FUSE_ROOT_ID) {
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

enum {
    REVOKE_NONE = 0,
    REVOKE_SOFT = 1,
    REVOKE_HARD = 2,
};

/* fuse start/stop */

int fuse_internal_init_synchronous(struct fuse_ticket *ftick);
int fuse_internal_send_init(struct fuse_data *data, vfs_context_t context);

/* other */

static __inline__
int
fuse_implemented(struct fuse_data *data, uint64_t which)
{
    int result;

    /* FUSE_DATA_LOCK_SHARED(data); */
    result = !(int)(data->noimplflags & which);
    /* FUSE_DATA_UNLOCK_SHARED(data); */

    return result;
}

static __inline__
void
fuse_clear_implemented(struct fuse_data *data, uint64_t which) 
{
    /* FUSE_DATA_LOCK_EXCLUSIVE(data); */
    data->noimplflags |= which;
    /* FUSE_DATA_UNLOCK_EXCLUSIVE(data); */
}

static __inline__
int
fuse_set_implemented_custom(struct fuse_data *data, uint64_t flags)
{
    if (!data) {
        return EINVAL;
    }

    FUSE_DATA_LOCK_EXCLUSIVE(data);
    data->noimplflags = flags;
    FUSE_DATA_UNLOCK_EXCLUSIVE(data);

    return 0;
}

void
fuse_internal_print_vnodes(mount_t mp);

void
fuse_preflight_log(vnode_t vp, fufh_type_t fufh_type, int err, char *message);

#endif /* _FUSE_INTERNAL_H_ */
