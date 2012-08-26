/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2012 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_IPC_H_
#define _FUSE_IPC_H_

#include "fuse.h"

#include "fuse_device.h"

#if M_OSXFUSE_ENABLE_DSELECT
#  include "fuse_kludges.h"
#endif

#if M_OSXFUSE_ENABLE_BIG_LOCK
#  include "fuse_locking.h"
#endif

#include <stdbool.h>
#include <sys/kauth.h>
#include <sys/queue.h>

struct fuse_iov {
    void   *base;
    size_t  len;
    size_t  allocated_size;
    ssize_t credit;
};

#define FUSE_DATA_LOCK_SHARED(d)      fuse_lck_rw_lock_shared((d)->rwlock)
#define FUSE_DATA_LOCK_EXCLUSIVE(d)   fuse_lck_rw_lock_exclusive((d)->rwlock)
#define FUSE_DATA_UNLOCK_SHARED(d)    fuse_lck_rw_unlock_shared((d)->rwlock)
#define FUSE_DATA_UNLOCK_EXCLUSIVE(d) fuse_lck_rw_unlock_exclusive((d)->rwlock)

void fiov_init(struct fuse_iov *fiov, size_t size);
void fiov_teardown(struct fuse_iov *fiov);
void fiov_refresh(struct fuse_iov *fiov);
void fiov_adjust(struct fuse_iov *fiov, size_t size);
int  fiov_adjust_canfail(struct fuse_iov *fiov, size_t size);

#define FUSE_DIMALLOC(fiov, spc1, spc2, amnt)          \
do {                                                   \
    fiov_adjust(fiov, (sizeof(*(spc1)) + (amnt)));     \
    (spc1) = (fiov)->base;                             \
    (spc2) = (char *)(fiov)->base + (sizeof(*(spc1))); \
} while (0)

#define FU_AT_LEAST(siz) max((size_t)(siz), (size_t)160)

struct fuse_ticket;
struct fuse_data;

typedef int fuse_handler_t(struct fuse_ticket *ftick, uio_t uio);

struct fuse_ticket {
    uint64_t                     tk_unique;
    struct fuse_data            *tk_data;
    int                          tk_flag;
    uint32_t                     tk_age;
    uint32_t                     tk_ref_count;
    struct fuse_ticket          *tk_interrupt;

    STAILQ_ENTRY(fuse_ticket)    tk_freetickets_link;
    TAILQ_ENTRY(fuse_ticket)     tk_alltickets_link;

    struct fuse_iov              tk_ms_fiov;
    void                        *tk_ms_bufdata;
    size_t                       tk_ms_bufsize;
    enum { FT_M_FIOV, FT_M_BUF } tk_ms_type;
    STAILQ_ENTRY(fuse_ticket)    tk_ms_link;

    struct fuse_iov              tk_aw_fiov;
    void                        *tk_aw_bufdata;
    size_t                       tk_aw_bufsize;
    enum { FT_A_FIOV, FT_A_BUF } tk_aw_type;

    struct fuse_out_header       tk_aw_ohead;
    int                          tk_aw_errno;
    lck_mtx_t                   *tk_aw_mtx;
    fuse_handler_t              *tk_aw_handler;
    TAILQ_ENTRY(fuse_ticket)     tk_aw_link;
};

#define FT_ANSW  0x01  // request of ticket has already been answered
#define FT_INVAL 0x02  // ticket is invalidated
#define FT_DIRTY 0x04  // ticket has been used
#define FT_KILLL 0x08  // ticket has been marked for death (KILLL => KILL_LATER)

static __inline__
struct fuse_iov *
fticket_resp(struct fuse_ticket *ftick)
{
    return &ftick->tk_aw_fiov;
}

static __inline__
int
fticket_answered(struct fuse_ticket *ftick)
{
    return (ftick->tk_flag & FT_ANSW);
}

static __inline__
void
fticket_set_answered(struct fuse_ticket *ftick)
{
    ftick->tk_flag |= FT_ANSW;
}

static __inline__
void
fticket_set_killl(struct fuse_ticket *ftick)
{
    ftick->tk_flag |= FT_KILLL;
}

static __inline__
enum fuse_opcode
fticket_opcode(struct fuse_ticket *ftick)
{
    return (((struct fuse_in_header *)(ftick->tk_ms_fiov.base))->opcode);
}

int fticket_pull(struct fuse_ticket *ftick, uio_t uio);

enum mount_state { FM_NOTMOUNTED, FM_MOUNTED };

struct fuse_abi_version {
    uint32_t major;
    uint32_t minor;
};

struct fuse_data {
    fuse_device_t              fdev;
    mount_t                    mp;
    vnode_t                    rootvp;
    enum mount_state           mount_state;
    kauth_cred_t               daemoncred;
    pid_t                      daemonpid;
    uint32_t                   dataflags;     /* effective fuse_data flags */
    uint64_t                   mountaltflags; /* as-is copy of altflags    */
    uint64_t                   noimplflags;   /* not-implemented flags     */

#if M_OSXFUSE_ENABLE_DSELECT
    struct fuse_selinfo        d_rsel;
#endif /* M_OSXFUSE_ENABLE_DSELECT */

    lck_rw_t                  *rwlock;

    lck_mtx_t                 *ms_mtx;
    STAILQ_HEAD(, fuse_ticket) ms_head;

    lck_mtx_t                 *aw_mtx;
    TAILQ_HEAD(, fuse_ticket)  aw_head;

    lck_mtx_t                 *ticket_mtx;
    STAILQ_HEAD(, fuse_ticket) freetickets_head;
    TAILQ_HEAD(, fuse_ticket)  alltickets_head;
    uint32_t                   freeticket_counter;
    uint32_t                   deadticket_counter;
    uint64_t                   ticketer;

#if M_OSXFUSE_EXPLICIT_RENAME_LOCK
    lck_rw_t                  *rename_lock;
#endif /* M_OSXFUSE_EXPLICIT_RENAME_LOCK */

    struct fuse_abi_version    abi_version;

    uint32_t                   max_write;
    uint32_t                   max_read;
    uint32_t                   blocksize;
    uint32_t                   iosize;
    uint32_t                   userkernel_bufsize;
    uint32_t                   fssubtype;
    char                       volname[MAXPATHLEN];

    struct timespec            daemon_timeout;
    struct timespec           *daemon_timeout_p;
    struct timespec            init_timeout;
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_t            *biglock;
#endif
};

enum {
    FUSE_DAEMON_TIMEOUT_NONE       = 0,
    FUSE_DAEMON_TIMEOUT_PROCESSING = 1,
    FUSE_DAEMON_TIMEOUT_DEAD       = 2,
};

/* Not-Implemented Bits */
#define FSESS_NOIMPLBIT(MSG)      (1ULL << FUSE_##MSG)

#define FSESS_DEAD                0x00000001 // session is to be closed
#define FSESS_OPENED              0x00000002 // session device has been opened
#define FSESS_INITED              0x00000004 // session has been inited
#define FSESS_UNCONSCIOUS         0x00000008 // session is temporarily gone

#define FSESS_ALLOW_OTHER         0x00000010
#define FSESS_ALLOW_ROOT          0x00000020
#define FSESS_AUTO_XATTR          0x00000040
#define FSESS_DEFAULT_PERMISSIONS 0x00000080
#define FSESS_DEFER_PERMISSIONS   0x00000100
#define FSESS_DIRECT_IO           0x00000200
#define FSESS_EXTENDED_SECURITY   0x00000400
#define FSESS_JAIL_SYMLINKS       0x00000800
#define FSESS_KILL_ON_UNMOUNT     0x00001000
#define FSESS_LOCALVOL            0x00002000
#define FSESS_NEGATIVE_VNCACHE    0x00004000
#define FSESS_NO_APPLEDOUBLE      0x00010000
#define FSESS_NO_APPLEXATTR       0x00020000
#define FSESS_NO_ATTRCACHE        0x00040000
#define FSESS_NO_READAHEAD        0x00080000
#define FSESS_NO_SYNCONCLOSE      0x00100000
#define FSESS_NO_SYNCWRITES       0x00200000
#define FSESS_NO_UBC              0x00400000
#define FSESS_NO_VNCACHE          0x00800000
#define FSESS_CASE_INSENSITIVE    0x01000000
#define FSESS_VOL_RENAME          0x02000000
#define FSESS_XTIMES              0x04000000
#define FSESS_AUTO_CACHE          0x08000000
#define FSESS_NATIVE_XATTR        0x10000000
#define FSESS_SPARSE              0x20000000
#define FSESS_SLOW_STATFS         0x40000000

static __inline__
struct fuse_data *
fuse_get_mpdata(mount_t mp)
{
    /*
     * data->mount_state should be FM_MOUNTED for it to be valid
     */
    return (struct fuse_data *)vfs_fsprivate(mp);
}

static __inline__
void
fuse_ms_push(struct fuse_ticket *ftick)
{
    STAILQ_INSERT_TAIL(&ftick->tk_data->ms_head, ftick, tk_ms_link);
}

static __inline__
void
fuse_ms_push_head(struct fuse_ticket *ftick)
{
    STAILQ_INSERT_HEAD(&ftick->tk_data->ms_head, ftick, tk_ms_link);
}

static __inline__
struct fuse_ticket *
fuse_ms_pop(struct fuse_data *data)
{
    struct fuse_ticket *ftick = NULL;

    if ((ftick = STAILQ_FIRST(&data->ms_head))) {
        STAILQ_REMOVE_HEAD(&data->ms_head, tk_ms_link);
    }

    return ftick;
}

static __inline__
void
fuse_aw_push(struct fuse_ticket *ftick)
{
    TAILQ_INSERT_TAIL(&ftick->tk_data->aw_head, ftick, tk_aw_link);
}

static __inline__
void
fuse_aw_remove(struct fuse_ticket *ftick)
{
    TAILQ_REMOVE(&ftick->tk_data->aw_head, ftick, tk_aw_link);
}

static __inline__
struct fuse_ticket *
fuse_aw_pop(struct fuse_data *data)
{
    struct fuse_ticket *ftick = NULL;

    if ((ftick = TAILQ_FIRST(&data->aw_head))) {
        fuse_aw_remove(ftick);
    }

    return ftick;
}

struct fuse_ticket *fuse_ticket_fetch(struct fuse_data *data);
void fuse_ticket_drop(struct fuse_ticket *ftick);
void fuse_ticket_drop_invalid(struct fuse_ticket *ftick);
void fuse_ticket_kill(struct fuse_ticket *ftick);

#ifndef OSCompareAndSwap
#  define OSCompareAndSwap(a, b, c) OSCompareAndSwap(a, b, (volatile UInt32*)c)
#endif

/*
 * Increases the reference count of the specified ticket.
 */
static __inline__
void
fuse_ticket_retain(struct fuse_ticket *ticket)
{
    int count;

    do {
        count = ticket->tk_ref_count;
    } while (!OSCompareAndSwap(count, count + 1, &(ticket->tk_ref_count)));

    if (count == 0) {
        panic("OSXFUSE: fuse_ticket_retain: ticket reference count is 0");
    }
}

/*
 * Decrements the reference count of the specified ticket. If the count reaches
 * 0 the ticket is dropped instantly.
 */
static __inline__
void
fuse_ticket_release(struct fuse_ticket *ticket) {
    int count;

    do {
        count = ticket->tk_ref_count;
    } while (!OSCompareAndSwap(count, count - 1, &(ticket->tk_ref_count)));

    if (count == 0) {
        panic("OSXFUSE: fuse_ticket_release: ticket reference count is 0");
    }
    if (count == 1) {
        if (ticket->tk_interrupt) {
            struct fuse_ticket *interrupt = ticket->tk_interrupt;
            ticket->tk_interrupt = NULL;
            fuse_ticket_release(interrupt);
        }
        fuse_ticket_drop(ticket);
    }
}

void fuse_insert_callback(struct fuse_ticket *ftick, fuse_handler_t *handler);
void fuse_remove_callback(struct fuse_ticket *ftick);
void fuse_insert_message(struct fuse_ticket *ftick);
void fuse_insert_message_head(struct fuse_ticket *ftick);

struct fuse_data *fdata_alloc(struct proc *p);
void fdata_destroy(struct fuse_data *data);
bool fdata_dead_get(struct fuse_data *data);
bool fdata_set_dead(struct fuse_data *data);

struct fuse_dispatcher {

    struct fuse_ticket    *tick;
    struct fuse_in_header *finh;

    void    *indata;
    size_t   iosize;
    uint64_t nodeid;
    int      answ_stat;
    void    *answ;
};

static __inline__
void
fdisp_init(struct fuse_dispatcher *fdisp, size_t iosize)
{
    fdisp->iosize = iosize;
    fdisp->tick = NULL;
}

#define fdisp_init_abi(fdisp, name, abi_version) \
    fdisp_init((fdisp), fuse_abi_sizeof(name, (abi_version)))

void fdisp_make(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                mount_t mp, uint64_t nid, vfs_context_t context);

int  fdisp_make_canfail(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                        mount_t mp, uint64_t nid, vfs_context_t context);

void fdisp_make_vp(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                   vnode_t vp, vfs_context_t context);

int  fdisp_make_vp_canfail(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                           vnode_t vp, vfs_context_t context);

int  fdisp_wait_answ(struct fuse_dispatcher *fdip);

static __inline__
int
fdisp_simple_putget_vp(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                       vnode_t vp, vfs_context_t context)
{
    fdisp_init(fdip, 0);
    fdisp_make_vp(fdip, op, vp, context);
    return fdisp_wait_answ(fdip);
}

/*
 * FUSE ABI helpers
 */
#define FUSE_ABI_709 709
#define FUSE_ABI_710 710
#define FUSE_ABI_711 711
#define FUSE_ABI_712 712

#define ABITOI(abi_version) 100 * abi_version->major + abi_version->minor

#define DTOABI(data) &(data->abi_version)

/*
 * Returns true, if the specified FUSE operation is supported in the ABI version
 * used to communicate with FUSE server.
 */
static __inline__
bool
fuse_abi_is_op_supported(struct fuse_abi_version *abi_version,
                         enum fuse_opcode op)
{
    switch (op) {
        case FUSE_IOCTL:
        case FUSE_POLL:
            return ABITOI(abi_version) >= FUSE_ABI_712;
            break;
        default:
            return true; /* ABI 7.8 */
    }
}

/*
 * Returns true, if the specified FUSE notification is supported in the ABI
 * version used to communicate with the FUSE server.
 */
static __inline__
bool
fuse_abi_is_notify_supported(struct fuse_abi_version *abi_version, int notify)
{
    /* Unsolicited notification require at least ABI 7.11 */
    if (ABITOI(abi_version) < FUSE_ABI_711 ||
        notify < 0 ||
        notify >= FUSE_NOTIFY_CODE_MAX) {
        return false;
    }

    switch (notify) {
        case FUSE_NOTIFY_INVAL_INODE:
        case FUSE_NOTIFY_INVAL_ENTRY:
            return ABITOI(abi_version) >= FUSE_ABI_712;
            break;
        default:
            return true; /* ABI 7.11 */
    }
}

/*
 * Returns the size of the specified data structures given the FUSE ABI version
 * used to communicate with the user space daemon.
 */
#define fuse_abi_sizeof(name, abi_version) \
    fuse_abi_impl_sizeof_##name(abi_version)
#define fuse_abi_sizeof_p(name) &fuse_abi_impl_sizeof_##name

typedef size_t (*fuse_abi_sizeof_t)(struct fuse_abi_version *);

#define FUSE_ABI_SIZEOF_IMPL(NAME, COMMANDS)                                   \
    static __inline__                                                          \
    size_t                                                                     \
    fuse_abi_impl_sizeof_##NAME(__unused struct fuse_abi_version *abi_version) \
    {                                                                          \
        COMMANDS                                                               \
        return sizeof(struct NAME);                                            \
    }

FUSE_ABI_SIZEOF_IMPL(fuse_attr,
                     if (ABITOI(abi_version) < FUSE_ABI_709) {
                         return 96;
                     })
FUSE_ABI_SIZEOF_IMPL(fuse_kstatfs, )
FUSE_ABI_SIZEOF_IMPL(fuse_file_lock, )
FUSE_ABI_SIZEOF_IMPL(fuse_entry_out,
                     return 40 + fuse_abi_sizeof(fuse_attr, abi_version);)
FUSE_ABI_SIZEOF_IMPL(fuse_forget_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_getattr_in,
                     if (ABITOI(abi_version) < FUSE_ABI_709) {
                         return 0;
                     })
FUSE_ABI_SIZEOF_IMPL(fuse_attr_out,
                  return 16 + fuse_abi_sizeof(fuse_attr, abi_version);)
FUSE_ABI_SIZEOF_IMPL(fuse_getxtimes_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_mknod_in,
                     if (ABITOI(abi_version) < FUSE_ABI_712) {
                         return FUSE_COMPAT_MKNOD_IN_SIZE;
                     })
FUSE_ABI_SIZEOF_IMPL(fuse_mkdir_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_rename_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_exchange_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_link_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_setattr_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_open_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_create_in,
                     if (ABITOI(abi_version) < FUSE_ABI_712) {
                         return fuse_abi_sizeof(fuse_open_in, abi_version);
                     })
FUSE_ABI_SIZEOF_IMPL(fuse_open_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_release_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_flush_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_read_in,
                     if (ABITOI(abi_version) < FUSE_ABI_709) {
                         return 24;
                     })
FUSE_ABI_SIZEOF_IMPL(fuse_write_in,
                     if (ABITOI(abi_version) < FUSE_ABI_709) {
                         return FUSE_COMPAT_WRITE_IN_SIZE;
                     })
FUSE_ABI_SIZEOF_IMPL(fuse_write_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_statfs_out,
                     return fuse_abi_sizeof(fuse_kstatfs, abi_version);)
FUSE_ABI_SIZEOF_IMPL(fuse_fsync_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_setxattr_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_getxattr_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_getxattr_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_lk_in,
                     return 16 + fuse_abi_sizeof(fuse_file_lock, abi_version);)
FUSE_ABI_SIZEOF_IMPL(fuse_lk_out,
                     return fuse_abi_sizeof(fuse_file_lock, abi_version);)
FUSE_ABI_SIZEOF_IMPL(fuse_access_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_init_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_init_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_interrupt_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_bmap_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_bmap_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_ioctl_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_ioctl_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_poll_in, )
FUSE_ABI_SIZEOF_IMPL(fuse_poll_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_notify_poll_wakeup_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_dirent, )
FUSE_ABI_SIZEOF_IMPL(fuse_notify_inval_inode_out, )
FUSE_ABI_SIZEOF_IMPL(fuse_notify_inval_entry_out, )

/*
 * Translates the specified FUSE output data structure at the input pointer to
 * the native FUSE ABI version implemented by this kernel extension and writes
 * it to the given output pointer.
 */
#define fuse_abi_out(name, abi_version, inp, outp) \
    fuse_abi_impl_out_##name((abi_version), (inp), (outp))

typedef void *(*fuse_abi_out_t)(struct fuse_abi_version *, void *, void *);
#define fuse_abi_out_p(name) &fuse_abi_impl_out_##name

#define FUSE_ABI_OUT_IMPL(NAME, COMMANDS)                                      \
    static __inline__                                                         \
    void *                                                                    \
    fuse_abi_impl_out_##NAME(struct fuse_abi_version *abi_version, void *inp, \
                             void *outp)                                      \
    {                                                                         \
        size_t abi_size = fuse_abi_sizeof(NAME, abi_version);                 \
        if (sizeof(struct NAME) > abi_size) {                                 \
            bzero(outp, sizeof(struct NAME));                                 \
        }                                                                     \
        memcpy(outp, inp, min(sizeof(struct NAME), abi_size));                \
        COMMANDS                                                              \
        return (void *)((char *)inp + abi_size);                              \
    }

FUSE_ABI_OUT_IMPL(fuse_entry_out, )     /* attr.blksize = 0 (< ABI 7.9) */
FUSE_ABI_OUT_IMPL(fuse_attr_out, )      /* attr.blksize = 0 (< ABI 7.9) */
FUSE_ABI_OUT_IMPL(fuse_getxtimes_out, )
FUSE_ABI_OUT_IMPL(fuse_open_out, )
FUSE_ABI_OUT_IMPL(fuse_write_out, )
FUSE_ABI_OUT_IMPL(fuse_statfs_out, )
FUSE_ABI_OUT_IMPL(fuse_getxattr_out, )
FUSE_ABI_OUT_IMPL(fuse_lk_out, )
FUSE_ABI_OUT_IMPL(fuse_init_out, )
FUSE_ABI_OUT_IMPL(fuse_bmap_out, )
FUSE_ABI_OUT_IMPL(fuse_ioctl_out, )
FUSE_ABI_OUT_IMPL(fuse_poll_out, )
FUSE_ABI_OUT_IMPL(fuse_notify_poll_wakeup_out, )
FUSE_ABI_OUT_IMPL(fuse_dirent, )
FUSE_ABI_OUT_IMPL(fuse_notify_inval_inode_out, )
FUSE_ABI_OUT_IMPL(fuse_notify_inval_entry_out, )

/*
 * Translates the specified FUSE input data structure at the input pointer to
 * the FUSE ABI version used to communicate with the user space daemon and
 * writes it to the given output pointer.
 */
#define fuse_abi_in(name, abi_version, inp, outp) \
    fuse_abi_impl_in_##name((abi_version), (inp), (outp))

typedef void *(*fuse_abi_in_t)(struct fuse_abi_version *, void *, void *);
#define fuse_abi_in_p(name) &fuse_abi_impl_in_##name

#define FUSE_ABI_IN_IMPL(NAME, COMMANDS)                                     \
    static __inline__                                                        \
    void *                                                                   \
    fuse_abi_impl_in_##NAME(struct fuse_abi_version *abi_version, void *inp, \
                            void *outp)                                      \
    {                                                                        \
        size_t abi_size = fuse_abi_sizeof(NAME, abi_version);                \
        if (sizeof(struct NAME) < abi_size) {                                \
            bzero(outp, abi_size);                                           \
        }                                                                    \
        memcpy(outp, inp, min(sizeof(struct NAME), abi_size));               \
        COMMANDS                                                             \
        return (void *)((char *)outp + abi_size);                            \
    }

FUSE_ABI_IN_IMPL(fuse_forget_in, )
FUSE_ABI_IN_IMPL(fuse_getattr_in, )
FUSE_ABI_IN_IMPL(fuse_mknod_in, )
FUSE_ABI_IN_IMPL(fuse_mkdir_in, )
FUSE_ABI_IN_IMPL(fuse_rename_in, )
FUSE_ABI_IN_IMPL(fuse_exchange_in, )
FUSE_ABI_IN_IMPL(fuse_link_in, )
FUSE_ABI_IN_IMPL(fuse_setattr_in, )
FUSE_ABI_IN_IMPL(fuse_open_in, )
FUSE_ABI_IN_IMPL(fuse_create_in, )
FUSE_ABI_IN_IMPL(fuse_release_in, )
FUSE_ABI_IN_IMPL(fuse_flush_in, )
FUSE_ABI_IN_IMPL(fuse_read_in, )
FUSE_ABI_IN_IMPL(fuse_write_in, )
FUSE_ABI_IN_IMPL(fuse_fsync_in, )
FUSE_ABI_IN_IMPL(fuse_setxattr_in, )
FUSE_ABI_IN_IMPL(fuse_getxattr_in, )
FUSE_ABI_IN_IMPL(fuse_lk_in, )
FUSE_ABI_IN_IMPL(fuse_access_in, )
FUSE_ABI_IN_IMPL(fuse_init_in, )
FUSE_ABI_IN_IMPL(fuse_interrupt_in, )
FUSE_ABI_IN_IMPL(fuse_bmap_in, )
FUSE_ABI_IN_IMPL(fuse_ioctl_in, )
FUSE_ABI_IN_IMPL(fuse_poll_in, )
FUSE_ABI_IN_IMPL(fuse_dirent, )

/* Undefine ABI macros */
#undef FUSE_ABI_SIZEOF_IMPL
#undef FUSE_ABI_OUT_IMPL
#undef FUSE_ABI_IN_IMPL

/* Unsolicited notifications */
int fuse_ipc_notify_handler(struct fuse_data *data, int notify, uio_t uio);

#endif /* _FUSE_IPC_H_ */
