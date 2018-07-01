/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2012-2018 Benjamin Fleischer
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
    void    *base;
    size_t   len;
    size_t   allocated_size;
    ssize_t  credit;
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

#define FUSE_DIMALLOC(fiov, spc1, spc2, amnt)                  \
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
    lck_mtx_t                   *tk_mtx;
    int                          tk_flag;
#ifdef FUSE_TRACE_TICKET
    uint32_t                     tk_age;
#endif
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
    fuse_handler_t              *tk_aw_handler;
    TAILQ_ENTRY(fuse_ticket)     tk_aw_link;
};

#define FT_DIRTY       0x01  // ticket has been used
#define FT_SENT        0x02  // ticket has been used
#define FT_INTERRUPTED 0x04  // request has been interrupted
#define FT_ANSWERED    0x08  // request of ticket has already been answered
#define FT_KILL        0x10  // ticket has been marked for death


FUSE_INLINE
struct fuse_iov *
fticket_resp(struct fuse_ticket *ftick)
{
    return &ftick->tk_aw_fiov;
}

FUSE_INLINE
int
fticket_sent(struct fuse_ticket *ftick)
{
    return (ftick->tk_flag & FT_SENT);
}

FUSE_INLINE
void
fticket_set_sent(struct fuse_ticket *ftick)
{
    ftick->tk_flag |= FT_SENT;
}

FUSE_INLINE
int
fticket_interrupted(struct fuse_ticket *ftick)
{
    return (ftick->tk_flag & FT_INTERRUPTED);
}

FUSE_INLINE
void
fticket_set_interrupted(struct fuse_ticket *ftick)
{
    /*
     * Do not reuse this ticket to prevent possible race conditions:
     *
     * - The FUSE server responds to the original request before processing the
     *   interrupt we just sent.
     * - We drop the original request ticket.
     * - The server processes the interrupt and queues it.
     * - We reuse the dropped ticket for a new request.
     * - The server interrupts the new request.
     */

    ftick->tk_flag |= FT_INTERRUPTED | FT_KILL;
}

FUSE_INLINE
int
fticket_answered(struct fuse_ticket *ftick)
{
    return (ftick->tk_flag & FT_ANSWERED);
}

FUSE_INLINE
void
fticket_set_answered(struct fuse_ticket *ftick)
{
    ftick->tk_flag |= FT_ANSWERED;
}

FUSE_INLINE
void
fticket_set_kill(struct fuse_ticket *ftick)
{
    ftick->tk_flag |= FT_KILL;
}

FUSE_INLINE
enum fuse_opcode
fticket_opcode(struct fuse_ticket *ftick)
{
    return (((struct fuse_in_header *)(ftick->tk_ms_fiov.base))->opcode);
}

int fticket_pull(struct fuse_ticket *ftick, uio_t uio);

enum mount_state { FM_NOTMOUNTED, FM_MOUNTED, FM_UNMOUNTING };

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
    uint32_t                   dataflags;     /* effective fuse_data flags */
    uint64_t                   mountaltflags; /* as-is copy of altflags    */
    uint64_t                   noimplflags;   /* not-implemented flags     */

#if M_OSXFUSE_ENABLE_DSELECT
    struct fuse_kludge_selinfo d_rsel;
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

#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_t            *biglock;
#endif
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
#define FSESS_LOCALVOL            0x00001000
#define FSESS_NEGATIVE_VNCACHE    0x00002000
#define FSESS_NO_APPLEDOUBLE      0x00004000
#define FSESS_NO_APPLEXATTR       0x00008000
#define FSESS_NO_ATTRCACHE        0x00010000
#define FSESS_NO_READAHEAD        0x00020000
#define FSESS_NO_SYNCONCLOSE      0x00040000
#define FSESS_NO_SYNCWRITES       0x00080000
#define FSESS_NO_UBC              0x00100000
#define FSESS_NO_VNCACHE          0x00200000
#define FSESS_CASE_INSENSITIVE    0x00400000
#define FSESS_XTIMES              0x00800000
#define FSESS_AUTO_CACHE          0x01000000
#define FSESS_NATIVE_XATTR        0x02000000
#define FSESS_SPARSE              0x04000000
#define FSESS_SLOW_STATFS         0x08000000
#define FSESS_ATOMIC_O_TRUNC      0x10000000
#define FSESS_EXCL_CREATE         0x20000000

FUSE_INLINE
struct fuse_data *
fuse_get_mpdata(mount_t mp)
{
    /*
     * data->mount_state should be FM_MOUNTED for it to be valid
     */
    return (struct fuse_data *)vfs_fsprivate(mp);
}

FUSE_INLINE
void
fuse_ms_push(struct fuse_ticket *ftick)
{
    STAILQ_INSERT_TAIL(&ftick->tk_data->ms_head, ftick, tk_ms_link);
}

FUSE_INLINE
void
fuse_ms_push_head(struct fuse_ticket *ftick)
{
    STAILQ_INSERT_HEAD(&ftick->tk_data->ms_head, ftick, tk_ms_link);
}

FUSE_INLINE
struct fuse_ticket *
fuse_ms_pop(struct fuse_data *data)
{
    struct fuse_ticket *ftick = NULL;

    if ((ftick = STAILQ_FIRST(&data->ms_head))) {
        STAILQ_REMOVE_HEAD(&data->ms_head, tk_ms_link);
    }

    return ftick;
}

FUSE_INLINE
void
fuse_aw_push(struct fuse_ticket *ftick)
{
    TAILQ_INSERT_TAIL(&ftick->tk_data->aw_head, ftick, tk_aw_link);
}

FUSE_INLINE
void
fuse_aw_remove(struct fuse_ticket *ftick)
{
    TAILQ_REMOVE(&ftick->tk_data->aw_head, ftick, tk_aw_link);
}

FUSE_INLINE
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
void fuse_ticket_kill(struct fuse_ticket *ftick);

#ifndef OSCompareAndSwap
#  define OSCompareAndSwap(a, b, c) OSCompareAndSwap(a, b, (volatile UInt32*)c)
#endif

/*
 * Increases the reference count of the specified ticket.
 */
FUSE_INLINE
void
fuse_ticket_retain(struct fuse_ticket *ticket)
{
    int count;

    do {
        count = ticket->tk_ref_count;
    } while (!OSCompareAndSwap(count, count + 1, &(ticket->tk_ref_count)));

    if (count == 0) {
        panic("osxfuse: fuse_ticket_retain: ticket reference count is 0");
    }
}

/*
 * Decrements the reference count of the specified ticket. If the count reaches
 * 0 the ticket is dropped instantly.
 */
FUSE_INLINE
void
fuse_ticket_release(struct fuse_ticket *ticket) {
    int count;

    do {
        count = ticket->tk_ref_count;
    } while (!OSCompareAndSwap(count, count - 1, &(ticket->tk_ref_count)));

    if (count == 0) {
        panic("osxfuse: fuse_ticket_release: ticket reference count is 0");
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
bool fdata_set_dead(struct fuse_data *data, bool fdev_locked);
int fdata_wait_init(struct fuse_data *data);

struct fuse_dispatcher
{
    struct fuse_ticket    *tick;
    struct fuse_in_header *finh;

    void    *indata;
    size_t   iosize;
    uint64_t nodeid;
    int      answ_stat;
    void    *answ;
};

FUSE_INLINE
void
fdisp_init(struct fuse_dispatcher *fdisp, size_t iosize)
{
    fdisp->iosize = iosize;
    fdisp->tick = NULL;
}

#define fdisp_init_abi(fdisp, name, data) \
    do { \
        fdata_wait_init(data); \
        fdisp_init((fdisp), name ## _sizeof(DATOI(data))); \
    } while (0)

void fdisp_make(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                mount_t mp, uint64_t nid, vfs_context_t context);

int  fdisp_make_canfail(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                        mount_t mp, uint64_t nid, vfs_context_t context);

void fdisp_make_vp(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                   vnode_t vp, vfs_context_t context);

int  fdisp_make_vp_canfail(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                           vnode_t vp, vfs_context_t context);

int  fdisp_wait_answ(struct fuse_dispatcher *fdip);

FUSE_INLINE
int
fdisp_simple_putget_vp(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                       vnode_t vp, vfs_context_t context)
{
    fdisp_init(fdip, 0);
    fdisp_make_vp(fdip, op, vp, context);
    return fdisp_wait_answ(fdip);
}

/* Unsolicited notifications */
int fuse_ipc_notify_handler(struct fuse_data *data, int notify, uio_t uio);

/*
 * FUSE ABI helpers
 */
#define FUSE_ABI_708 708
#define FUSE_ABI_709 709
#define FUSE_ABI_710 710
#define FUSE_ABI_711 711
#define FUSE_ABI_712 712
#define FUSE_ABI_713 713
#define FUSE_ABI_715 715
#define FUSE_ABI_716 716
#define FUSE_ABI_718 718
#define FUSE_ABI_719 719

#define ABITOI(abi_version) (100 * (abi_version)->major + (abi_version)->minor)

#define DTOABI(data) (&((data)->abi_version))

#define DATOI(data) ABITOI(DTOABI(data))

/*
 * Returns true, if the specified FUSE operation is supported in the ABI version
 * used to communicate with FUSE server.
 */
FUSE_INLINE
bool
fuse_abi_is_op_supported(struct fuse_abi_version *abi_version,
                         enum fuse_opcode op)
{
    switch (op) {
        case FUSE_IOCTL:
        case FUSE_POLL:
            return ABITOI(abi_version) >= FUSE_ABI_712;

        case FUSE_NOTIFY_REPLY:
            return ABITOI(abi_version) >= FUSE_ABI_715;

        case FUSE_BATCH_FORGET:
            return ABITOI(abi_version) >= FUSE_ABI_716;

        case FUSE_FALLOCATE:
            return ABITOI(abi_version) >= FUSE_ABI_719;

        default:
            return true; /* ABI 7.8 */
    }
}

/*
 * Returns true, if the specified FUSE notification is supported in the ABI
 * version used to communicate with the FUSE server.
 */
FUSE_INLINE
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

        case FUSE_NOTIFY_STORE:
        case FUSE_NOTIFY_RETRIEVE:
            return ABITOI(abi_version) >= FUSE_ABI_715;

        case FUSE_NOTIFY_DELETE:
            return ABITOI(abi_version) >= FUSE_ABI_718;

        default:
            return true; /* ABI 7.11 */
    }
}

/*
 * FUSE ABI
 */

#pragma mark fuse_abi_data

FUSE_INLINE
void
fuse_abi_data_init(struct fuse_abi_data *fuse_abi_data, int abi_version, void *data)
{
    fuse_abi_data->fad_version = abi_version;
    fuse_abi_data->fad_data = data;
}

#pragma mark fuse_attr

FUSE_INLINE
size_t
fuse_attr_sizeof(int abi_version)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (abi_version < FUSE_ABI_709) {
        return 96;
    }
#else
    (void)abi_version;
#endif

    return sizeof(struct fuse_attr);
}

FUSE_INLINE
uint64_t
fuse_attr_get_ino(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->ino;
}

FUSE_INLINE
void
fuse_attr_set_ino(struct fuse_abi_data *fuse_attr, uint64_t ino)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->ino = ino;
}

FUSE_INLINE
uint64_t
fuse_attr_get_size(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->size;
}

FUSE_INLINE
void
fuse_attr_set_size(struct fuse_abi_data *fuse_attr, uint64_t size)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->size = size;
}

FUSE_INLINE
uint64_t
fuse_attr_get_blocks(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->blocks;
}

FUSE_INLINE
void
fuse_attr_set_blocks(struct fuse_abi_data *fuse_attr, uint64_t blocks)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->blocks = blocks;
}

FUSE_INLINE
uint64_t
fuse_attr_get_atime(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->atime;
}

FUSE_INLINE
void
fuse_attr_set_atime(struct fuse_abi_data *fuse_attr, uint64_t atime)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->atime = atime;
}

FUSE_INLINE
uint64_t
fuse_attr_get_mtime(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->mtime;
}

FUSE_INLINE
void
fuse_attr_set_mtime(struct fuse_abi_data *fuse_attr, uint64_t mtime)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->mtime = mtime;
}

FUSE_INLINE
uint64_t
fuse_attr_get_ctime(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->ctime;
}

FUSE_INLINE
void
fuse_attr_set_ctime(struct fuse_abi_data *fuse_attr, uint64_t ctime)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->ctime = ctime;
}

FUSE_INLINE
uint64_t
fuse_attr_get_crtime(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->crtime;
}

FUSE_INLINE
void
fuse_attr_set_crtime(struct fuse_abi_data *fuse_attr, uint64_t crtime)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->crtime = crtime;
}

FUSE_INLINE
uint32_t
fuse_attr_get_atimensec(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->atimensec;
}

FUSE_INLINE
void
fuse_attr_set_atimensec(struct fuse_abi_data *fuse_attr, uint32_t atimensec)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->atimensec = atimensec;
}

FUSE_INLINE
uint32_t
fuse_attr_get_mtimensec(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->mtimensec;
}

FUSE_INLINE
void
fuse_attr_set_mtimensec(struct fuse_abi_data *fuse_attr, uint32_t mtimensec)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->mtimensec = mtimensec;
}

FUSE_INLINE
uint32_t
fuse_attr_get_ctimensec(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->ctimensec;
}

FUSE_INLINE
void
fuse_attr_set_ctimensec(struct fuse_abi_data *fuse_attr, uint32_t ctimensec)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->ctimensec = ctimensec;
}

FUSE_INLINE
uint32_t
fuse_attr_get_crtimensec(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->crtimensec;
}

FUSE_INLINE
void
fuse_attr_set_crtimensec(struct fuse_abi_data *fuse_attr, uint32_t crtimensec)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->crtimensec = crtimensec;
}

FUSE_INLINE
uint32_t
fuse_attr_get_mode(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->mode;
}

FUSE_INLINE
void
fuse_attr_set_mode(struct fuse_abi_data *fuse_attr, uint32_t mode)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->mode = mode;
}

FUSE_INLINE
uint32_t
fuse_attr_get_nlink(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->nlink;
}

FUSE_INLINE
void
fuse_attr_set_nlink(struct fuse_abi_data *fuse_attr, uint32_t nlink)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->nlink = nlink;
}

FUSE_INLINE
uint32_t
fuse_attr_get_uid(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->uid;
}

FUSE_INLINE
void
fuse_attr_set_uid(struct fuse_abi_data *fuse_attr, uint32_t uid)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->uid = uid;
}

FUSE_INLINE
uint32_t
fuse_attr_get_gid(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->gid;
}

FUSE_INLINE
void
fuse_attr_set_gid(struct fuse_abi_data *fuse_attr, uint32_t gid)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->gid = gid;
}

FUSE_INLINE
uint32_t
fuse_attr_get_rdev(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->rdev;
}

FUSE_INLINE
void
fuse_attr_set_rdev(struct fuse_abi_data *fuse_attr, uint32_t rdev)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->rdev = rdev;
}

FUSE_INLINE
uint32_t
fuse_attr_get_flags(struct fuse_abi_data *fuse_attr)
{
    return ((struct fuse_attr *)fuse_attr->fad_data)->flags;
}

FUSE_INLINE
void
fuse_attr_set_flags(struct fuse_abi_data *fuse_attr, uint32_t flags)
{
    ((struct fuse_attr *)fuse_attr->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
fuse_attr_get_blksize(struct fuse_abi_data *fuse_attr)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_attr->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_attr *)fuse_attr->fad_data)->blksize;
}

FUSE_INLINE
void
fuse_attr_set_blksize(struct fuse_abi_data *fuse_attr, uint32_t blksize)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_attr->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_attr *)fuse_attr->fad_data)->blksize = blksize;
}

#pragma mark fuse_kstatfs

FUSE_INLINE
size_t
fuse_kstatfs_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_kstatfs);
}

FUSE_INLINE
uint64_t
fuse_kstatfs_get_blocks(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->blocks;
}

FUSE_INLINE
void
fuse_kstatfs_set_blocks(struct fuse_abi_data *fuse_kstatfs, uint64_t blocks)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->blocks = blocks;
}

FUSE_INLINE
uint64_t
fuse_kstatfs_get_bfree(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->bfree;
}

FUSE_INLINE
void
fuse_kstatfs_set_bfree(struct fuse_abi_data *fuse_kstatfs, uint64_t bfree)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->bfree = bfree;
}

FUSE_INLINE
uint64_t
fuse_kstatfs_get_bavail(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->bavail;
}

FUSE_INLINE
void
fuse_kstatfs_set_bavail(struct fuse_abi_data *fuse_kstatfs, uint64_t bavail)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->bavail = bavail;
}

FUSE_INLINE
uint64_t
fuse_kstatfs_get_files(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->files;
}

FUSE_INLINE
void
fuse_kstatfs_set_files(struct fuse_abi_data *fuse_kstatfs, uint64_t files)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->files = files;
}

FUSE_INLINE
uint64_t
fuse_kstatfs_get_ffree(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->ffree;
}

FUSE_INLINE
void
fuse_kstatfs_set_ffree(struct fuse_abi_data *fuse_kstatfs, uint64_t ffree)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->ffree = ffree;
}

FUSE_INLINE
uint32_t
fuse_kstatfs_get_bsize(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->bsize;
}

FUSE_INLINE
void
fuse_kstatfs_set_bsize(struct fuse_abi_data *fuse_kstatfs, uint32_t bsize)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->bsize = bsize;
}

FUSE_INLINE
uint32_t
fuse_kstatfs_get_namelen(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->namelen;
}

FUSE_INLINE
void
fuse_kstatfs_set_namelen(struct fuse_abi_data *fuse_kstatfs, uint32_t namelen)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->namelen = namelen;
}

FUSE_INLINE
uint32_t
fuse_kstatfs_get_frsize(struct fuse_abi_data *fuse_kstatfs)
{
    return ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->frsize;
}

FUSE_INLINE
void
fuse_kstatfs_set_frsize(struct fuse_abi_data *fuse_kstatfs, uint32_t frsize)
{
    ((struct fuse_kstatfs *)fuse_kstatfs->fad_data)->frsize = frsize;
}

#pragma mark fuse_file_lock

FUSE_INLINE
size_t
fuse_file_lock_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_file_lock);
}

FUSE_INLINE
uint64_t
fuse_file_lock_get_start(struct fuse_abi_data *fuse_file_lock)
{
    return ((struct fuse_file_lock *)fuse_file_lock->fad_data)->start;
}

FUSE_INLINE
void
fuse_file_lock_set_start(struct fuse_abi_data *fuse_file_lock, uint64_t start)
{
    ((struct fuse_file_lock *)fuse_file_lock->fad_data)->start = start;
}

FUSE_INLINE
uint64_t
fuse_file_lock_get_end(struct fuse_abi_data *fuse_file_lock)
{
    return ((struct fuse_file_lock *)fuse_file_lock->fad_data)->end;
}

FUSE_INLINE
void
fuse_file_lock_set_end(struct fuse_abi_data *fuse_file_lock, uint64_t end)
{
    ((struct fuse_file_lock *)fuse_file_lock->fad_data)->end = end;
}

FUSE_INLINE
uint32_t
fuse_file_lock_get_type(struct fuse_abi_data *fuse_file_lock)
{
    return ((struct fuse_file_lock *)fuse_file_lock->fad_data)->type;
}

FUSE_INLINE
void
fuse_file_lock_set_type(struct fuse_abi_data *fuse_file_lock, uint32_t type)
{
    ((struct fuse_file_lock *)fuse_file_lock->fad_data)->type = type;
}

FUSE_INLINE
uint32_t
fuse_file_lock_get_pid(struct fuse_abi_data *fuse_file_lock)
{
    return ((struct fuse_file_lock *)fuse_file_lock->fad_data)->pid;
}

FUSE_INLINE
void
fuse_file_lock_set_pid(struct fuse_abi_data *fuse_file_lock, uint32_t pid)
{
    ((struct fuse_file_lock *)fuse_file_lock->fad_data)->pid = pid;
}

#pragma mark fuse_entry_out

FUSE_INLINE
size_t
fuse_entry_out_sizeof(int abi_version)
{
    return 40 + fuse_attr_sizeof(abi_version);
}

FUSE_INLINE
uint64_t
fuse_entry_out_get_nodeid(struct fuse_abi_data *fuse_entry_out)
{
    return ((struct fuse_entry_out *)fuse_entry_out->fad_data)->nodeid;
}

FUSE_INLINE
void
fuse_entry_out_set_nodeid(struct fuse_abi_data *fuse_entry_out, uint64_t nodeid)
{
    ((struct fuse_entry_out *)fuse_entry_out->fad_data)->nodeid = nodeid;
}

FUSE_INLINE
uint64_t
fuse_entry_out_get_generation(struct fuse_abi_data *fuse_entry_out)
{
    return ((struct fuse_entry_out *)fuse_entry_out->fad_data)->generation;
}

FUSE_INLINE
void
fuse_entry_out_set_generation(struct fuse_abi_data *fuse_entry_out, uint64_t generation)
{
    ((struct fuse_entry_out *)fuse_entry_out->fad_data)->generation = generation;
}

FUSE_INLINE
uint64_t
fuse_entry_out_get_entry_valid(struct fuse_abi_data *fuse_entry_out)
{
    return ((struct fuse_entry_out *)fuse_entry_out->fad_data)->entry_valid;
}

FUSE_INLINE
void
fuse_entry_out_set_entry_valid(struct fuse_abi_data *fuse_entry_out, uint64_t entry_valid)
{
    ((struct fuse_entry_out *)fuse_entry_out->fad_data)->entry_valid = entry_valid;
}

FUSE_INLINE
uint64_t
fuse_entry_out_get_attr_valid(struct fuse_abi_data *fuse_entry_out)
{
    return ((struct fuse_entry_out *)fuse_entry_out->fad_data)->attr_valid;
}

FUSE_INLINE
void
fuse_entry_out_set_attr_valid(struct fuse_abi_data *fuse_entry_out, uint64_t attr_valid)
{
    ((struct fuse_entry_out *)fuse_entry_out->fad_data)->attr_valid = attr_valid;
}

FUSE_INLINE
uint32_t
fuse_entry_out_get_entry_valid_nsec(struct fuse_abi_data *fuse_entry_out)
{
    return ((struct fuse_entry_out *)fuse_entry_out->fad_data)->entry_valid_nsec;
}

FUSE_INLINE
void
fuse_entry_out_set_entry_valid_nsec(struct fuse_abi_data *fuse_entry_out, uint32_t entry_valid_nsec)
{
    ((struct fuse_entry_out *)fuse_entry_out->fad_data)->entry_valid_nsec = entry_valid_nsec;
}

FUSE_INLINE
uint32_t
fuse_entry_out_get_attr_valid_nsec(struct fuse_abi_data *fuse_entry_out)
{
    return ((struct fuse_entry_out *)fuse_entry_out->fad_data)->attr_valid_nsec;
}

FUSE_INLINE
void
fuse_entry_out_set_attr_valid_nsec(struct fuse_abi_data *fuse_entry_out, uint32_t attr_valid_nsec)
{
    ((struct fuse_entry_out *)fuse_entry_out->fad_data)->attr_valid_nsec = attr_valid_nsec;
}

FUSE_INLINE
void *
fuse_entry_out_get_attr(struct fuse_abi_data *fuse_entry_out)
{
    return &((struct fuse_entry_out *)fuse_entry_out->fad_data)->attr;
}

#pragma mark fuse_forget_in

FUSE_INLINE
size_t
fuse_forget_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_forget_in);
}

FUSE_INLINE
uint64_t
fuse_forget_in_get_nlookup(struct fuse_abi_data *fuse_forget_in)
{
    return ((struct fuse_forget_in *)fuse_forget_in->fad_data)->nlookup;
}

FUSE_INLINE
void
fuse_forget_in_set_nlookup(struct fuse_abi_data *fuse_forget_in, uint64_t nlookup)
{
    ((struct fuse_forget_in *)fuse_forget_in->fad_data)->nlookup = nlookup;
}

#pragma mark fuse_forget_one

FUSE_INLINE
size_t
fuse_forget_one_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_forget_one);
}

FUSE_INLINE
uint64_t
fuse_forget_one_get_nodeid(struct fuse_abi_data *fuse_forget_one)
{
    return ((struct fuse_forget_one *)fuse_forget_one->fad_data)->nodeid;
}

FUSE_INLINE
void
fuse_forget_one_set_nodeid(struct fuse_abi_data *fuse_forget_one, uint64_t nodeid)
{
    ((struct fuse_forget_one *)fuse_forget_one->fad_data)->nodeid = nodeid;
}

FUSE_INLINE
uint64_t
fuse_forget_one_get_nlookup(struct fuse_abi_data *fuse_forget_one)
{
    return ((struct fuse_forget_one *)fuse_forget_one->fad_data)->nlookup;
}

FUSE_INLINE
void
fuse_forget_one_set_nlookup(struct fuse_abi_data *fuse_forget_one, uint64_t nlookup)
{
    ((struct fuse_forget_one *)fuse_forget_one->fad_data)->nlookup = nlookup;
}

#pragma mark fuse_batch_forget_in

FUSE_INLINE
size_t
fuse_batch_forget_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_batch_forget_in);
}

FUSE_INLINE
uint32_t
fuse_batch_forget_in_get_count(struct fuse_abi_data *fuse_batch_forget_in)
{
    return ((struct fuse_batch_forget_in *)fuse_batch_forget_in->fad_data)->count;
}

FUSE_INLINE
void
fuse_batch_forget_in_set_count(struct fuse_abi_data *fuse_batch_forget_in, uint32_t count)
{
    ((struct fuse_batch_forget_in *)fuse_batch_forget_in->fad_data)->count = count;
}

#pragma mark fuse_getattr_in

FUSE_INLINE
size_t
fuse_getattr_in_sizeof(int abi_version)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (abi_version < FUSE_ABI_709) {
        return 0;
    }
#else
    (void)abi_version;
#endif

    return sizeof(struct fuse_getattr_in);
}

FUSE_INLINE
uint32_t
fuse_getattr_in_get_getattr_flags(struct fuse_abi_data *fuse_getattr_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_getattr_in->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_getattr_in *)fuse_getattr_in->fad_data)->getattr_flags;
}

FUSE_INLINE
void
fuse_getattr_in_set_getattr_flags(struct fuse_abi_data *fuse_getattr_in, uint32_t getattr_flags)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_getattr_in->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_getattr_in *)fuse_getattr_in->fad_data)->getattr_flags = getattr_flags;
}

FUSE_INLINE
uint64_t
fuse_getattr_in_get_fh(struct fuse_abi_data *fuse_getattr_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_getattr_in->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_getattr_in *)fuse_getattr_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_getattr_in_set_fh(struct fuse_abi_data *fuse_getattr_in, uint64_t fh)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_getattr_in->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_getattr_in *)fuse_getattr_in->fad_data)->fh = fh;
}

#pragma mark fuse_attr_out

FUSE_INLINE
size_t
fuse_attr_out_sizeof(int abi_version)
{
    return 16 + fuse_attr_sizeof(abi_version);
}

FUSE_INLINE
uint64_t
fuse_attr_out_get_attr_valid(struct fuse_abi_data *fuse_attr_out)
{
    return ((struct fuse_attr_out *)fuse_attr_out->fad_data)->attr_valid;
}

FUSE_INLINE
void
fuse_attr_out_set_attr_valid(struct fuse_abi_data *fuse_attr_out, uint64_t attr_valid)
{
    ((struct fuse_attr_out *)fuse_attr_out->fad_data)->attr_valid = attr_valid;
}

FUSE_INLINE
uint32_t
fuse_attr_out_get_attr_valid_nsec(struct fuse_abi_data *fuse_attr_out)
{
    return ((struct fuse_attr_out *)fuse_attr_out->fad_data)->attr_valid_nsec;
}

FUSE_INLINE
void
fuse_attr_out_set_attr_valid_nsec(struct fuse_abi_data *fuse_attr_out, uint32_t attr_valid_nsec)
{
    ((struct fuse_attr_out *)fuse_attr_out->fad_data)->attr_valid_nsec = attr_valid_nsec;
}

FUSE_INLINE
void *
fuse_attr_out_get_attr(struct fuse_abi_data *fuse_attr_out)
{
    return &((struct fuse_attr_out *)fuse_attr_out->fad_data)->attr;
}

#pragma mark fuse_getxtimes_out

FUSE_INLINE
size_t
fuse_getxtimes_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_getxtimes_out);
}

FUSE_INLINE
uint64_t
fuse_getxtimes_out_get_bkuptime(struct fuse_abi_data *fuse_getxtimes_out)
{
    return ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->bkuptime;
}

FUSE_INLINE
void
fuse_getxtimes_out_set_bkuptime(struct fuse_abi_data *fuse_getxtimes_out, uint64_t bkuptime)
{
    ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->bkuptime = bkuptime;
}

FUSE_INLINE
uint64_t
fuse_getxtimes_out_get_crtime(struct fuse_abi_data *fuse_getxtimes_out)
{
    return ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->crtime;
}

FUSE_INLINE
void
fuse_getxtimes_out_set_crtime(struct fuse_abi_data *fuse_getxtimes_out, uint64_t crtime)
{
    ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->crtime = crtime;
}

FUSE_INLINE
uint32_t
fuse_getxtimes_out_get_bkuptimensec(struct fuse_abi_data *fuse_getxtimes_out)
{
    return ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->bkuptimensec;
}

FUSE_INLINE
void
fuse_getxtimes_out_set_bkuptimensec(struct fuse_abi_data *fuse_getxtimes_out, uint32_t bkuptimensec)
{
    ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->bkuptimensec = bkuptimensec;
}

FUSE_INLINE
uint32_t
fuse_getxtimes_out_get_crtimensec(struct fuse_abi_data *fuse_getxtimes_out)
{
    return ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->crtimensec;
}

FUSE_INLINE
void
fuse_getxtimes_out_set_crtimensec(struct fuse_abi_data *fuse_getxtimes_out, uint32_t crtimensec)
{
    ((struct fuse_getxtimes_out *)fuse_getxtimes_out->fad_data)->crtimensec = crtimensec;
}

#pragma mark fuse_mknod_in

FUSE_INLINE
size_t
fuse_mknod_in_sizeof(int abi_version)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_712
    if (abi_version < FUSE_ABI_712) {
        return FUSE_COMPAT_MKNOD_IN_SIZE;
    }
#else
    (void)abi_version;
#endif

    return sizeof(struct fuse_mknod_in);
}

FUSE_INLINE
uint32_t
fuse_mknod_in_get_mode(struct fuse_abi_data *fuse_mknod_in)
{
    return ((struct fuse_mknod_in *)fuse_mknod_in->fad_data)->mode;
}

FUSE_INLINE
void
fuse_mknod_in_set_mode(struct fuse_abi_data *fuse_mknod_in, uint32_t mode)
{
    ((struct fuse_mknod_in *)fuse_mknod_in->fad_data)->mode = mode;
}

FUSE_INLINE
uint32_t
fuse_mknod_in_get_rdev(struct fuse_abi_data *fuse_mknod_in)
{
    return ((struct fuse_mknod_in *)fuse_mknod_in->fad_data)->rdev;
}

FUSE_INLINE
void
fuse_mknod_in_set_rdev(struct fuse_abi_data *fuse_mknod_in, uint32_t rdev)
{
    ((struct fuse_mknod_in *)fuse_mknod_in->fad_data)->rdev = rdev;
}

FUSE_INLINE
uint32_t
fuse_mknod_in_get_umask(struct fuse_abi_data *fuse_mknod_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_712
    if (fuse_mknod_in->fad_version < FUSE_ABI_712) {
        return 0;
    }
#endif

    return ((struct fuse_mknod_in *)fuse_mknod_in->fad_data)->umask;
}

FUSE_INLINE
void
fuse_mknod_in_set_umask(struct fuse_abi_data *fuse_mknod_in, uint32_t umask)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_712
    if (fuse_mknod_in->fad_version < FUSE_ABI_712) {
        return;
    }
#endif

    ((struct fuse_mknod_in *)fuse_mknod_in->fad_data)->umask = umask;
}

#pragma mark fuse_mkdir_in

FUSE_INLINE
size_t
fuse_mkdir_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_mkdir_in);
}

FUSE_INLINE
uint32_t
fuse_mkdir_in_get_mode(struct fuse_abi_data *fuse_mkdir_in)
{
    return ((struct fuse_mkdir_in *)fuse_mkdir_in->fad_data)->mode;
}

FUSE_INLINE
void
fuse_mkdir_in_set_mode(struct fuse_abi_data *fuse_mkdir_in, uint32_t mode)
{
    ((struct fuse_mkdir_in *)fuse_mkdir_in->fad_data)->mode = mode;
}

FUSE_INLINE
uint32_t
fuse_mkdir_in_get_umask(struct fuse_abi_data *fuse_mkdir_in)
{
    return ((struct fuse_mkdir_in *)fuse_mkdir_in->fad_data)->umask;
}

FUSE_INLINE
void
fuse_mkdir_in_set_umask(struct fuse_abi_data *fuse_mkdir_in, uint32_t umask)
{
    ((struct fuse_mkdir_in *)fuse_mkdir_in->fad_data)->umask = umask;
}

#pragma mark fuse_rename_in

FUSE_INLINE
size_t
fuse_rename_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_rename_in);
}

FUSE_INLINE
uint64_t
fuse_rename_in_get_newdir(struct fuse_abi_data *fuse_rename_in)
{
    return ((struct fuse_rename_in *)fuse_rename_in->fad_data)->newdir;
}

FUSE_INLINE
void
fuse_rename_in_set_newdir(struct fuse_abi_data *fuse_rename_in, uint64_t newdir)
{
    ((struct fuse_rename_in *)fuse_rename_in->fad_data)->newdir = newdir;
}

#pragma mark fuse_exchange_in

FUSE_INLINE
size_t
fuse_exchange_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_exchange_in);
}

FUSE_INLINE
uint64_t
fuse_exchange_in_get_olddir(struct fuse_abi_data *fuse_exchange_in)
{
    return ((struct fuse_exchange_in *)fuse_exchange_in->fad_data)->olddir;
}

FUSE_INLINE
void
fuse_exchange_in_set_olddir(struct fuse_abi_data *fuse_exchange_in, uint64_t olddir)
{
    ((struct fuse_exchange_in *)fuse_exchange_in->fad_data)->olddir = olddir;
}

FUSE_INLINE
uint64_t
fuse_exchange_in_get_newdir(struct fuse_abi_data *fuse_exchange_in)
{
    return ((struct fuse_exchange_in *)fuse_exchange_in->fad_data)->newdir;
}

FUSE_INLINE
void
fuse_exchange_in_set_newdir(struct fuse_abi_data *fuse_exchange_in, uint64_t newdir)
{
    ((struct fuse_exchange_in *)fuse_exchange_in->fad_data)->newdir = newdir;
}

FUSE_INLINE
uint64_t
fuse_exchange_in_get_options(struct fuse_abi_data *fuse_exchange_in)
{
    return ((struct fuse_exchange_in *)fuse_exchange_in->fad_data)->options;
}

FUSE_INLINE
void
fuse_exchange_in_set_options(struct fuse_abi_data *fuse_exchange_in, uint64_t options)
{
    ((struct fuse_exchange_in *)fuse_exchange_in->fad_data)->options = options;
}

#pragma mark fuse_link_in

FUSE_INLINE
size_t
fuse_link_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_link_in);
}

FUSE_INLINE
uint64_t
fuse_link_in_get_oldnodeid(struct fuse_abi_data *fuse_link_in)
{
    return ((struct fuse_link_in *)fuse_link_in->fad_data)->oldnodeid;
}

FUSE_INLINE
void
fuse_link_in_set_oldnodeid(struct fuse_abi_data *fuse_link_in, uint64_t oldnodeid)
{
    ((struct fuse_link_in *)fuse_link_in->fad_data)->oldnodeid = oldnodeid;
}

#pragma mark fuse_setattr_in

FUSE_INLINE
size_t
fuse_setattr_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_setattr_in);
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_valid(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->valid;
}

FUSE_INLINE
void
fuse_setattr_in_set_valid(struct fuse_abi_data *fuse_setattr_in, uint32_t valid)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->valid = valid;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_fh(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_setattr_in_set_fh(struct fuse_abi_data *fuse_setattr_in, uint64_t fh)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_size(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->size;
}

FUSE_INLINE
void
fuse_setattr_in_set_size(struct fuse_abi_data *fuse_setattr_in, uint64_t size)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->size = size;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_lock_owner(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->lock_owner;
}

FUSE_INLINE
void
fuse_setattr_in_set_lock_owner(struct fuse_abi_data *fuse_setattr_in, uint64_t lock_owner)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->lock_owner = lock_owner;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_atime(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->atime;
}

FUSE_INLINE
void
fuse_setattr_in_set_atime(struct fuse_abi_data *fuse_setattr_in, uint64_t atime)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->atime = atime;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_mtime(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->mtime;
}

FUSE_INLINE
void
fuse_setattr_in_set_mtime(struct fuse_abi_data *fuse_setattr_in, uint64_t mtime)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->mtime = mtime;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_unused2(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused2;
}

FUSE_INLINE
void
fuse_setattr_in_set_unused2(struct fuse_abi_data *fuse_setattr_in, uint64_t unused2)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused2 = unused2;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_atimensec(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->atimensec;
}

FUSE_INLINE
void
fuse_setattr_in_set_atimensec(struct fuse_abi_data *fuse_setattr_in, uint32_t atimensec)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->atimensec = atimensec;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_mtimensec(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->mtimensec;
}

FUSE_INLINE
void
fuse_setattr_in_set_mtimensec(struct fuse_abi_data *fuse_setattr_in, uint32_t mtimensec)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->mtimensec = mtimensec;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_unused3(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused3;
}

FUSE_INLINE
void
fuse_setattr_in_set_unused3(struct fuse_abi_data *fuse_setattr_in, uint32_t unused3)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused3 = unused3;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_mode(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->mode;
}

FUSE_INLINE
void
fuse_setattr_in_set_mode(struct fuse_abi_data *fuse_setattr_in, uint32_t mode)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->mode = mode;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_unused4(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused4;
}

FUSE_INLINE
void
fuse_setattr_in_set_unused4(struct fuse_abi_data *fuse_setattr_in, uint32_t unused4)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused4 = unused4;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_uid(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->uid;
}

FUSE_INLINE
void
fuse_setattr_in_set_uid(struct fuse_abi_data *fuse_setattr_in, uint32_t uid)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->uid = uid;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_gid(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->gid;
}

FUSE_INLINE
void
fuse_setattr_in_set_gid(struct fuse_abi_data *fuse_setattr_in, uint32_t gid)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->gid = gid;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_unused5(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused5;
}

FUSE_INLINE
void
fuse_setattr_in_set_unused5(struct fuse_abi_data *fuse_setattr_in, uint32_t unused5)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->unused5 = unused5;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_bkuptime(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->bkuptime;
}

FUSE_INLINE
void
fuse_setattr_in_set_bkuptime(struct fuse_abi_data *fuse_setattr_in, uint64_t bkuptime)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->bkuptime = bkuptime;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_chgtime(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->chgtime;
}

FUSE_INLINE
void
fuse_setattr_in_set_chgtime(struct fuse_abi_data *fuse_setattr_in, uint64_t chgtime)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->chgtime = chgtime;
}

FUSE_INLINE
uint64_t
fuse_setattr_in_get_crtime(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->crtime;
}

FUSE_INLINE
void
fuse_setattr_in_set_crtime(struct fuse_abi_data *fuse_setattr_in, uint64_t crtime)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->crtime = crtime;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_bkuptimensec(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->bkuptimensec;
}

FUSE_INLINE
void
fuse_setattr_in_set_bkuptimensec(struct fuse_abi_data *fuse_setattr_in, uint32_t bkuptimensec)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->bkuptimensec = bkuptimensec;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_chgtimensec(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->chgtimensec;
}

FUSE_INLINE
void
fuse_setattr_in_set_chgtimensec(struct fuse_abi_data *fuse_setattr_in, uint32_t chgtimensec)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->chgtimensec = chgtimensec;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_crtimensec(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->crtimensec;
}

FUSE_INLINE
void
fuse_setattr_in_set_crtimensec(struct fuse_abi_data *fuse_setattr_in, uint32_t crtimensec)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->crtimensec = crtimensec;
}

FUSE_INLINE
uint32_t
fuse_setattr_in_get_flags(struct fuse_abi_data *fuse_setattr_in)
{
    return ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_setattr_in_set_flags(struct fuse_abi_data *fuse_setattr_in, uint32_t flags)
{
    ((struct fuse_setattr_in *)fuse_setattr_in->fad_data)->flags = flags;
}

#pragma mark fuse_open_in

FUSE_INLINE
size_t
fuse_open_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_open_in);
}

FUSE_INLINE
uint32_t
fuse_open_in_get_flags(struct fuse_abi_data *fuse_open_in)
{
    return ((struct fuse_open_in *)fuse_open_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_open_in_set_flags(struct fuse_abi_data *fuse_open_in, uint32_t flags)
{
    ((struct fuse_open_in *)fuse_open_in->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
fuse_open_in_get_unused(struct fuse_abi_data *fuse_open_in)
{
    return ((struct fuse_open_in *)fuse_open_in->fad_data)->unused;
}

FUSE_INLINE
void
fuse_open_in_set_unused(struct fuse_abi_data *fuse_open_in, uint32_t unused)
{
    ((struct fuse_open_in *)fuse_open_in->fad_data)->unused = unused;
}

#pragma mark fuse_create_in

FUSE_INLINE
size_t
fuse_create_in_sizeof(int abi_version)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_712
    if (abi_version < FUSE_ABI_712) {
        return fuse_open_in_sizeof(abi_version);
    }
#else
    (void)abi_version;
#endif

    return sizeof(struct fuse_create_in);
}

FUSE_INLINE
uint32_t
fuse_create_in_get_flags(struct fuse_abi_data *fuse_create_in)
{
    return ((struct fuse_create_in *)fuse_create_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_create_in_set_flags(struct fuse_abi_data *fuse_create_in, uint32_t flags)
{
    ((struct fuse_create_in *)fuse_create_in->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
fuse_create_in_get_mode(struct fuse_abi_data *fuse_create_in)
{
    return ((struct fuse_create_in *)fuse_create_in->fad_data)->mode;
}

FUSE_INLINE
void
fuse_create_in_set_mode(struct fuse_abi_data *fuse_create_in, uint32_t mode)
{
    ((struct fuse_create_in *)fuse_create_in->fad_data)->mode = mode;
}

FUSE_INLINE
uint32_t
fuse_create_in_get_umask(struct fuse_abi_data *fuse_create_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_712
    if (fuse_create_in->fad_version < FUSE_ABI_712) {
        return 0;
    }
#endif

    return ((struct fuse_create_in *)fuse_create_in->fad_data)->umask;
}

FUSE_INLINE
void
fuse_create_in_set_umask(struct fuse_abi_data *fuse_create_in, uint32_t umask)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_712
    if (fuse_create_in->fad_version < FUSE_ABI_712) {
        return;
    }
#endif

    ((struct fuse_create_in *)fuse_create_in->fad_data)->umask = umask;
}

#pragma mark fuse_open_out

FUSE_INLINE
size_t
fuse_open_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_open_out);
}

FUSE_INLINE
uint64_t
fuse_open_out_get_fh(struct fuse_abi_data *fuse_open_out)
{
    return ((struct fuse_open_out *)fuse_open_out->fad_data)->fh;
}

FUSE_INLINE
void
fuse_open_out_set_fh(struct fuse_abi_data *fuse_open_out, uint64_t fh)
{
    ((struct fuse_open_out *)fuse_open_out->fad_data)->fh = fh;
}

FUSE_INLINE
uint32_t
fuse_open_out_get_open_flags(struct fuse_abi_data *fuse_open_out)
{
    return ((struct fuse_open_out *)fuse_open_out->fad_data)->open_flags;
}

FUSE_INLINE
void
fuse_open_out_set_open_flags(struct fuse_abi_data *fuse_open_out, uint32_t open_flags)
{
    ((struct fuse_open_out *)fuse_open_out->fad_data)->open_flags = open_flags;
}

#pragma mark fuse_release_in

FUSE_INLINE
size_t
fuse_release_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_release_in);
}

FUSE_INLINE
uint64_t
fuse_release_in_get_fh(struct fuse_abi_data *fuse_release_in)
{
    return ((struct fuse_release_in *)fuse_release_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_release_in_set_fh(struct fuse_abi_data *fuse_release_in, uint64_t fh)
{
    ((struct fuse_release_in *)fuse_release_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint32_t
fuse_release_in_get_flags(struct fuse_abi_data *fuse_release_in)
{
    return ((struct fuse_release_in *)fuse_release_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_release_in_set_flags(struct fuse_abi_data *fuse_release_in, uint32_t flags)
{
    ((struct fuse_release_in *)fuse_release_in->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
fuse_release_in_get_release_flags(struct fuse_abi_data *fuse_release_in)
{
    return ((struct fuse_release_in *)fuse_release_in->fad_data)->release_flags;
}

FUSE_INLINE
void
fuse_release_in_set_release_flags(struct fuse_abi_data *fuse_release_in, uint32_t release_flags)
{
    ((struct fuse_release_in *)fuse_release_in->fad_data)->release_flags = release_flags;
}

FUSE_INLINE
uint64_t
fuse_release_in_get_lock_owner(struct fuse_abi_data *fuse_release_in)
{
    return ((struct fuse_release_in *)fuse_release_in->fad_data)->lock_owner;
}

FUSE_INLINE
void
fuse_release_in_set_lock_owner(struct fuse_abi_data *fuse_release_in, uint64_t lock_owner)
{
    ((struct fuse_release_in *)fuse_release_in->fad_data)->lock_owner = lock_owner;
}

#pragma mark fuse_flush_in

FUSE_INLINE
size_t
fuse_flush_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_flush_in);
}

FUSE_INLINE
uint64_t
fuse_flush_in_get_fh(struct fuse_abi_data *fuse_flush_in)
{
    return ((struct fuse_flush_in *)fuse_flush_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_flush_in_set_fh(struct fuse_abi_data *fuse_flush_in, uint64_t fh)
{
    ((struct fuse_flush_in *)fuse_flush_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint32_t
fuse_flush_in_get_unused(struct fuse_abi_data *fuse_flush_in)
{
    return ((struct fuse_flush_in *)fuse_flush_in->fad_data)->unused;
}

FUSE_INLINE
void
fuse_flush_in_set_unused(struct fuse_abi_data *fuse_flush_in, uint32_t unused)
{
    ((struct fuse_flush_in *)fuse_flush_in->fad_data)->unused = unused;
}

FUSE_INLINE
uint64_t
fuse_flush_in_get_lock_owner(struct fuse_abi_data *fuse_flush_in)
{
    return ((struct fuse_flush_in *)fuse_flush_in->fad_data)->lock_owner;
}

FUSE_INLINE
void
fuse_flush_in_set_lock_owner(struct fuse_abi_data *fuse_flush_in, uint64_t lock_owner)
{
    ((struct fuse_flush_in *)fuse_flush_in->fad_data)->lock_owner = lock_owner;
}

#pragma mark fuse_read_in

FUSE_INLINE
size_t
fuse_read_in_sizeof(int abi_version)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (abi_version < FUSE_ABI_709) {
        return 24;
    }
#else
    (void)abi_version;
#endif

    return sizeof(struct fuse_read_in);
}

FUSE_INLINE
uint64_t
fuse_read_in_get_fh(struct fuse_abi_data *fuse_read_in)
{
    return ((struct fuse_read_in *)fuse_read_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_read_in_set_fh(struct fuse_abi_data *fuse_read_in, uint64_t fh)
{
    ((struct fuse_read_in *)fuse_read_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint64_t
fuse_read_in_get_offset(struct fuse_abi_data *fuse_read_in)
{
    return ((struct fuse_read_in *)fuse_read_in->fad_data)->offset;
}

FUSE_INLINE
void
fuse_read_in_set_offset(struct fuse_abi_data *fuse_read_in, uint64_t offset)
{
    ((struct fuse_read_in *)fuse_read_in->fad_data)->offset = offset;
}

FUSE_INLINE
uint32_t
fuse_read_in_get_size(struct fuse_abi_data *fuse_read_in)
{
    return ((struct fuse_read_in *)fuse_read_in->fad_data)->size;
}

FUSE_INLINE
void
fuse_read_in_set_size(struct fuse_abi_data *fuse_read_in, uint32_t size)
{
    ((struct fuse_read_in *)fuse_read_in->fad_data)->size = size;
}

FUSE_INLINE
uint32_t
fuse_read_in_get_read_flags(struct fuse_abi_data *fuse_read_in)
{
    return ((struct fuse_read_in *)fuse_read_in->fad_data)->read_flags;
}

FUSE_INLINE
void
fuse_read_in_set_read_flags(struct fuse_abi_data *fuse_read_in, uint32_t read_flags)
{
    ((struct fuse_read_in *)fuse_read_in->fad_data)->read_flags = read_flags;
}

FUSE_INLINE
uint64_t
fuse_read_in_get_lock_owner(struct fuse_abi_data *fuse_read_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_read_in->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_read_in *)fuse_read_in->fad_data)->lock_owner;
}

FUSE_INLINE
void
fuse_read_in_set_lock_owner(struct fuse_abi_data *fuse_read_in, uint64_t lock_owner)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_read_in->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_read_in *)fuse_read_in->fad_data)->lock_owner = lock_owner;
}

FUSE_INLINE
uint32_t
fuse_read_in_get_flags(struct fuse_abi_data *fuse_read_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_read_in->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_read_in *)fuse_read_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_read_in_set_flags(struct fuse_abi_data *fuse_read_in, uint32_t flags)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_read_in->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_read_in *)fuse_read_in->fad_data)->flags = flags;
}

#pragma mark fuse_write_in

FUSE_INLINE
size_t
fuse_write_in_sizeof(int abi_version)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (abi_version < FUSE_ABI_709) {
        return FUSE_COMPAT_WRITE_IN_SIZE;
    }
#else
    (void)abi_version;
#endif

    return sizeof(struct fuse_write_in);
}

FUSE_INLINE
uint64_t
fuse_write_in_get_fh(struct fuse_abi_data *fuse_write_in)
{
    return ((struct fuse_write_in *)fuse_write_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_write_in_set_fh(struct fuse_abi_data *fuse_write_in, uint64_t fh)
{
    ((struct fuse_write_in *)fuse_write_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint64_t
fuse_write_in_get_offset(struct fuse_abi_data *fuse_write_in)
{
    return ((struct fuse_write_in *)fuse_write_in->fad_data)->offset;
}

FUSE_INLINE
void
fuse_write_in_set_offset(struct fuse_abi_data *fuse_write_in, uint64_t offset)
{
    ((struct fuse_write_in *)fuse_write_in->fad_data)->offset = offset;
}

FUSE_INLINE
uint32_t
fuse_write_in_get_size(struct fuse_abi_data *fuse_write_in)
{
    return ((struct fuse_write_in *)fuse_write_in->fad_data)->size;
}

FUSE_INLINE
void
fuse_write_in_set_size(struct fuse_abi_data *fuse_write_in, uint32_t size)
{
    ((struct fuse_write_in *)fuse_write_in->fad_data)->size = size;
}

FUSE_INLINE
uint32_t
fuse_write_in_get_write_flags(struct fuse_abi_data *fuse_write_in)
{
    return ((struct fuse_write_in *)fuse_write_in->fad_data)->write_flags;
}

FUSE_INLINE
void
fuse_write_in_set_write_flags(struct fuse_abi_data *fuse_write_in, uint32_t write_flags)
{
    ((struct fuse_write_in *)fuse_write_in->fad_data)->write_flags = write_flags;
}

FUSE_INLINE
uint64_t
fuse_write_in_get_lock_owner(struct fuse_abi_data *fuse_write_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_write_in->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_write_in *)fuse_write_in->fad_data)->lock_owner;
}

FUSE_INLINE
void
fuse_write_in_set_lock_owner(struct fuse_abi_data *fuse_write_in, uint64_t lock_owner)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_write_in->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_write_in *)fuse_write_in->fad_data)->lock_owner = lock_owner;
}

FUSE_INLINE
uint32_t
fuse_write_in_get_flags(struct fuse_abi_data *fuse_write_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_write_in->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_write_in *)fuse_write_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_write_in_set_flags(struct fuse_abi_data *fuse_write_in, uint32_t flags)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_write_in->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_write_in *)fuse_write_in->fad_data)->flags = flags;
}

#pragma mark fuse_write_out

FUSE_INLINE
size_t
fuse_write_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_write_out);
}

FUSE_INLINE
uint32_t
fuse_write_out_get_size(struct fuse_abi_data *fuse_write_out)
{
    return ((struct fuse_write_out *)fuse_write_out->fad_data)->size;
}

FUSE_INLINE
void
fuse_write_out_set_size(struct fuse_abi_data *fuse_write_out, uint32_t size)
{
    ((struct fuse_write_out *)fuse_write_out->fad_data)->size = size;
}

#pragma mark fuse_statfs_out

FUSE_INLINE
size_t
fuse_statfs_out_sizeof(int abi_version)
{
    return fuse_kstatfs_sizeof(abi_version);
}

FUSE_INLINE
void *
fuse_statfs_out_get_st(struct fuse_abi_data *fuse_statfs_out)
{
    return &((struct fuse_statfs_out *)fuse_statfs_out->fad_data)->st;
}

#pragma mark fuse_fsync_in

FUSE_INLINE
size_t
fuse_fsync_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_fsync_in);
}

FUSE_INLINE
uint64_t
fuse_fsync_in_get_fh(struct fuse_abi_data *fuse_fsync_in)
{
    return ((struct fuse_fsync_in *)fuse_fsync_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_fsync_in_set_fh(struct fuse_abi_data *fuse_fsync_in, uint64_t fh)
{
    ((struct fuse_fsync_in *)fuse_fsync_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint32_t
fuse_fsync_in_get_fsync_flags(struct fuse_abi_data *fuse_fsync_in)
{
    return ((struct fuse_fsync_in *)fuse_fsync_in->fad_data)->fsync_flags;
}

FUSE_INLINE
void
fuse_fsync_in_set_fsync_flags(struct fuse_abi_data *fuse_fsync_in, uint32_t fsync_flags)
{
    ((struct fuse_fsync_in *)fuse_fsync_in->fad_data)->fsync_flags = fsync_flags;
}

#pragma mark fuse_setxattr_in

FUSE_INLINE
size_t
fuse_setxattr_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_setxattr_in);
}

FUSE_INLINE
uint32_t
fuse_setxattr_in_get_size(struct fuse_abi_data *fuse_setxattr_in)
{
    return ((struct fuse_setxattr_in *)fuse_setxattr_in->fad_data)->size;
}

FUSE_INLINE
void
fuse_setxattr_in_set_size(struct fuse_abi_data *fuse_setxattr_in, uint32_t size)
{
    ((struct fuse_setxattr_in *)fuse_setxattr_in->fad_data)->size = size;
}

FUSE_INLINE
uint32_t
fuse_setxattr_in_get_flags(struct fuse_abi_data *fuse_setxattr_in)
{
    return ((struct fuse_setxattr_in *)fuse_setxattr_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_setxattr_in_set_flags(struct fuse_abi_data *fuse_setxattr_in, uint32_t flags)
{
    ((struct fuse_setxattr_in *)fuse_setxattr_in->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
fuse_setxattr_in_get_position(struct fuse_abi_data *fuse_setxattr_in)
{
    return ((struct fuse_setxattr_in *)fuse_setxattr_in->fad_data)->position;
}

FUSE_INLINE
void
fuse_setxattr_in_set_position(struct fuse_abi_data *fuse_setxattr_in, uint32_t position)
{
    ((struct fuse_setxattr_in *)fuse_setxattr_in->fad_data)->position = position;
}

#pragma mark fuse_getxattr_in

FUSE_INLINE
size_t
fuse_getxattr_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_getxattr_in);
}

FUSE_INLINE
uint32_t
fuse_getxattr_in_get_size(struct fuse_abi_data *fuse_getxattr_in)
{
    return ((struct fuse_getxattr_in *)fuse_getxattr_in->fad_data)->size;
}

FUSE_INLINE
void
fuse_getxattr_in_set_size(struct fuse_abi_data *fuse_getxattr_in, uint32_t size)
{
    ((struct fuse_getxattr_in *)fuse_getxattr_in->fad_data)->size = size;
}

FUSE_INLINE
uint32_t
fuse_getxattr_in_get_position(struct fuse_abi_data *fuse_getxattr_in)
{
    return ((struct fuse_getxattr_in *)fuse_getxattr_in->fad_data)->position;
}

FUSE_INLINE
void
fuse_getxattr_in_set_position(struct fuse_abi_data *fuse_getxattr_in, uint32_t position)
{
    ((struct fuse_getxattr_in *)fuse_getxattr_in->fad_data)->position = position;
}

#pragma mark fuse_getxattr_out

FUSE_INLINE
size_t
fuse_getxattr_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_getxattr_out);
}

FUSE_INLINE
uint32_t
fuse_getxattr_out_get_size(struct fuse_abi_data *fuse_getxattr_out)
{
    return ((struct fuse_getxattr_out *)fuse_getxattr_out->fad_data)->size;
}

FUSE_INLINE
void
fuse_getxattr_out_set_size(struct fuse_abi_data *fuse_getxattr_out, uint32_t size)
{
    ((struct fuse_getxattr_out *)fuse_getxattr_out->fad_data)->size = size;
}

#pragma mark fuse_lk_in

FUSE_INLINE
size_t
fuse_lk_in_sizeof(int abi_version)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (abi_version < FUSE_ABI_709) {
        return 16 + fuse_file_lock_sizeof(abi_version);
    }
#endif

    return 24 + fuse_file_lock_sizeof(abi_version);
}

FUSE_INLINE
uint64_t
fuse_lk_in_get_fh(struct fuse_abi_data *fuse_lk_in)
{
    return ((struct fuse_lk_in *)fuse_lk_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_lk_in_set_fh(struct fuse_abi_data *fuse_lk_in, uint64_t fh)
{
    ((struct fuse_lk_in *)fuse_lk_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint64_t
fuse_lk_in_get_owner(struct fuse_abi_data *fuse_lk_in)
{
    return ((struct fuse_lk_in *)fuse_lk_in->fad_data)->owner;
}

FUSE_INLINE
void
fuse_lk_in_set_owner(struct fuse_abi_data *fuse_lk_in, uint64_t owner)
{
    ((struct fuse_lk_in *)fuse_lk_in->fad_data)->owner = owner;
}

FUSE_INLINE
void *
fuse_lk_in_get_lk(struct fuse_abi_data *fuse_lk_in)
{
    return &((struct fuse_lk_in *)fuse_lk_in->fad_data)->lk;
}

FUSE_INLINE
uint32_t
fuse_lk_in_get_lk_flags(struct fuse_abi_data *fuse_lk_in)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_lk_in->fad_version < FUSE_ABI_709) {
        return 0;
    }
#endif

    return ((struct fuse_lk_in *)fuse_lk_in->fad_data)->lk_flags;
}

FUSE_INLINE
void
fuse_lk_in_set_lk_flags(struct fuse_abi_data *fuse_lk_in, uint32_t lk_flags)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_709
    if (fuse_lk_in->fad_version < FUSE_ABI_709) {
        return;
    }
#endif

    ((struct fuse_lk_in *)fuse_lk_in->fad_data)->lk_flags = lk_flags;
}

#pragma mark fuse_lk_out

FUSE_INLINE
size_t
fuse_lk_out_sizeof(int abi_version)
{
    return fuse_file_lock_sizeof(abi_version);
}

FUSE_INLINE
void *
fuse_lk_out_get_lk(struct fuse_abi_data *fuse_lk_out)
{
    return &((struct fuse_lk_out *)fuse_lk_out->fad_data)->lk;
}

#pragma mark fuse_access_in

FUSE_INLINE
size_t
fuse_access_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_access_in);
}

FUSE_INLINE
uint32_t
fuse_access_in_get_mask(struct fuse_abi_data *fuse_access_in)
{
    return ((struct fuse_access_in *)fuse_access_in->fad_data)->mask;
}

FUSE_INLINE
void
fuse_access_in_set_mask(struct fuse_abi_data *fuse_access_in, uint32_t mask)
{
    ((struct fuse_access_in *)fuse_access_in->fad_data)->mask = mask;
}

#pragma mark fuse_init_in

FUSE_INLINE
size_t
fuse_init_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_init_in);
}

FUSE_INLINE
uint32_t
fuse_init_in_get_major(struct fuse_abi_data *fuse_init_in)
{
    return ((struct fuse_init_in *)fuse_init_in->fad_data)->major;
}

FUSE_INLINE
void
fuse_init_in_set_major(struct fuse_abi_data *fuse_init_in, uint32_t major)
{
    ((struct fuse_init_in *)fuse_init_in->fad_data)->major = major;
}

FUSE_INLINE
uint32_t
fuse_init_in_get_minor(struct fuse_abi_data *fuse_init_in)
{
    return ((struct fuse_init_in *)fuse_init_in->fad_data)->minor;
}

FUSE_INLINE
void
fuse_init_in_set_minor(struct fuse_abi_data *fuse_init_in, uint32_t minor)
{
    ((struct fuse_init_in *)fuse_init_in->fad_data)->minor = minor;
}

FUSE_INLINE
uint32_t
fuse_init_in_get_max_readahead(struct fuse_abi_data *fuse_init_in)
{
    return ((struct fuse_init_in *)fuse_init_in->fad_data)->max_readahead;
}

FUSE_INLINE
void
fuse_init_in_set_max_readahead(struct fuse_abi_data *fuse_init_in, uint32_t max_readahead)
{
    ((struct fuse_init_in *)fuse_init_in->fad_data)->max_readahead = max_readahead;
}

FUSE_INLINE
uint32_t
fuse_init_in_get_flags(struct fuse_abi_data *fuse_init_in)
{
    return ((struct fuse_init_in *)fuse_init_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_init_in_set_flags(struct fuse_abi_data *fuse_init_in, uint32_t flags)
{
    ((struct fuse_init_in *)fuse_init_in->fad_data)->flags = flags;
}

#pragma mark fuse_init_out

FUSE_INLINE
size_t
fuse_init_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_init_out);
}

FUSE_INLINE
uint32_t
fuse_init_out_get_major(struct fuse_abi_data *fuse_init_out)
{
    return ((struct fuse_init_out *)fuse_init_out->fad_data)->major;
}

FUSE_INLINE
void
fuse_init_out_set_major(struct fuse_abi_data *fuse_init_out, uint32_t major)
{
    ((struct fuse_init_out *)fuse_init_out->fad_data)->major = major;
}

FUSE_INLINE
uint32_t
fuse_init_out_get_minor(struct fuse_abi_data *fuse_init_out)
{
    return ((struct fuse_init_out *)fuse_init_out->fad_data)->minor;
}

FUSE_INLINE
void
fuse_init_out_set_minor(struct fuse_abi_data *fuse_init_out, uint32_t minor)
{
    ((struct fuse_init_out *)fuse_init_out->fad_data)->minor = minor;
}

FUSE_INLINE
uint32_t
fuse_init_out_get_max_readahead(struct fuse_abi_data *fuse_init_out)
{
    return ((struct fuse_init_out *)fuse_init_out->fad_data)->max_readahead;
}

FUSE_INLINE
void
fuse_init_out_set_max_readahead(struct fuse_abi_data *fuse_init_out, uint32_t max_readahead)
{
    ((struct fuse_init_out *)fuse_init_out->fad_data)->max_readahead = max_readahead;
}

FUSE_INLINE
uint32_t
fuse_init_out_get_flags(struct fuse_abi_data *fuse_init_out)
{
    return ((struct fuse_init_out *)fuse_init_out->fad_data)->flags;
}

FUSE_INLINE
void
fuse_init_out_set_flags(struct fuse_abi_data *fuse_init_out, uint32_t flags)
{
    ((struct fuse_init_out *)fuse_init_out->fad_data)->flags = flags;
}

FUSE_INLINE
uint16_t
fuse_init_out_get_max_background(struct fuse_abi_data *fuse_init_out)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_713
    if (fuse_init_out->fad_version < FUSE_ABI_713) {
        return 0;
    }
#endif

    return ((struct fuse_init_out *)fuse_init_out->fad_data)->max_background;
}

FUSE_INLINE
void
fuse_init_out_set_max_background(struct fuse_abi_data *fuse_init_out, uint16_t max_background)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_713
    if (fuse_init_out->fad_version < FUSE_ABI_713) {
        return;
    }
#endif

    ((struct fuse_init_out *)fuse_init_out->fad_data)->max_background = max_background;
}

FUSE_INLINE
uint16_t
fuse_init_out_get_congestion_threshold(struct fuse_abi_data *fuse_init_out)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_713
    if (fuse_init_out->fad_version < FUSE_ABI_713) {
        return 0;
    }
#endif

    return ((struct fuse_init_out *)fuse_init_out->fad_data)->congestion_threshold;
}

FUSE_INLINE
void
fuse_init_out_set_congestion_threshold(struct fuse_abi_data *fuse_init_out, uint16_t congestion_threshold)
{
#if FUSE_ABI_VERSION_MIN < FUSE_ABI_713
    if (fuse_init_out->fad_version < FUSE_ABI_713) {
        return;
    }
#endif

    ((struct fuse_init_out *)fuse_init_out->fad_data)->congestion_threshold = congestion_threshold;
}

FUSE_INLINE
uint32_t
fuse_init_out_get_max_write(struct fuse_abi_data *fuse_init_out)
{
    return ((struct fuse_init_out *)fuse_init_out->fad_data)->max_write;
}

FUSE_INLINE
void
fuse_init_out_set_max_write(struct fuse_abi_data *fuse_init_out, uint32_t max_write)
{
    ((struct fuse_init_out *)fuse_init_out->fad_data)->max_write = max_write;
}

#pragma mark cuse_init_in

FUSE_INLINE
size_t
cuse_init_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct cuse_init_in);
}

FUSE_INLINE
uint32_t
cuse_init_in_get_major(struct fuse_abi_data *cuse_init_in)
{
    return ((struct cuse_init_in *)cuse_init_in->fad_data)->major;
}

FUSE_INLINE
void
cuse_init_in_set_major(struct fuse_abi_data *cuse_init_in, uint32_t major)
{
    ((struct cuse_init_in *)cuse_init_in->fad_data)->major = major;
}

FUSE_INLINE
uint32_t
cuse_init_in_get_minor(struct fuse_abi_data *cuse_init_in)
{
    return ((struct cuse_init_in *)cuse_init_in->fad_data)->minor;
}

FUSE_INLINE
void
cuse_init_in_set_minor(struct fuse_abi_data *cuse_init_in, uint32_t minor)
{
    ((struct cuse_init_in *)cuse_init_in->fad_data)->minor = minor;
}

FUSE_INLINE
uint32_t
cuse_init_in_get_unused(struct fuse_abi_data *cuse_init_in)
{
    return ((struct cuse_init_in *)cuse_init_in->fad_data)->unused;
}

FUSE_INLINE
void
cuse_init_in_set_unused(struct fuse_abi_data *cuse_init_in, uint32_t unused)
{
    ((struct cuse_init_in *)cuse_init_in->fad_data)->unused = unused;
}

FUSE_INLINE
uint32_t
cuse_init_in_get_flags(struct fuse_abi_data *cuse_init_in)
{
    return ((struct cuse_init_in *)cuse_init_in->fad_data)->flags;
}

FUSE_INLINE
void
cuse_init_in_set_flags(struct fuse_abi_data *cuse_init_in, uint32_t flags)
{
    ((struct cuse_init_in *)cuse_init_in->fad_data)->flags = flags;
}

#pragma mark cuse_init_out

FUSE_INLINE
size_t
cuse_init_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct cuse_init_out);
}

FUSE_INLINE
uint32_t
cuse_init_out_get_major(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->major;
}

FUSE_INLINE
void
cuse_init_out_set_major(struct fuse_abi_data *cuse_init_out, uint32_t major)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->major = major;
}

FUSE_INLINE
uint32_t
cuse_init_out_get_minor(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->minor;
}

FUSE_INLINE
void
cuse_init_out_set_minor(struct fuse_abi_data *cuse_init_out, uint32_t minor)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->minor = minor;
}

FUSE_INLINE
uint32_t
cuse_init_out_get_unused(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->unused;
}

FUSE_INLINE
void
cuse_init_out_set_unused(struct fuse_abi_data *cuse_init_out, uint32_t unused)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->unused = unused;
}

FUSE_INLINE
uint32_t
cuse_init_out_get_flags(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->flags;
}

FUSE_INLINE
void
cuse_init_out_set_flags(struct fuse_abi_data *cuse_init_out, uint32_t flags)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
cuse_init_out_get_max_read(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->max_read;
}

FUSE_INLINE
void
cuse_init_out_set_max_read(struct fuse_abi_data *cuse_init_out, uint32_t max_read)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->max_read = max_read;
}

FUSE_INLINE
uint32_t
cuse_init_out_get_max_write(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->max_write;
}

FUSE_INLINE
void
cuse_init_out_set_max_write(struct fuse_abi_data *cuse_init_out, uint32_t max_write)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->max_write = max_write;
}

FUSE_INLINE
uint32_t
cuse_init_out_get_dev_major(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->dev_major;
}

FUSE_INLINE
void
cuse_init_out_set_dev_major(struct fuse_abi_data *cuse_init_out, uint32_t dev_major)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->dev_major = dev_major;
}

FUSE_INLINE
uint32_t
cuse_init_out_get_dev_minor(struct fuse_abi_data *cuse_init_out)
{
    return ((struct cuse_init_out *)cuse_init_out->fad_data)->dev_minor;
}

FUSE_INLINE
void
cuse_init_out_set_dev_minor(struct fuse_abi_data *cuse_init_out, uint32_t dev_minor)
{
    ((struct cuse_init_out *)cuse_init_out->fad_data)->dev_minor = dev_minor;
}

#pragma mark fuse_interrupt_in

FUSE_INLINE
size_t
fuse_interrupt_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_interrupt_in);
}

FUSE_INLINE
uint64_t
fuse_interrupt_in_get_unique(struct fuse_abi_data *fuse_interrupt_in)
{
    return ((struct fuse_interrupt_in *)fuse_interrupt_in->fad_data)->unique;
}

FUSE_INLINE
void
fuse_interrupt_in_set_unique(struct fuse_abi_data *fuse_interrupt_in, uint64_t unique)
{
    ((struct fuse_interrupt_in *)fuse_interrupt_in->fad_data)->unique = unique;
}

#pragma mark fuse_bmap_in

FUSE_INLINE
size_t
fuse_bmap_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_bmap_in);
}

FUSE_INLINE
uint64_t
fuse_bmap_in_get_block(struct fuse_abi_data *fuse_bmap_in)
{
    return ((struct fuse_bmap_in *)fuse_bmap_in->fad_data)->block;
}

FUSE_INLINE
void
fuse_bmap_in_set_block(struct fuse_abi_data *fuse_bmap_in, uint64_t block)
{
    ((struct fuse_bmap_in *)fuse_bmap_in->fad_data)->block = block;
}

FUSE_INLINE
uint32_t
fuse_bmap_in_get_blocksize(struct fuse_abi_data *fuse_bmap_in)
{
    return ((struct fuse_bmap_in *)fuse_bmap_in->fad_data)->blocksize;
}

FUSE_INLINE
void
fuse_bmap_in_set_blocksize(struct fuse_abi_data *fuse_bmap_in, uint32_t blocksize)
{
    ((struct fuse_bmap_in *)fuse_bmap_in->fad_data)->blocksize = blocksize;
}

#pragma mark fuse_bmap_out

FUSE_INLINE
size_t
fuse_bmap_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_bmap_out);
}

FUSE_INLINE
uint64_t
fuse_bmap_out_get_block(struct fuse_abi_data *fuse_bmap_out)
{
    return ((struct fuse_bmap_out *)fuse_bmap_out->fad_data)->block;
}

FUSE_INLINE
void
fuse_bmap_out_set_block(struct fuse_abi_data *fuse_bmap_out, uint64_t block)
{
    ((struct fuse_bmap_out *)fuse_bmap_out->fad_data)->block = block;
}

#pragma mark fuse_ioctl_in

FUSE_INLINE
size_t
fuse_ioctl_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_ioctl_in);
}

FUSE_INLINE
uint64_t
fuse_ioctl_in_get_fh(struct fuse_abi_data *fuse_ioctl_in)
{
    return ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_ioctl_in_set_fh(struct fuse_abi_data *fuse_ioctl_in, uint64_t fh)
{
    ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint32_t
fuse_ioctl_in_get_flags(struct fuse_abi_data *fuse_ioctl_in)
{
    return ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_ioctl_in_set_flags(struct fuse_abi_data *fuse_ioctl_in, uint32_t flags)
{
    ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
fuse_ioctl_in_get_cmd(struct fuse_abi_data *fuse_ioctl_in)
{
    return ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->cmd;
}

FUSE_INLINE
void
fuse_ioctl_in_set_cmd(struct fuse_abi_data *fuse_ioctl_in, uint32_t cmd)
{
    ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->cmd = cmd;
}

FUSE_INLINE
uint64_t
fuse_ioctl_in_get_arg(struct fuse_abi_data *fuse_ioctl_in)
{
    return ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->arg;
}

FUSE_INLINE
void
fuse_ioctl_in_set_arg(struct fuse_abi_data *fuse_ioctl_in, uint64_t arg)
{
    ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->arg = arg;
}

FUSE_INLINE
uint32_t
fuse_ioctl_in_get_in_size(struct fuse_abi_data *fuse_ioctl_in)
{
    return ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->in_size;
}

FUSE_INLINE
void
fuse_ioctl_in_set_in_size(struct fuse_abi_data *fuse_ioctl_in, uint32_t in_size)
{
    ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->in_size = in_size;
}

FUSE_INLINE
uint32_t
fuse_ioctl_in_get_out_size(struct fuse_abi_data *fuse_ioctl_in)
{
    return ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->out_size;
}

FUSE_INLINE
void
fuse_ioctl_in_set_out_size(struct fuse_abi_data *fuse_ioctl_in, uint32_t out_size)
{
    ((struct fuse_ioctl_in *)fuse_ioctl_in->fad_data)->out_size = out_size;
}

#pragma mark fuse_ioctl_iovec

FUSE_INLINE
size_t
fuse_ioctl_iovec_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_ioctl_iovec);
}

FUSE_INLINE
uint64_t
fuse_ioctl_iovec_get_base(struct fuse_abi_data *fuse_ioctl_iovec)
{
    return ((struct fuse_ioctl_iovec *)fuse_ioctl_iovec->fad_data)->base;
}

FUSE_INLINE
void
fuse_ioctl_iovec_set_base(struct fuse_abi_data *fuse_ioctl_iovec, uint64_t base)
{
    ((struct fuse_ioctl_iovec *)fuse_ioctl_iovec->fad_data)->base = base;
}

FUSE_INLINE
uint64_t
fuse_ioctl_iovec_get_len(struct fuse_abi_data *fuse_ioctl_iovec)
{
    return ((struct fuse_ioctl_iovec *)fuse_ioctl_iovec->fad_data)->len;
}

FUSE_INLINE
void
fuse_ioctl_iovec_set_len(struct fuse_abi_data *fuse_ioctl_iovec, uint64_t len)
{
    ((struct fuse_ioctl_iovec *)fuse_ioctl_iovec->fad_data)->len = len;
}

#pragma mark fuse_ioctl_out

FUSE_INLINE
size_t
fuse_ioctl_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_ioctl_out);
}

FUSE_INLINE
int32_t
fuse_ioctl_out_get_result(struct fuse_abi_data *fuse_ioctl_out)
{
    return ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->result;
}

FUSE_INLINE
void
fuse_ioctl_out_set_result(struct fuse_abi_data *fuse_ioctl_out, int32_t result)
{
    ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->result = result;
}

FUSE_INLINE
uint32_t
fuse_ioctl_out_get_flags(struct fuse_abi_data *fuse_ioctl_out)
{
    return ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->flags;
}

FUSE_INLINE
void
fuse_ioctl_out_set_flags(struct fuse_abi_data *fuse_ioctl_out, uint32_t flags)
{
    ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->flags = flags;
}

FUSE_INLINE
uint32_t
fuse_ioctl_out_get_in_iovs(struct fuse_abi_data *fuse_ioctl_out)
{
    return ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->in_iovs;
}

FUSE_INLINE
void
fuse_ioctl_out_set_in_iovs(struct fuse_abi_data *fuse_ioctl_out, uint32_t in_iovs)
{
    ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->in_iovs = in_iovs;
}

FUSE_INLINE
uint32_t
fuse_ioctl_out_get_out_iovs(struct fuse_abi_data *fuse_ioctl_out)
{
    return ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->out_iovs;
}

FUSE_INLINE
void
fuse_ioctl_out_set_out_iovs(struct fuse_abi_data *fuse_ioctl_out, uint32_t out_iovs)
{
    ((struct fuse_ioctl_out *)fuse_ioctl_out->fad_data)->out_iovs = out_iovs;
}

#pragma mark fuse_poll_in

FUSE_INLINE
size_t
fuse_poll_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_poll_in);
}

FUSE_INLINE
uint64_t
fuse_poll_in_get_fh(struct fuse_abi_data *fuse_poll_in)
{
    return ((struct fuse_poll_in *)fuse_poll_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_poll_in_set_fh(struct fuse_abi_data *fuse_poll_in, uint64_t fh)
{
    ((struct fuse_poll_in *)fuse_poll_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint64_t
fuse_poll_in_get_kh(struct fuse_abi_data *fuse_poll_in)
{
    return ((struct fuse_poll_in *)fuse_poll_in->fad_data)->kh;
}

FUSE_INLINE
void
fuse_poll_in_set_kh(struct fuse_abi_data *fuse_poll_in, uint64_t kh)
{
    ((struct fuse_poll_in *)fuse_poll_in->fad_data)->kh = kh;
}

FUSE_INLINE
uint32_t
fuse_poll_in_get_flags(struct fuse_abi_data *fuse_poll_in)
{
    return ((struct fuse_poll_in *)fuse_poll_in->fad_data)->flags;
}

FUSE_INLINE
void
fuse_poll_in_set_flags(struct fuse_abi_data *fuse_poll_in, uint32_t flags)
{
    ((struct fuse_poll_in *)fuse_poll_in->fad_data)->flags = flags;
}

#pragma mark fuse_poll_out

FUSE_INLINE
size_t
fuse_poll_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_poll_out);
}

FUSE_INLINE
uint32_t
fuse_poll_out_get_revents(struct fuse_abi_data *fuse_poll_out)
{
    return ((struct fuse_poll_out *)fuse_poll_out->fad_data)->revents;
}

FUSE_INLINE
void
fuse_poll_out_set_revents(struct fuse_abi_data *fuse_poll_out, uint32_t revents)
{
    ((struct fuse_poll_out *)fuse_poll_out->fad_data)->revents = revents;
}

#pragma mark fuse_notify_poll_wakeup_out

FUSE_INLINE
size_t
fuse_notify_poll_wakeup_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_notify_poll_wakeup_out);
}

FUSE_INLINE
uint64_t
fuse_notify_poll_wakeup_out_get_kh(struct fuse_abi_data *fuse_notify_poll_wakeup_out)
{
    return ((struct fuse_notify_poll_wakeup_out *)fuse_notify_poll_wakeup_out->fad_data)->kh;
}

FUSE_INLINE
void
fuse_notify_poll_wakeup_out_set_kh(struct fuse_abi_data *fuse_notify_poll_wakeup_out, uint64_t kh)
{
    ((struct fuse_notify_poll_wakeup_out *)fuse_notify_poll_wakeup_out->fad_data)->kh = kh;
}

#pragma mark fuse_fallocate_in

FUSE_INLINE
size_t
fuse_fallocate_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_fallocate_in);
}

FUSE_INLINE
uint64_t
fuse_fallocate_in_get_fh(struct fuse_abi_data *fuse_fallocate_in)
{
    return ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->fh;
}

FUSE_INLINE
void
fuse_fallocate_in_set_fh(struct fuse_abi_data *fuse_fallocate_in, uint64_t fh)
{
    ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->fh = fh;
}

FUSE_INLINE
uint64_t
fuse_fallocate_in_get_offset(struct fuse_abi_data *fuse_fallocate_in)
{
    return ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->offset;
}

FUSE_INLINE
void
fuse_fallocate_in_set_offset(struct fuse_abi_data *fuse_fallocate_in, uint64_t offset)
{
    ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->offset = offset;
}

FUSE_INLINE
uint64_t
fuse_fallocate_in_get_length(struct fuse_abi_data *fuse_fallocate_in)
{
    return ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->length;
}

FUSE_INLINE
void
fuse_fallocate_in_set_length(struct fuse_abi_data *fuse_fallocate_in, uint64_t length)
{
    ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->length = length;
}

FUSE_INLINE
uint32_t
fuse_fallocate_in_get_mode(struct fuse_abi_data *fuse_fallocate_in)
{
    return ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->mode;
}

FUSE_INLINE
void
fuse_fallocate_in_set_mode(struct fuse_abi_data *fuse_fallocate_in, uint32_t mode)
{
    ((struct fuse_fallocate_in *)fuse_fallocate_in->fad_data)->mode = mode;
}

#pragma mark fuse_in_header

FUSE_INLINE
size_t
fuse_in_header_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_in_header);
}

FUSE_INLINE
uint32_t
fuse_in_header_get_len(struct fuse_abi_data *fuse_in_header)
{
    return ((struct fuse_in_header *)fuse_in_header->fad_data)->len;
}

FUSE_INLINE
void
fuse_in_header_set_len(struct fuse_abi_data *fuse_in_header, uint32_t len)
{
    ((struct fuse_in_header *)fuse_in_header->fad_data)->len = len;
}

FUSE_INLINE
uint32_t
fuse_in_header_get_opcode(struct fuse_abi_data *fuse_in_header)
{
    return ((struct fuse_in_header *)fuse_in_header->fad_data)->opcode;
}

FUSE_INLINE
void
fuse_in_header_set_opcode(struct fuse_abi_data *fuse_in_header, uint32_t opcode)
{
    ((struct fuse_in_header *)fuse_in_header->fad_data)->opcode = opcode;
}

FUSE_INLINE
uint64_t
fuse_in_header_get_unique(struct fuse_abi_data *fuse_in_header)
{
    return ((struct fuse_in_header *)fuse_in_header->fad_data)->unique;
}

FUSE_INLINE
void
fuse_in_header_set_unique(struct fuse_abi_data *fuse_in_header, uint64_t unique)
{
    ((struct fuse_in_header *)fuse_in_header->fad_data)->unique = unique;
}

FUSE_INLINE
uint64_t
fuse_in_header_get_nodeid(struct fuse_abi_data *fuse_in_header)
{
    return ((struct fuse_in_header *)fuse_in_header->fad_data)->nodeid;
}

FUSE_INLINE
void
fuse_in_header_set_nodeid(struct fuse_abi_data *fuse_in_header, uint64_t nodeid)
{
    ((struct fuse_in_header *)fuse_in_header->fad_data)->nodeid = nodeid;
}

FUSE_INLINE
uint32_t
fuse_in_header_get_uid(struct fuse_abi_data *fuse_in_header)
{
    return ((struct fuse_in_header *)fuse_in_header->fad_data)->uid;
}

FUSE_INLINE
void
fuse_in_header_set_uid(struct fuse_abi_data *fuse_in_header, uint32_t uid)
{
    ((struct fuse_in_header *)fuse_in_header->fad_data)->uid = uid;
}

FUSE_INLINE
uint32_t
fuse_in_header_get_gid(struct fuse_abi_data *fuse_in_header)
{
    return ((struct fuse_in_header *)fuse_in_header->fad_data)->gid;
}

FUSE_INLINE
void
fuse_in_header_set_gid(struct fuse_abi_data *fuse_in_header, uint32_t gid)
{
    ((struct fuse_in_header *)fuse_in_header->fad_data)->gid = gid;
}

FUSE_INLINE
uint32_t
fuse_in_header_get_pid(struct fuse_abi_data *fuse_in_header)
{
    return ((struct fuse_in_header *)fuse_in_header->fad_data)->pid;
}

FUSE_INLINE
void
fuse_in_header_set_pid(struct fuse_abi_data *fuse_in_header, uint32_t pid)
{
    ((struct fuse_in_header *)fuse_in_header->fad_data)->pid = pid;
}

#pragma mark fuse_out_header

FUSE_INLINE
size_t
fuse_out_header_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_out_header);
}

FUSE_INLINE
uint32_t
fuse_out_header_get_len(struct fuse_abi_data *fuse_out_header)
{
    return ((struct fuse_out_header *)fuse_out_header->fad_data)->len;
}

FUSE_INLINE
void
fuse_out_header_set_len(struct fuse_abi_data *fuse_out_header, uint32_t len)
{
    ((struct fuse_out_header *)fuse_out_header->fad_data)->len = len;
}

FUSE_INLINE
int32_t
fuse_out_header_get_error(struct fuse_abi_data *fuse_out_header)
{
    return ((struct fuse_out_header *)fuse_out_header->fad_data)->error;
}

FUSE_INLINE
void
fuse_out_header_set_error(struct fuse_abi_data *fuse_out_header, int32_t error)
{
    ((struct fuse_out_header *)fuse_out_header->fad_data)->error = error;
}

FUSE_INLINE
uint64_t
fuse_out_header_get_unique(struct fuse_abi_data *fuse_out_header)
{
    return ((struct fuse_out_header *)fuse_out_header->fad_data)->unique;
}

FUSE_INLINE
void
fuse_out_header_set_unique(struct fuse_abi_data *fuse_out_header, uint64_t unique)
{
    ((struct fuse_out_header *)fuse_out_header->fad_data)->unique = unique;
}

#pragma mark fuse_dirent

FUSE_INLINE
size_t
fuse_dirent_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_dirent);
}

FUSE_INLINE
uint64_t
fuse_dirent_get_ino(struct fuse_abi_data *fuse_dirent)
{
    return ((struct fuse_dirent *)fuse_dirent->fad_data)->ino;
}

FUSE_INLINE
void
fuse_dirent_set_ino(struct fuse_abi_data *fuse_dirent, uint64_t ino)
{
    ((struct fuse_dirent *)fuse_dirent->fad_data)->ino = ino;
}

FUSE_INLINE
uint64_t
fuse_dirent_get_off(struct fuse_abi_data *fuse_dirent)
{
    return ((struct fuse_dirent *)fuse_dirent->fad_data)->off;
}

FUSE_INLINE
void
fuse_dirent_set_off(struct fuse_abi_data *fuse_dirent, uint64_t off)
{
    ((struct fuse_dirent *)fuse_dirent->fad_data)->off = off;
}

FUSE_INLINE
uint32_t
fuse_dirent_get_namelen(struct fuse_abi_data *fuse_dirent)
{
    return ((struct fuse_dirent *)fuse_dirent->fad_data)->namelen;
}

FUSE_INLINE
void
fuse_dirent_set_namelen(struct fuse_abi_data *fuse_dirent, uint32_t namelen)
{
    ((struct fuse_dirent *)fuse_dirent->fad_data)->namelen = namelen;
}

FUSE_INLINE
uint32_t
fuse_dirent_get_type(struct fuse_abi_data *fuse_dirent)
{
    return ((struct fuse_dirent *)fuse_dirent->fad_data)->type;
}

FUSE_INLINE
void
fuse_dirent_set_type(struct fuse_abi_data *fuse_dirent, uint32_t type)
{
    ((struct fuse_dirent *)fuse_dirent->fad_data)->type = type;
}

FUSE_INLINE
char *
fuse_dirent_get_name(struct fuse_abi_data *fuse_dirent)
{
    return ((struct fuse_dirent *)fuse_dirent->fad_data)->name;
}

#pragma mark fuse_notify_inval_inode_out

FUSE_INLINE
size_t
fuse_notify_inval_inode_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_notify_inval_inode_out);
}

FUSE_INLINE
uint64_t
fuse_notify_inval_inode_out_get_ino(struct fuse_abi_data *fuse_notify_inval_inode_out)
{
    return ((struct fuse_notify_inval_inode_out *)fuse_notify_inval_inode_out->fad_data)->ino;
}

FUSE_INLINE
void
fuse_notify_inval_inode_out_set_ino(struct fuse_abi_data *fuse_notify_inval_inode_out, uint64_t ino)
{
    ((struct fuse_notify_inval_inode_out *)fuse_notify_inval_inode_out->fad_data)->ino = ino;
}

FUSE_INLINE
int64_t
fuse_notify_inval_inode_out_get_off(struct fuse_abi_data *fuse_notify_inval_inode_out)
{
    return ((struct fuse_notify_inval_inode_out *)fuse_notify_inval_inode_out->fad_data)->off;
}

FUSE_INLINE
void
fuse_notify_inval_inode_out_set_off(struct fuse_abi_data *fuse_notify_inval_inode_out, int64_t off)
{
    ((struct fuse_notify_inval_inode_out *)fuse_notify_inval_inode_out->fad_data)->off = off;
}

FUSE_INLINE
int64_t
fuse_notify_inval_inode_out_get_len(struct fuse_abi_data *fuse_notify_inval_inode_out)
{
    return ((struct fuse_notify_inval_inode_out *)fuse_notify_inval_inode_out->fad_data)->len;
}

FUSE_INLINE
void
fuse_notify_inval_inode_out_set_len(struct fuse_abi_data *fuse_notify_inval_inode_out, int64_t len)
{
    ((struct fuse_notify_inval_inode_out *)fuse_notify_inval_inode_out->fad_data)->len = len;
}

#pragma mark fuse_notify_inval_entry_out

FUSE_INLINE
size_t
fuse_notify_inval_entry_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_notify_inval_entry_out);
}

FUSE_INLINE
uint64_t
fuse_notify_inval_entry_out_get_parent(struct fuse_abi_data *fuse_notify_inval_entry_out)
{
    return ((struct fuse_notify_inval_entry_out *)fuse_notify_inval_entry_out->fad_data)->parent;
}

FUSE_INLINE
void
fuse_notify_inval_entry_out_set_parent(struct fuse_abi_data *fuse_notify_inval_entry_out, uint64_t parent)
{
    ((struct fuse_notify_inval_entry_out *)fuse_notify_inval_entry_out->fad_data)->parent = parent;
}

FUSE_INLINE
uint32_t
fuse_notify_inval_entry_out_get_namelen(struct fuse_abi_data *fuse_notify_inval_entry_out)
{
    return ((struct fuse_notify_inval_entry_out *)fuse_notify_inval_entry_out->fad_data)->namelen;
}

FUSE_INLINE
void
fuse_notify_inval_entry_out_set_namelen(struct fuse_abi_data *fuse_notify_inval_entry_out, uint32_t namelen)
{
    ((struct fuse_notify_inval_entry_out *)fuse_notify_inval_entry_out->fad_data)->namelen = namelen;
}

#pragma mark fuse_notify_delete_out

FUSE_INLINE
size_t
fuse_notify_delete_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_notify_delete_out);
}

FUSE_INLINE
uint64_t
fuse_notify_delete_out_get_parent(struct fuse_abi_data *fuse_notify_delete_out)
{
    return ((struct fuse_notify_delete_out *)fuse_notify_delete_out->fad_data)->parent;
}

FUSE_INLINE
void
fuse_notify_delete_out_set_parent(struct fuse_abi_data *fuse_notify_delete_out, uint64_t parent)
{
    ((struct fuse_notify_delete_out *)fuse_notify_delete_out->fad_data)->parent = parent;
}

FUSE_INLINE
uint64_t
fuse_notify_delete_out_get_child(struct fuse_abi_data *fuse_notify_delete_out)
{
    return ((struct fuse_notify_delete_out *)fuse_notify_delete_out->fad_data)->child;
}

FUSE_INLINE
void
fuse_notify_delete_out_set_child(struct fuse_abi_data *fuse_notify_delete_out, uint64_t child)
{
    ((struct fuse_notify_delete_out *)fuse_notify_delete_out->fad_data)->child = child;
}

FUSE_INLINE
uint32_t
fuse_notify_delete_out_get_namelen(struct fuse_abi_data *fuse_notify_delete_out)
{
    return ((struct fuse_notify_delete_out *)fuse_notify_delete_out->fad_data)->namelen;
}

FUSE_INLINE
void
fuse_notify_delete_out_set_namelen(struct fuse_abi_data *fuse_notify_delete_out, uint32_t namelen)
{
    ((struct fuse_notify_delete_out *)fuse_notify_delete_out->fad_data)->namelen = namelen;
}

#pragma mark fuse_notify_store_out

FUSE_INLINE
size_t
fuse_notify_store_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_notify_store_out);
}

FUSE_INLINE
uint64_t
fuse_notify_store_out_get_nodeid(struct fuse_abi_data *fuse_notify_store_out)
{
    return ((struct fuse_notify_store_out *)fuse_notify_store_out->fad_data)->nodeid;
}

FUSE_INLINE
void
fuse_notify_store_out_set_nodeid(struct fuse_abi_data *fuse_notify_store_out, uint64_t nodeid)
{
    ((struct fuse_notify_store_out *)fuse_notify_store_out->fad_data)->nodeid = nodeid;
}

FUSE_INLINE
uint64_t
fuse_notify_store_out_get_offset(struct fuse_abi_data *fuse_notify_store_out)
{
    return ((struct fuse_notify_store_out *)fuse_notify_store_out->fad_data)->offset;
}

FUSE_INLINE
void
fuse_notify_store_out_set_offset(struct fuse_abi_data *fuse_notify_store_out, uint64_t offset)
{
    ((struct fuse_notify_store_out *)fuse_notify_store_out->fad_data)->offset = offset;
}

FUSE_INLINE
uint32_t
fuse_notify_store_out_get_size(struct fuse_abi_data *fuse_notify_store_out)
{
    return ((struct fuse_notify_store_out *)fuse_notify_store_out->fad_data)->size;
}

FUSE_INLINE
void
fuse_notify_store_out_set_size(struct fuse_abi_data *fuse_notify_store_out, uint32_t size)
{
    ((struct fuse_notify_store_out *)fuse_notify_store_out->fad_data)->size = size;
}

#pragma mark fuse_notify_retrieve_out

FUSE_INLINE
size_t
fuse_notify_retrieve_out_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_notify_retrieve_out);
}

FUSE_INLINE
uint64_t
fuse_notify_retrieve_out_get_notify_unique(struct fuse_abi_data *fuse_notify_retrieve_out)
{
    return ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->notify_unique;
}

FUSE_INLINE
void
fuse_notify_retrieve_out_set_notify_unique(struct fuse_abi_data *fuse_notify_retrieve_out, uint64_t notify_unique)
{
    ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->notify_unique = notify_unique;
}

FUSE_INLINE
uint64_t
fuse_notify_retrieve_out_get_nodeid(struct fuse_abi_data *fuse_notify_retrieve_out)
{
    return ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->nodeid;
}

FUSE_INLINE
void
fuse_notify_retrieve_out_set_nodeid(struct fuse_abi_data *fuse_notify_retrieve_out, uint64_t nodeid)
{
    ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->nodeid = nodeid;
}

FUSE_INLINE
uint64_t
fuse_notify_retrieve_out_get_offset(struct fuse_abi_data *fuse_notify_retrieve_out)
{
    return ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->offset;
}

FUSE_INLINE
void
fuse_notify_retrieve_out_set_offset(struct fuse_abi_data *fuse_notify_retrieve_out, uint64_t offset)
{
    ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->offset = offset;
}

FUSE_INLINE
uint32_t
fuse_notify_retrieve_out_get_size(struct fuse_abi_data *fuse_notify_retrieve_out)
{
    return ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->size;
}

FUSE_INLINE
void
fuse_notify_retrieve_out_set_size(struct fuse_abi_data *fuse_notify_retrieve_out, uint32_t size)
{
    ((struct fuse_notify_retrieve_out *)fuse_notify_retrieve_out->fad_data)->size = size;
}

#pragma mark fuse_notify_retrieve_in

FUSE_INLINE
size_t
fuse_notify_retrieve_in_sizeof(int abi_version)
{
    (void)abi_version;
    return sizeof(struct fuse_notify_retrieve_in);
}

FUSE_INLINE
uint64_t
fuse_notify_retrieve_in_get_offset(struct fuse_abi_data *fuse_notify_retrieve_in)
{
    return ((struct fuse_notify_retrieve_in *)fuse_notify_retrieve_in->fad_data)->offset;
}

FUSE_INLINE
void
fuse_notify_retrieve_in_set_offset(struct fuse_abi_data *fuse_notify_retrieve_in, uint64_t offset)
{
    ((struct fuse_notify_retrieve_in *)fuse_notify_retrieve_in->fad_data)->offset = offset;
}

FUSE_INLINE
uint32_t
fuse_notify_retrieve_in_get_size(struct fuse_abi_data *fuse_notify_retrieve_in)
{
    return ((struct fuse_notify_retrieve_in *)fuse_notify_retrieve_in->fad_data)->size;
}

FUSE_INLINE
void
fuse_notify_retrieve_in_set_size(struct fuse_abi_data *fuse_notify_retrieve_in, uint32_t size)
{
    ((struct fuse_notify_retrieve_in *)fuse_notify_retrieve_in->fad_data)->size = size;
}

#endif /* _FUSE_IPC_H_ */
