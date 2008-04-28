/*
 * Copyright (C) 2006-2007 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_NODE_H_
#define _FUSE_NODE_H_

#include "fuse_file.h"
#include "fuse_knote.h"
#include "fuse_nodehash.h"
#include <fuse_param.h>

extern errno_t (**fuse_vnode_operations)(void *);

#if M_MACFUSE_ENABLE_FIFOFS
extern errno_t (**fuse_fifo_operations)(void *);
#endif /* M_MACFUSE_ENABLE_FIFOFS */

#if M_MACFUSE_ENABLE_SPECFS
extern errno_t (**fuse_spec_operations)(void *);
#endif /* M_MACFUSE_ENABLE_SPECFS */

enum {
    kFSNodeMagic    = 'FUSE',
    kFSNodeBadMagic = 'FU**',
    kHNodeMagic     = 'HNOD',
};

#define FN_ACCESS_NOOP       0x00000001
#define FN_CREATING          0x00000002
#define FN_DIRECT_IO         0x00000004
#define FN_HAS_ACL           0x00000008
#define FN_IS_ROOT           0x00000010
#define FN_REVOKED           0x00000020

#define C_NEED_RVNODE_PUT    0x000000001
#define C_NEED_DVNODE_PUT    0x000000002
#define C_ZFWANTSYNC         0x000000004
#define C_FROMSYNC           0x000000008
#define C_MODIFIED           0x000000010
#define C_NOEXISTS           0x000000020
#define C_DELETED            0x000000040
#define C_HARDLINK           0x000000080
#define C_FORCEUPDATE        0x000000100
#define C_HASXATTRS          0x000000200
#define C_NEED_DATA_SETSIZE  0x000001000
#define C_NEED_RSRC_SETSIZE  0x000002000
#define C_CREATING           0x000004000
#define C_ACCESS_NOOP        0x000008000
#define C_TOUCH_ACCTIME      0x000010000
#define C_TOUCH_CHGTIME      0x000020000
#define C_TOUCH_MODTIME      0x000040000
#define C_XTIMES_VALID       0x000080000

/* 408 bytes */
struct fuse_vnode_data {

    /** check **/
    uint32_t   fMagic;
    boolean_t  fInitialised;

    /** self **/
    vnode_t    vp;
    uint64_t   nodeid;
    uint64_t   generation;

    /** parent **/
    vnode_t    parentvp;
    uint64_t   parent_nodeid;

    /** I/O **/
    struct     fuse_filehandle fufh[FUFH_MAXTYPE];

    /** flags **/
    uint32_t   flag;
    uint32_t   c_flag;

    /** meta **/
    struct timespec   entry_valid;
    struct timespec   attr_valid;
    struct vnode_attr cached_attr;
    off_t             filesize; 
    uint64_t          nlookup;
    enum vtype        vtype;

    /** locking **/

    lck_mtx_t *createlock;
    void      *creator;

#if M_MACFUSE_ENABLE_TSLOCKING
    /*
     * The nodelock must be held when data in the FUSE node is accessed or
     * modified. Typically, we would take this lock at the beginning of a
     * vnop and drop it at the end of the vnop.
     */
    lck_rw_t  *nodelock;
    void      *nodelockowner;

    /*
     * The truncatelock guards against the EOF changing on us (that is, a
     * file resize) unexpectedly.
     */
    lck_rw_t  *truncatelock;
#endif

    /** miscellaneous **/

#if M_MACFUSE_ENABLE_KQUEUE
    struct klist c_knotes;
#endif /* M_MACFUSE_ENABLE_KQUEUE */
};
typedef struct fuse_vnode_data * fusenode_t;

#define VTOFUD(vp) \
    ((struct fuse_vnode_data *)FSNodeGenericFromHNode(vnode_fsnode(vp)))
#define VTOI(vp)    (VTOFUD(vp)->nodeid)
#define VTOVA(vp)   (&(VTOFUD(vp)->cached_attr))
#define VTOILLU(vp) ((unsigned long long)(VTOFUD(vp) ? VTOI(vp) : 0))

#define FUSE_NULL_ID 0

static __inline__
void
fuse_invalidate_attr(vnode_t vp)
{
    if (VTOFUD(vp)) {
        bzero(&VTOFUD(vp)->attr_valid, sizeof(struct timespec));
        VTOFUD(vp)->c_flag &= ~C_XTIMES_VALID;
    }
}

void fuse_vnode_init(vnode_t vp, struct fuse_vnode_data *fvdat,
                     uint64_t nodeid, enum vtype vtyp, uint64_t parentid);
void fuse_vnode_ditch(vnode_t vp, vfs_context_t context);
void fuse_vnode_teardown(vnode_t vp, vfs_context_t context, enum vtype vtyp);

struct get_filehandle_param {

    enum fuse_opcode opcode;
    uint8_t          do_gc:1;
    uint8_t          do_new:1;

    int   explicitidentity;
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

errno_t
FSNodeGetOrCreateFileVNodeByID(vnode_t               *vpp,
                               uint32_t               flags,
                               struct fuse_entry_out *feo,
                               mount_t                mp,
                               vnode_t                dvp,
                               vfs_context_t          context,
                               uint32_t              *oflags);

void FSNodeScrub(struct fuse_vnode_data *fvdat);

int
fuse_vget_i(vnode_t               *vpp,
            uint32_t               flags,
            struct fuse_entry_out *feo,
            struct componentname  *cnp,
            vnode_t                dvp,
            mount_t                mp,
            vfs_context_t          context);

/* Name cache wrappers */

static __inline__
void
fuse_vncache_enter(vnode_t dvp, vnode_t vp, struct componentname *cnp)
{
#if FUSE_TRACE_VNCACHE
    IOLog("MacFUSE: cache enter dvp=%p, vp=%p, %s\n", dvp, vp, cnp->cn_nameptr);
#endif
    return cache_enter(dvp, vp, cnp);
}

static __inline__
void
fuse_vncache_purge(vnode_t vp)
{
#if FUSE_TRACE_VNCACHE
    IOLog("MacFUSE: cache purge vp=%p\n", vp);
#endif
    return cache_purge(vp);
}

static __inline__
int
fuse_vncache_lookup(vnode_t dvp, vnode_t *vpp, struct componentname *cnp)
{
    int ret = cache_lookup(dvp, vpp, cnp);
#if FUSE_TRACE_VNCACHE
    IOLog("MacFUSE: cache lookup ret=%d, dvp=%p, *vpp=%p, %s\n",
          ret, dvp, *vpp, cnp->cn_nameptr);
#endif
    return ret;
}

#endif /* _FUSE_NODE_H_ */
