/*
 * Copyright (c) 2016 EditShare LLC
 * All rights reserved.
 */

#include "fuse_fsevents.h"

#if VERSION_MAJOR >= 15

void
fsevent(vnode_t vp, uint32_t hint)
{
    struct vnode_attr vattr;

    vfs_get_notify_attributes(&vattr);
    vnode_notify(vp, hint, &vattr);
}

#endif
