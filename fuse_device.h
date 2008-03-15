/*
 * Copyright (C) 2006-2007 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_DEVICE_H_
#define _FUSE_DEVICE_H_

#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>

struct fuse_data;

/* softc */

struct fuse_device;
typedef struct fuse_device * fuse_device_t;

#define FUSE_DEVICE_NULL (fuse_device_t)0

/* Global */

int fuse_devices_start(void);
int fuse_devices_stop(void);

/* Per Device */

fuse_device_t     fuse_device_get(dev_t dev);
struct fuse_data *fuse_device_get_mpdata(fuse_device_t fdev);
uint32_t          fuse_device_get_random(fuse_device_t fdev);

void              fuse_device_lock(fuse_device_t fdev);
void              fuse_device_unlock(fuse_device_t fdev);

void              fuse_device_close_final(fuse_device_t fdev);

/* Control/Debug Utilities */

int fuse_device_kill(int unit, struct proc *p);
int fuse_device_print_vnodes(int unit_flags, struct proc *p);

#endif /* _FUSE_DEVICE_H_ */
