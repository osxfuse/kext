/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#include <err.h>
#include <libgen.h>
#include <sysexits.h>
#include <paths.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <libgen.h>
#include <signal.h>
#include <mach/mach.h>

#include "mntopts.h"
#include <fuse_ioctl.h>
#include <fuse_mount.h>
#include <fuse_param.h>
#include <fuse_version.h>

#include <CoreFoundation/CoreFoundation.h>

#define PROGNAME "mount_" MACFUSE_FS_TYPE

static int signal_idx = -1;

void  showhelp(void);
void  showversion(int doexit);

struct mntopt mopts[] = {
    MOPT_STDOPTS,
    MOPT_UPDATE,
    { "allow_other",         0, FUSE_MOPT_ALLOW_OTHER,            1 }, // kused
    { "allow_recursion",     0, FUSE_MOPT_ALLOW_RECURSION,        1 }, // uused
    { "allow_root",          0, FUSE_MOPT_ALLOW_ROOT,             1 }, // kused
    { "autoxattr",           0, FUSE_MOPT_AUTO_XATTR,             1 }, // kused
    { "blocksize=",          0, FUSE_MOPT_BLOCKSIZE,              1 }, // kused
    { "daemon_timeout=",     0, FUSE_MOPT_DAEMON_TIMEOUT,         1 }, // kused
    { "debug",               0, FUSE_MOPT_DEBUG,                  1 }, // kused
    { "default_permissions", 0, FUSE_MOPT_DEFAULT_PERMISSIONS,    1 },
    { "defer_auth",          0, FUSE_MOPT_DEFER_AUTH,             1 }, // kused
    { "direct_io",           0, FUSE_MOPT_DIRECT_IO,              1 }, // kused
    { "extended_security",   0, FUSE_MOPT_EXTENDED_SECURITY,      1 }, // kused
    { "fd=",                 0, FUSE_MOPT_FD,                     1 },
    { "fsid=" ,              0, FUSE_MOPT_FSID,                   1 }, // kused
    { "fsname=",             0, FUSE_MOPT_FSNAME,                 1 }, // kused
    { "fssubtype=",          0, FUSE_MOPT_FSSUBTYPE,              1 }, // kused
    { "gid=",                0, FUSE_MOPT_GID,                    1 }, // kused
    { "hard_remove",         0, FUSE_MOPT_HARD_REMOVE,            1 },
    { "init_timeout=",       0, FUSE_MOPT_INIT_TIMEOUT,           1 }, // kused
    { "iosize=",             0, FUSE_MOPT_IOSIZE,                 1 }, // kused
    { "jail_symlinks",       0, FUSE_MOPT_JAIL_SYMLINKS,          1 }, // kused
    { "kernel_cache",        0, FUSE_MOPT_KERNEL_CACHE,           1 },
    { "kill_on_unmount",     0, FUSE_MOPT_KILL_ON_UNMOUNT,        1 }, // kused 
    { "readdir_ino",         0, FUSE_MOPT_READDIR_INO,            1 },
    { "rootmode=",           0, FUSE_MOPT_ROOTMODE,               1 },
    { "uid=",                0, FUSE_MOPT_UID,                    1 }, // kused
    { "umask=",              0, FUSE_MOPT_UMASK,                  1 },
    { "use_ino",             0, FUSE_MOPT_USE_INO,                1 },
    { "volname=",            0, FUSE_MOPT_VOLNAME,                1 }, // kused

    /* negative ones */

    { "alerts",              1, FUSE_MOPT_NO_ALERTS,              1 }, // kused
    { "appledouble",         1, FUSE_MOPT_NO_APPLEDOUBLE,         1 }, // kused
    { "applexattr",          1, FUSE_MOPT_NO_APPLEXATTR,          1 }, // kused
    { "attrcache",           1, FUSE_MOPT_NO_ATTRCACHE,           1 }, // kused
    { "authopaque",          1, FUSE_MOPT_NO_AUTH_OPAQUE,         1 }, // kused
    { "authopaqueaccess",    1, FUSE_MOPT_NO_AUTH_OPAQUE_ACCESS,  1 }, // kused
    { "browse",              1, FUSE_MOPT_NO_BROWSE,              1 }, // kused
    { "localcaches",         1, FUSE_MOPT_NO_LOCALCACHES,         1 }, // kused
    { "readahead",           1, FUSE_MOPT_NO_READAHEAD,           1 }, // kused
    { "synconclose",         1, FUSE_MOPT_NO_SYNCONCLOSE,         1 }, // kused
    { "syncwrites",          1, FUSE_MOPT_NO_SYNCWRITES,          1 }, // kused
    { "ubc",                 1, FUSE_MOPT_NO_UBC,                 1 }, // kused
    { "vncache",             1, FUSE_MOPT_NO_VNCACHE,             1 }, // kused

    { NULL }
};

typedef int (* converter_t)(void **target, void *value, void *fallback);

struct mntval {
    uint64_t    mv_mntflag;
    void       *mv_value;
    int         mv_len;
    converter_t mv_converter;
    void       *mv_fallback;
    void      **mv_target;
    char       *mv_errstr;
};

static __inline__ int
fuse_to_string(void **target, void *value, void *fallback)
{
    if (!value) {
        // think about what to do if we want to set a NULL value when the
        // fallback value is non-NULL
        value = fallback;
    }

    *target = value;

    return 0;
}

static __inline__ int
fuse_to_uint32(void **target, void *value, void *fallback)
{
    unsigned long u;

    if (!value) {
        *target = fallback;
        return 0;
    }

    errno = 0;
    u = strtoul((char *)value, NULL, 10);
    if ((errno == ERANGE) || (errno == EINVAL)) {
        *target = fallback;
        return errno;
    }

    *target = (void *)u;

    return 0;
}

static __inline__ int
fuse_to_fsid(void **target, void *value, void *fallback)
{
    int ret;
    uint32_t u;

    if (!value) {
        *target = fallback;
        return 0;
    }

    ret = fuse_to_uint32(target, value, fallback);

    if (ret) {
        return ret;
    }

    u = *(uint32_t *)target;

    if ((u & ~FUSE_MINOR_MASK) || (u == 0)) {
        return EINVAL;
    }

    return 0;
}

static __inline__ int
fuse_to_fssubtype(void **target, void *value, void *fallback)
{
    int ret = 0;
    uint32_t u;
    
    *(uint32_t *)target = FUSE_FSSUBTYPE_UNKNOWN;

    if (value) {
        ret = fuse_to_uint32(target, value, fallback);
        if (ret) {
            return ret;
        }   
        u = *(uint32_t *)target;
        if (u >= FUSE_FSSUBTYPE_MAX) {
            return EINVAL;
        }
        if (u > FUSE_FSSUBTYPE_UNKNOWN) {
            return 0;
        }
    }

    /* try to guess */

    *(uint32_t *)target = FUSE_FSSUBTYPE_UNKNOWN;

    {
        char *title = getenv("MOUNT_FUSEFS_DAEMON_PATH");

        if (!title) {
            return 0;
        }

        if (strcasestr(title, "xmp")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_XMPFS;
        } else if (strcasestr(title, "ssh")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_SSHFS;
        } else if (strcasestr(title, "ftp")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_FTPFS;
        } else if ((strcasestr(title, "webdav")) ||
                   (strcasestr(title, "wdfs"))) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_WEBDAVFS;
        } else if (strcasestr(title, "spotlight")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_SPOTLIGHTFS;
        } else if (strcasestr(title, "picasa")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_PICASAFS;
        } else if (strcasestr(title, "proc")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_PROCFS;
        } else if (strcasestr(title, "ntfs")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_NTFS;
        } else if (strcasestr(title, "beagle")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_BEAGLEFS;
        } else if (strcasestr(title, "crypto")) {
            *(uint32_t *)target = FUSE_FSSUBTYPE_CRYPTOFS;
        }
    }
    
    return 0;
}

static uint32_t  blocksize      = FUSE_DEFAULT_BLOCKSIZE;
static uint32_t  daemon_timeout = FUSE_DEFAULT_DAEMON_TIMEOUT;
static uint32_t  fsid           = 0;
static char     *fsname         = NULL;
static uint32_t  init_timeout   = FUSE_DEFAULT_INIT_TIMEOUT;
static uint32_t  iosize         = FUSE_DEFAULT_IOSIZE;
static uint32_t  fssubtype      = 0;
static char     *volname        = NULL;

struct mntval mvals[] = {
    {
        FUSE_MOPT_BLOCKSIZE,
        NULL,
        0,
        fuse_to_uint32,
        (void *)FUSE_DEFAULT_BLOCKSIZE,
        (void **)&blocksize,
        "invalid value for argument blocksize"
    },
    {
        FUSE_MOPT_DAEMON_TIMEOUT,
        NULL,
        0,
        fuse_to_uint32,
        (void *)FUSE_DEFAULT_DAEMON_TIMEOUT,
        (void **)&daemon_timeout,
        "invalid value for argument daemon_timeout"
    },
    {
        FUSE_MOPT_FSID,
        NULL,
        0,
        fuse_to_fsid,
        0,
        (void **)&fsid,
        "invalid value for argument fsid (must be 0 < fsid < 0xFFFFFF)"
    },
    {
        FUSE_MOPT_FSNAME,
        NULL,
        0,
        fuse_to_string,
        NULL,
        (void **)&fsname,
        "invalid value for argument fsname"
    },
    {
        FUSE_MOPT_INIT_TIMEOUT,
        NULL,
        0,
        fuse_to_uint32,
        (void *)FUSE_DEFAULT_INIT_TIMEOUT,
        (void **)&init_timeout,
        "invalid value for argument init_timeout"
    },
    {
        FUSE_MOPT_IOSIZE,
        NULL,
        0,
        fuse_to_uint32,
        (void *)FUSE_DEFAULT_IOSIZE,
        (void **)&iosize,
        "invalid value for argument iosize"
    },
    {
        FUSE_MOPT_FSSUBTYPE,
        NULL,
        0,
        fuse_to_fssubtype,
        NULL,
        (void **)&fssubtype,
        "invalid value for argument fssubtype"
    },
    {
        FUSE_MOPT_VOLNAME,
        NULL,
        0,
        fuse_to_string,
        NULL,
        (void **)&volname,
        "invalid value for argument volname"
    },
    {
        0, NULL, 0, NULL, (void *)NULL, (void **)NULL, (char *)NULL
    },
};

static void
fuse_process_mvals(void)
{
    int ret;
    struct mntval *mv;

    for (mv = mvals; mv->mv_mntflag; mv++) {
        ret = mv->mv_converter(mv->mv_target, mv->mv_value, mv->mv_fallback);
        if (ret) {
            fprintf(stderr, "%s\n", mv->mv_errstr);
            exit(ret);
        }
    }
}

static int
post_notification(char   *name,
                  char   *udata_keys[],
                  char   *udata_values[],
                  CFIndex nf_num)
{
    CFIndex i;
    CFStringRef nf_name   = NULL;
    CFStringRef nf_object = NULL;
    CFMutableDictionaryRef nf_udata  = NULL;

    CFNotificationCenterRef distributedCenter;
    CFStringEncoding encoding = kCFStringEncodingASCII;

    distributedCenter = CFNotificationCenterGetDistributedCenter();

    if (!distributedCenter) {
        return -1;
    }

    nf_name = CFStringCreateWithCString(kCFAllocatorDefault, name, encoding);
      
    nf_object = CFStringCreateWithCString(kCFAllocatorDefault,
                                          FUSE_UNOTIFICATIONS_OBJECT,
                                          encoding);
 
    nf_udata = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                         nf_num,
                                         &kCFCopyStringDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);

    if (!nf_name || !nf_object || !nf_udata) {
        goto out;
    }

    for (i = 0; i < nf_num; i++) {
        CFStringRef a_key = CFStringCreateWithCString(kCFAllocatorDefault,
                                                      udata_keys[i],
                                                      kCFStringEncodingASCII);
        CFStringRef a_value = CFStringCreateWithCString(kCFAllocatorDefault,
                                                        udata_values[i],
                                                        kCFStringEncodingASCII);
        CFDictionarySetValue(nf_udata, a_key, a_value);
        CFRelease(a_key);
        CFRelease(a_value);
    }

    CFNotificationCenterPostNotification(distributedCenter,
                                         nf_name, nf_object, nf_udata, false);

out:
    if (nf_name) {
        CFRelease(nf_name);
    }

    if (nf_object) {
        CFRelease(nf_object);
    }

    if (nf_udata) {
        CFRelease(nf_udata);
    }

    return 0;
}

static int
check_kext_status(void)
{
    int    result = -1;
    char   version[MAXHOSTNAMELEN + 1] = { 0 };
    size_t version_len = MAXHOSTNAMELEN;
    size_t version_len_desired = 0;
    struct vfsconf vfc = { 0 };

    result = getvfsbyname(MACFUSE_FS_TYPE, &vfc);
    if (result) { /* MacFUSE is not already loaded */
        return ESRCH;
    }

    /* some version of MacFUSE is already loaded; let us check it out */

    result = sysctlbyname(SYSCTL_MACFUSE_VERSION_NUMBER, version,
                          &version_len, (void *)NULL, (size_t)0);
    if (result) {
        return result;
    }

    /* sysctlbyname() includes the trailing '\0' in version_len */
    version_len_desired = strlen(MACFUSE_VERSION) + 1;

    if ((version_len != version_len_desired) ||
        strncmp(MACFUSE_VERSION, version, version_len)) {
        return EINVAL;
    }

    /* what's currently loaded is good */

    return 0;
}

static void
signal_idx_atexit_handler(void)
{
    if (signal_idx != -1) {

        int32_t kill_fs_old = 0;
        int32_t kill_fs_new = signal_idx;
        size_t oldlen = sizeof(kill_fs_old);
        size_t newlen = sizeof(kill_fs_new);

        (void)sysctlbyname("macfuse.control.kill_fs", (void *)&kill_fs_old,
                           &oldlen, (void *)&kill_fs_new, newlen);
    }
}

// We will be called as follows by the FUSE library:
//
//   mount_<MACFUSE_FS_TYPE> -o OPTIONS... <fdnam> <mountpoint>

int
main(int argc, char **argv)
{
    int       result    = -1;
    int       mntflags  = 0;
    int       fd        = -1;
    int32_t   dindex    = -1;
    char     *fdnam     = NULL;
    uint64_t  altflags  = 0;
    char     *mntpath   = NULL;

    int i, ch = '\0', done = 0;
    struct mntopt *mo;
    struct mntval *mv;
    struct statfs statfsb;
    fuse_mount_args args;

    if (!getenv("MOUNT_FUSEFS_CALL_BY_LIB")) {
        showhelp();
        /* NOTREACHED */
    }

    /* Kludge to make "<fsdaemon> --version" happy. */
    if ((argc == 2) &&
        ((!strncmp(argv[1], "--version", strlen("--version"))) ||
         (!strncmp(argv[1], "-v", strlen("-v"))))) {
        showversion(1);
    }

    /* Kludge to make "<fsdaemon> --help" happy. */
    if ((argc == 2) &&
        ((!strncmp(argv[1], "--help", strlen("--help"))) ||
         (!strncmp(argv[1], "-h", strlen("-h"))))) {
        showhelp();
    }

    do {
        for (i = 0; i < 3; i++) {
            if (optind < argc && argv[optind][0] != '-') {
                if (mntpath) {
                    done = 1;
                    break;
                }
                if (fdnam)
                    mntpath = argv[optind];
                else
                    fdnam = argv[optind];
                optind++;
            }
        }

        switch(ch) {
        case 'o':
            getmntopts(optarg, mopts, &mntflags, &altflags);
            for (mv = mvals; mv->mv_mntflag; ++mv) {
                if (!(altflags & mv->mv_mntflag)) {
                    continue;
                }
                for (mo = mopts; mo->m_option; ++mo) {
                    char *p, *q;
                    if (mo->m_flag != mv->mv_mntflag) {
                        continue;
                    }
                    p = strstr(optarg, mo->m_option);
                    if (p) {
                        p += strlen(mo->m_option);
                        q = p;
                        while (*q != '\0' && *q != ',') {
                            q++;
                        }
                        mv->mv_len = q - p + 1;
                        mv->mv_value = malloc(mv->mv_len);
                        memcpy(mv->mv_value, p, mv->mv_len - 1);
                        ((char *)mv->mv_value)[mv->mv_len - 1] = '\0';
                        break;
                    }
                }
            }
            break;

        case '\0':
            break;

        case 'v': 
            showversion(1);
            break;

        case '?':
        case 'h':
        default:
            showhelp();
            break;
        }

        if (done) {
            break;
        }

    } while ((ch = getopt(argc, argv, "ho:v")) != -1);

    argc -= optind;
    argv += optind;

    if ((!fdnam) && argc > 0) {
        fdnam = *argv++;
        argc--;
    }

    if (!fdnam) {
        errx(1, "missing MacFUSE device file descriptor");
    }

    errno = 0;
    fd = strtol(fdnam, NULL, 10);
    if ((errno == EINVAL) || (errno == ERANGE)) {
        errx(1, "invalid name (%s) for MacFUSE device file descriptor", fdnam);
    }

    {
        char  ndev[MAXPATHLEN];
        char *ndevbas;
        struct stat sb;

        if (fstat(fd, &sb) == -1) {
            err(1, "fstat failed for FUSE device file descriptor");
        }
        args.rdev = sb.st_rdev;
        strcpy(ndev, _PATH_DEV);
        ndevbas = ndev + strlen(_PATH_DEV);
        devname_r(sb.st_rdev, S_IFCHR, ndevbas,
                  sizeof(ndev) - strlen(_PATH_DEV));

        if (strncmp(ndevbas, FUSE_DEVICE_BASENAME,
                    strlen(FUSE_DEVICE_BASENAME))) {
            errx(1, "mounting inappropriate device");
        }

        errno = 0;
        dindex = strtol(ndevbas + strlen(FUSE_DEVICE_BASENAME), NULL, 10);
        if ((errno == EINVAL) || (errno == ERANGE) ||
            (dindex < 0) || (dindex > FUSE_NDEVICES)) {
            errx(1, "invalid FUSE device unit (#%d)\n", dindex);
        }
    }

    signal_idx = dindex;

    atexit(signal_idx_atexit_handler);

    result = check_kext_status();

    switch (result) {

    case 0:
        break;

    case ESRCH:
        errx(1, "the MacFUSE kernel extension is not loaded");
        break;

    case EINVAL:
        errx(1, "the loaded MacFUSE kernel extension has a mismatched version");
        break;

    default:
        errx(1, "failed to query the loaded MacFUSE kernel extension (%d)",
             result);
        break;
    }

    if ((!mntpath) && argc > 0) {
        mntpath = *argv++;
        argc--;
    }

    if (!mntpath) {
        errx(1, "missing mount point");
    }

    (void)checkpath(mntpath, args.mntpath);

    mntpath = args.mntpath;

    fuse_process_mvals();

    if (statfs(mntpath, &statfsb)) {
        errx(1, "cannot stat the mount point %s", mntpath);
    }

    if ((strlen(statfsb.f_fstypename) == strlen(MACFUSE_FS_TYPE)) &&
        (strcmp(statfsb.f_fstypename, MACFUSE_FS_TYPE) == 0)) {
        if (!(altflags & FUSE_MOPT_ALLOW_RECURSION)) {
            errx(1, "mount point %s is itself on a MacFUSE volume", mntpath);
        }
    }

    if (altflags & FUSE_MOPT_NO_LOCALCACHES) {
        altflags |= FUSE_MOPT_NO_READAHEAD;
        altflags |= FUSE_MOPT_NO_UBC;
        altflags |= FUSE_MOPT_NO_VNCACHE;
    }

    /*
     * 'nosyncwrites' must not appear with either 'noubc' or 'noreadahead'.
     */
    if ((altflags & FUSE_MOPT_NO_SYNCWRITES) &&
        (altflags & (FUSE_MOPT_NO_UBC | FUSE_MOPT_NO_READAHEAD))) {
        errx(1, "disabling local caching is not allowed with 'nosyncwrites'");
    }

    /*
     * 'nosynconclose' only allowed if 'nosyncwrites' is also there.
     */
    if ((altflags & FUSE_MOPT_NO_SYNCONCLOSE) &&
        !(altflags & FUSE_MOPT_NO_SYNCWRITES)) {
        errx(1, "the 'nosynconclose' option requires 'nosyncwrites'");
    }

    /*
     * 'novncache' must not appear with 'extended_security'
     */
    if ((altflags & FUSE_MOPT_NO_VNCACHE) &&
        (altflags & FUSE_MOPT_EXTENDED_SECURITY)) {
        errx(1, "'novncache' is not allowed with 'extended_security'");
    }

    if ((altflags & FUSE_MOPT_DEFER_AUTH) &&
        (altflags &
         (FUSE_MOPT_NO_AUTH_OPAQUE | FUSE_MOPT_NO_AUTH_OPAQUE_ACCESS))) {
        errx(1, "'defer_auth' is not allowed with 'noauthopaque*'");
    }

    if (getenv("MOUNT_FUSEFS_NO_ALERTS")) {
        altflags |= FUSE_MOPT_NO_ALERTS;
    }


    if (daemon_timeout < FUSE_MIN_DAEMON_TIMEOUT) {
        daemon_timeout = FUSE_MIN_DAEMON_TIMEOUT;
    }

    if (daemon_timeout > FUSE_MAX_DAEMON_TIMEOUT) {
        daemon_timeout = FUSE_MAX_DAEMON_TIMEOUT;
    }

    if (init_timeout < FUSE_MIN_INIT_TIMEOUT) {
        init_timeout = FUSE_MIN_INIT_TIMEOUT;
    }

    if (init_timeout > FUSE_MAX_INIT_TIMEOUT) {
        init_timeout = FUSE_MAX_INIT_TIMEOUT;
    }

    args.altflags       = altflags;
    args.blocksize      = blocksize;
    args.daemon_timeout = daemon_timeout;
    args.fsid           = fsid;
    args.index          = dindex;
    args.init_timeout   = init_timeout;
    args.iosize         = iosize;
    args.fssubtype      = fssubtype;

    char *daemon_name = NULL;
    char *daemon_path = getenv("MOUNT_FUSEFS_DAEMON_PATH");
    if (daemon_path) {
        daemon_name = basename(daemon_path);
    }

    if (!fsname) {
        if (daemon_name) {
            snprintf(args.fsname, MAXPATHLEN, "%s@fuse%d", daemon_name, dindex);
        } else {
            snprintf(args.fsname, MAXPATHLEN, "instance@fuse%d", dindex);
        }
    } else {
        snprintf(args.fsname, MAXPATHLEN, "%s", fsname);
    }

    if (!volname) {
        if (daemon_name) {
            snprintf(args.volname, MAXPATHLEN, "MacFUSE Volume %d (%s)",
                     dindex, daemon_name);
        } else {
            snprintf(args.volname, MAXPATHLEN, "MacFUSE Volume %d", dindex);
        }
    } else {
        snprintf(args.volname, MAXPATHLEN, "%s", volname);
    }

    if (mount(MACFUSE_FS_TYPE, mntpath, mntflags, (void *)&args) < 0) {
        err(EX_OSERR, "failed to mount %s@/dev/fuse%d", mntpath, dindex);
    }

    {
        char *udata_keys[]   = { kFUSEMountPathKey };
        char *udata_values[] = { mntpath };
           
        post_notification(FUSE_UNOTIFICATIONS_NOTIFY_MOUNTED,
                          udata_keys, udata_values, 1);
    }

    signal_idx = -1;

    exit(0);
}

void
showhelp()
{
    if (!getenv("MOUNT_FUSEFS_CALL_BY_LIB")) {
        showversion(0);
        fprintf(stderr, "\nThis program is not meant to be called directly.\n");
    }
    fprintf(stderr, "\nAvailable mount options:\n");
    fprintf(stderr,
      "    -o allow_other         allow access to others besides the user who mounted"
      "                             mounted the file system\n"
      "    -o allow_recursion     allow a mount point that itself resides on a MacFUSE\n"
      "                           volume (by default, such mounting is disallowed)\n"
      "    -o allow_root          allow access to root (mutually exclusive with the\n"
      "                           allow_other option)\n"
      "    -o blocksize=<size>    specify block size in bytes of \"storage\"\n"
      "    -o daemon_timeout=<s>  timeout in seconds for kernel calls to daemon\n"
      "    -o debug               turn on debug information printing\n"
      "    -o defer_auth          defer permission checks to file operations themselves"
      "    -o extended_security   turn on Mac OS X extended security (ACLs)\n"
      "    -o fsid                set the second 32-bit component of the fsid\n"
      "    -o fssubtype=<num>     set the file system's fssubtype identifier\n"
      "    -o fsname=<name>       set the file system's name\n"
      "    -o iosize=<size>       specify maximum I/O size in bytes\n" 
      "    -o jail_symlinks       contain symbolic links within the mount\n"
      "    -o kill_on_unmount     kernel will send a signal (SIGKILL by default) to the\n                           daemon after unmount finishes\n" 
      "    -o noappledouble       ignore Apple Double (._) and .DS_Store files entirely\n"
      "    -o noapplexattr        ignore all \"com.apple.*\" extended attributes\n"
      "    -o nobrowse            set MNT_DONTBROWSE in the kernel\n"
      "    -o nolocalcaches       meta option equivalent to noreadahead,noubc,novncache\n"
      "    -o noping_diskarb      do not ping Disk Arbitration (pings by default)\n"
      "    -o noreadahead         disable I/O read-ahead behavior for this file system\n"
      "    -o nosynconclose       disable sync-on-close behavior (enabled by default)\n"
      "    -o nosyncwrites        disable synchronous-writes behavior (dangerous)\n"
      "    -o noubc               disable the unified buffer cache for this file system\n"
      "    -o novncache           disable the vnode name cache for this file system\n"
      "    -o volname=<name>      set the file system's volume name\n"      
    );
    exit(EX_USAGE);
}

void
showversion(int doexit)
{
    fprintf(stderr, "MacFUSE version %s\n", MACFUSE_VERSION);
    if (doexit) {
        exit(EX_USAGE);
    }
}
