/*
 ============================================================================
 Name        : hev-app-filter-lookup.c
 Author      : Boris Kovalskii
 Description : Per-OS PID/exe lookup for app-filter (macOS implementation +
               cross-platform test seam)
 ============================================================================
 */

/* On MSYS/MinGW, winsock2.h MUST be included before any header that
 * pulls in <sys/types.h> (fd_set conflict). Do it first. */
#if defined(_WIN32) || defined(__MSYS__)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#endif

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "hev-logger.h"
#include "hev-app-filter-lookup.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

/* libproc / proc_pidfdinfo is macOS-only; iOS/tvOS/watchOS lack the
 * header even though __APPLE__ is defined. */
#if defined(__APPLE__) && defined(TARGET_OS_OSX) && TARGET_OS_OSX
#define HAVE_MACOS_LOOKUP 1
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#define HAVE_MACOS_LOOKUP 0
#endif

/* Linux: SOCK_DIAG netlink + /proc fd scan. Skipped on Android — SELinux
 * blocks reading other apps' /proc/<pid>/fd/, and uid->package mapping
 * needs the host VPNService API which we don't have here. */
#if defined(__linux__) && !defined(__ANDROID__)
#define HAVE_LINUX_LOOKUP 1
#include <dirent.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#define HAVE_LINUX_LOOKUP 0
#endif

#define CACHE_SLOTS    64
#define CACHE_TTL_SEC  60

#if HAVE_MACOS_LOOKUP || HAVE_LINUX_LOOKUP || \
    defined(_WIN32) || defined(__MSYS__)
#define HAVE_INPROC_LOOKUP 1
#else
#define HAVE_INPROC_LOOKUP 0
#endif

typedef struct
{
    int      pid;
    uint64_t expires_mono;
    char     path[1024];
} CacheEntry;

static CacheEntry g_cache[CACHE_SLOTS];

static HevAppFilterLookupFn g_override;

#if HAVE_INPROC_LOOKUP

static uint64_t
mono_now_sec (void)
{
    struct timespec ts;
    if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t) ts.tv_sec;
}

#endif /* HAVE_INPROC_LOOKUP */

/* pid -> exe-path cache. Used by macOS / Windows resolvers; Linux uses
 * its own uid-keyed cache so these are dead code there. */
#if HAVE_MACOS_LOOKUP || defined(_WIN32) || defined(__MSYS__)

static const char *
cache_get (int pid)
{
    if (pid < 0)
        return NULL;
    CacheEntry *e = &g_cache[(unsigned) pid % CACHE_SLOTS];
    if (e->pid != pid)
        return NULL;
    if (e->expires_mono <= mono_now_sec ())
        return NULL;
    return e->path;
}

static void
cache_put (int pid, const char *path)
{
    if (pid < 0 || !path)
        return;
    CacheEntry *e = &g_cache[(unsigned) pid % CACHE_SLOTS];
    e->pid = pid;
    e->expires_mono = mono_now_sec () + CACHE_TTL_SEC;
    strncpy (e->path, path, sizeof (e->path) - 1);
    e->path[sizeof (e->path) - 1] = '\0';
}

#endif

void
hev_app_filter_lookup_cache_clear (void)
{
    memset (g_cache, 0, sizeof (g_cache));
}

void
hev_app_filter_lookup_set_override (HevAppFilterLookupFn fn)
{
    g_override = fn;
}

#if HAVE_MACOS_LOOKUP

/*
 * Match a single socket-info struct against the wanted flow. Returns 1 on
 * match, 0 otherwise. Caller has already filtered by protocol family.
 */
static int
match_socket_info (const struct socket_info *si, const HevAppFilterFlow *flow)
{
    /* insi_lport / insi_fport are stored in network byte order. */
    uint16_t lport_host;
    uint16_t fport_host;

    if (flow->proto == HEV_APP_FILTER_PROTO_TCP) {
        if (si->soi_kind != SOCKINFO_TCP)
            return 0;
    } else if (flow->proto == HEV_APP_FILTER_PROTO_UDP) {
        if (si->soi_kind != SOCKINFO_IN)
            return 0;
    } else {
        return 0;
    }

    const struct in_sockinfo *isi;
    if (flow->proto == HEV_APP_FILTER_PROTO_TCP)
        isi = &si->soi_proto.pri_tcp.tcpsi_ini;
    else
        isi = &si->soi_proto.pri_in;

    lport_host = ntohs ((uint16_t) isi->insi_lport);
    fport_host = ntohs ((uint16_t) isi->insi_fport);

    if (lport_host != flow->local_port)
        return 0;

    /*
     * For UDP, foreign port is often 0 (unconnected socket); skip strict
     * fport match in that case. For TCP we require it to match.
     */
    if (flow->proto == HEV_APP_FILTER_PROTO_TCP &&
        fport_host != flow->remote_port)
        return 0;

    /*
     * Address comparison: insi_vflag distinguishes v4/v6. We accept
     * either (a) family matches and addresses match, or (b) the socket
     * is wildcard-bound (laddr all zero), which is the common case for
     * outbound sockets.
     */
    if (isi->insi_vflag & INI_IPV4) {
        if (flow->family != AF_INET)
            return 0;
        uint32_t laddr = isi->insi_laddr.ina_46.i46a_addr4.s_addr;
        if (laddr != 0) {
            uint32_t want;
            memcpy (&want, flow->local_addr, sizeof (want));
            if (laddr != want)
                return 0;
        }
        return 1;
    }
    if (isi->insi_vflag & INI_IPV6) {
        if (flow->family != AF_INET6)
            return 0;
        const struct in6_addr *laddr = &isi->insi_laddr.ina_6;
        static const uint8_t zero[16] = { 0 };
        if (memcmp (laddr, zero, 16) != 0 &&
            memcmp (laddr, flow->local_addr, 16) != 0)
            return 0;
        return 1;
    }
    return 0;
}

static int
resolve_pid_path (int pid, char *out, size_t outlen)
{
    const char *cached = cache_get (pid);
    if (cached) {
        strncpy (out, cached, outlen - 1);
        out[outlen - 1] = '\0';
        return 0;
    }

    char buf[PROC_PIDPATHINFO_MAXSIZE];
    int n = proc_pidpath (pid, buf, sizeof (buf));
    if (n <= 0)
        return -1;
    buf[n < (int) sizeof (buf) ? n : (int) sizeof (buf) - 1] = '\0';

    cache_put (pid, buf);
    strncpy (out, buf, outlen - 1);
    out[outlen - 1] = '\0';
    return 0;
}

static int
lookup_macos (const HevAppFilterFlow *flow, HevAppFilterLookupResult *out)
{
    int pidcount;
    int *pids = NULL;
    int rc = -1;

    pidcount = proc_listpids (PROC_ALL_PIDS, 0, NULL, 0);
    if (pidcount <= 0)
        return -1;

    /* Re-query with a buffer; size returned is bytes, not entries. */
    int bytes = pidcount;
    pids = (int *) calloc ((size_t) bytes / sizeof (int) + 16, sizeof (int));
    if (!pids)
        return -1;

    bytes = proc_listpids (PROC_ALL_PIDS, 0, pids,
                           (int) ((bytes / sizeof (int) + 16) * sizeof (int)));
    if (bytes <= 0)
        goto done;

    int npids = bytes / (int) sizeof (int);
    for (int i = 0; i < npids; i++) {
        int pid = pids[i];
        if (pid <= 0)
            continue;

        int fdsz = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdsz <= 0)
            continue;
        struct proc_fdinfo *fds = (struct proc_fdinfo *) malloc ((size_t) fdsz);
        if (!fds)
            continue;
        int got = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, fds, fdsz);
        if (got <= 0) {
            free (fds);
            continue;
        }
        int nfds = got / (int) PROC_PIDLISTFD_SIZE;

        for (int j = 0; j < nfds; j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;

            struct socket_fdinfo sinfo;
            int n = proc_pidfdinfo (pid, fds[j].proc_fd,
                                    PROC_PIDFDSOCKETINFO,
                                    &sinfo, sizeof (sinfo));
            if (n != (int) sizeof (sinfo))
                continue;

            if (!match_socket_info (&sinfo.psi, flow))
                continue;

            out->pid = pid;
            out->uid = -1;
            out->path[0] = '\0';
            if (resolve_pid_path (pid, out->path, sizeof (out->path)) < 0) {
                /*
                 * Found owner but couldn't resolve path: degraded match,
                 * still useful for pid-based rules.
                 */
                LOG_D ("[app-filter] pid=%d path-resolve-failed", pid);
            }
            rc = 0;
            free (fds);
            goto done;
        }
        free (fds);
    }

done:
    free (pids);
    return rc;
}

#endif /* HAVE_MACOS_LOOKUP */

#if defined(_WIN32) || defined(__MSYS__)

static int
resolve_pid_path_win (DWORD pid, char *out, size_t outlen)
{
    const char *cached = cache_get ((int) pid);
    if (cached) {
        strncpy (out, cached, outlen - 1);
        out[outlen - 1] = '\0';
        return 0;
    }

    HANDLE h = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return -1;

    /*
     * Use the wide-char API and convert to UTF-8. Some packaged-app hosts
     * have non-ASCII paths (e.g. localized program-files names).
     */
    WCHAR wbuf[1024];
    DWORD wlen = sizeof (wbuf) / sizeof (wbuf[0]);
    BOOL ok = QueryFullProcessImageNameW (h, 0, wbuf, &wlen);
    CloseHandle (h);
    if (!ok)
        return -1;

    int n = WideCharToMultiByte (CP_UTF8, 0, wbuf, (int) wlen,
                                 out, (int) outlen - 1, NULL, NULL);
    if (n <= 0)
        return -1;
    out[n] = '\0';

    /*
     * Strip the \\?\ long-path prefix that QueryFullProcessImageNameW
     * sometimes returns, so paths compare equally with config entries.
     */
    if (strncmp (out, "\\\\?\\", 4) == 0)
        memmove (out, out + 4, strlen (out + 4) + 1);

    cache_put ((int) pid, out);
    return 0;
}

static int
is_packaged_host (const char *path)
{
    /* Match on the basename only. */
    const char *base = strrchr (path, '\\');
    base = base ? base + 1 : path;
    if (strcasecmp (base, "svchost.exe") == 0)
        return 1;
    if (strcasecmp (base, "ApplicationFrameHost.exe") == 0)
        return 1;
    if (strcasecmp (base, "RuntimeBroker.exe") == 0)
        return 1;
    return 0;
}

static int
lookup_tcp_table (const HevAppFilterFlow *flow, ULONG family, DWORD *pid_out)
{
    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable (NULL, &size, FALSE, family,
                                    TCP_TABLE_OWNER_MODULE_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER)
        return -1;
    void *buf = malloc (size);
    if (!buf)
        return -1;
    rc = GetExtendedTcpTable (buf, &size, FALSE, family,
                              TCP_TABLE_OWNER_MODULE_ALL, 0);
    if (rc != NO_ERROR) {
        free (buf);
        return -1;
    }

    int found = -1;
    if (family == AF_INET) {
        const MIB_TCPTABLE_OWNER_MODULE *t = buf;
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            const MIB_TCPROW_OWNER_MODULE *r = &t->table[i];
            uint16_t lport = ntohs ((uint16_t) r->dwLocalPort);
            uint16_t rport = ntohs ((uint16_t) r->dwRemotePort);
            if (lport != flow->local_port || rport != flow->remote_port)
                continue;
            uint32_t want;
            memcpy (&want, flow->local_addr, sizeof (want));
            if (r->dwLocalAddr != 0 && r->dwLocalAddr != want)
                continue;
            *pid_out = r->dwOwningPid;
            found = 0;
            break;
        }
    } else {
        const MIB_TCP6TABLE_OWNER_MODULE *t = buf;
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            const MIB_TCP6ROW_OWNER_MODULE *r = &t->table[i];
            uint16_t lport = ntohs ((uint16_t) r->dwLocalPort);
            uint16_t rport = ntohs ((uint16_t) r->dwRemotePort);
            if (lport != flow->local_port || rport != flow->remote_port)
                continue;
            static const uint8_t zero[16] = { 0 };
            if (memcmp (r->ucLocalAddr, zero, 16) != 0 &&
                memcmp (r->ucLocalAddr, flow->local_addr, 16) != 0)
                continue;
            *pid_out = r->dwOwningPid;
            found = 0;
            break;
        }
    }
    free (buf);
    return found;
}

static int
lookup_udp_table (const HevAppFilterFlow *flow, ULONG family, DWORD *pid_out)
{
    DWORD size = 0;
    DWORD rc = GetExtendedUdpTable (NULL, &size, FALSE, family,
                                    UDP_TABLE_OWNER_MODULE, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER)
        return -1;
    void *buf = malloc (size);
    if (!buf)
        return -1;
    rc = GetExtendedUdpTable (buf, &size, FALSE, family,
                              UDP_TABLE_OWNER_MODULE, 0);
    if (rc != NO_ERROR) {
        free (buf);
        return -1;
    }

    int found = -1;
    if (family == AF_INET) {
        const MIB_UDPTABLE_OWNER_MODULE *t = buf;
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            const MIB_UDPROW_OWNER_MODULE *r = &t->table[i];
            uint16_t lport = ntohs ((uint16_t) r->dwLocalPort);
            if (lport != flow->local_port)
                continue;
            uint32_t want;
            memcpy (&want, flow->local_addr, sizeof (want));
            if (r->dwLocalAddr != 0 && r->dwLocalAddr != want)
                continue;
            *pid_out = r->dwOwningPid;
            found = 0;
            break;
        }
    } else {
        const MIB_UDP6TABLE_OWNER_MODULE *t = buf;
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            const MIB_UDP6ROW_OWNER_MODULE *r = &t->table[i];
            uint16_t lport = ntohs ((uint16_t) r->dwLocalPort);
            if (lport != flow->local_port)
                continue;
            static const uint8_t zero[16] = { 0 };
            if (memcmp (r->ucLocalAddr, zero, 16) != 0 &&
                memcmp (r->ucLocalAddr, flow->local_addr, 16) != 0)
                continue;
            *pid_out = r->dwOwningPid;
            found = 0;
            break;
        }
    }
    free (buf);
    return found;
}

static int
lookup_windows (const HevAppFilterFlow *flow, HevAppFilterLookupResult *out)
{
    DWORD pid = 0;
    int rc;
    ULONG fam = (flow->family == AF_INET6) ? AF_INET6 : AF_INET;

    if (flow->proto == HEV_APP_FILTER_PROTO_TCP)
        rc = lookup_tcp_table (flow, fam, &pid);
    else if (flow->proto == HEV_APP_FILTER_PROTO_UDP)
        rc = lookup_udp_table (flow, fam, &pid);
    else
        return -1;

    if (rc < 0)
        return -1;

    out->pid = (int) pid;
    out->uid = -1;
    if (resolve_pid_path_win (pid, out->path, sizeof (out->path)) < 0) {
        LOG_D ("[app-filter] pid=%lu path-resolve-failed", pid);
        out->path[0] = '\0';
        /* PID-only matches (against app-filter.pids) still work. */
        return 0;
    }

    if (is_packaged_host (out->path)) {
        LOG_W ("[app-filter] pid=%lu is packaged-app host (%s); "
               "UWP not supported in v1, treating as unmatched",
               pid, out->path);
        /*
         * Returning -1 here makes the caller treat this as lookup-failed,
         * which matches the design doc: deferred UWP support, treat as
         * unmatched, warn-once. (Per-host-process warn-once is left to
         * the caller's stat counter.)
         */
        return -1;
    }
    return 0;
}

#endif /* _WIN32 || __MSYS__ */

#if HAVE_LINUX_LOOKUP

/*
 * Linux: SOCK_DIAG/NETLINK_INET_DIAG to map a 5-tuple to (uid, inode),
 * then a uid-keyed /proc scan to map inode to exe path. Modeled on
 * sing-box's common/process/searcher_linux.go but in C and without
 * goroutines.
 */

/* Persistent netlink fds, one per (family, proto). Lazily created. */
static int g_diag_fd[2][2] = { { -1, -1 }, { -1, -1 } };

#define DIAG_FAMILY_IDX(fam) ((fam) == AF_INET6 ? 1 : 0)
#define DIAG_PROTO_IDX(proto)                                                  \
    ((proto) == HEV_APP_FILTER_PROTO_UDP ? 1 : 0)

/* Per-uid inode->path cache with 1s TTL. */
typedef struct
{
    unsigned long inode;
    char          path[1024];
} UidPathEntry;

#define UID_CACHE_SLOTS  16
#define UID_CACHE_INODES 64
#define UID_CACHE_TTL_SEC 1

typedef struct
{
    int          uid;
    uint64_t     expires_mono;
    int          n_entries;
    UidPathEntry entries[UID_CACHE_INODES];
} UidCacheBucket;

static UidCacheBucket g_uid_cache[UID_CACHE_SLOTS];

static int
diag_fd_for (int family, int proto)
{
    int fi = DIAG_FAMILY_IDX (family);
    int pi = DIAG_PROTO_IDX (proto);
    if (g_diag_fd[fi][pi] >= 0)
        return g_diag_fd[fi][pi];
    int fd = socket (AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_INET_DIAG);
    if (fd < 0)
        return -1;
    g_diag_fd[fi][pi] = fd;
    return fd;
}

/* Send INET_DIAG_REQ_V2 for the exact 5-tuple, parse the (single)
 * INET_DIAG_MSG reply for inode and uid. Returns 0 on success. */
static int
linux_diag_query (const HevAppFilterFlow *flow, int *out_uid,
                  unsigned long *out_inode)
{
    int family = (flow->family == AF_INET6) ? AF_INET6 : AF_INET;
    int fd = diag_fd_for (family,
                          flow->proto == HEV_APP_FILTER_PROTO_UDP ? IPPROTO_UDP
                                                                  : IPPROTO_TCP);
    if (fd < 0)
        return -1;

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } msg;
    memset (&msg, 0, sizeof (msg));
    msg.nlh.nlmsg_len = sizeof (msg);
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST;
    msg.req.sdiag_family = (uint8_t) family;
    msg.req.sdiag_protocol =
        (flow->proto == HEV_APP_FILTER_PROTO_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
    /* For UDP we also accept LISTEN (=7) since unconnected sockets are
     * common. For TCP, ESTABLISHED is the right state. */
    if (flow->proto == HEV_APP_FILTER_PROTO_UDP)
        msg.req.idiag_states = (1 << 7) | (1 << 1);
    else
        msg.req.idiag_states = 1 << 1; /* TCP_ESTABLISHED */

    /* Convention: flow->local_* is the host-process side. */
    msg.req.id.idiag_sport = htons (flow->local_port);
    msg.req.id.idiag_dport = htons (flow->remote_port);
    if (family == AF_INET) {
        memcpy (msg.req.id.idiag_src, flow->local_addr, 4);
        memcpy (msg.req.id.idiag_dst, flow->remote_addr, 4);
    } else {
        memcpy (msg.req.id.idiag_src, flow->local_addr, 16);
        memcpy (msg.req.id.idiag_dst, flow->remote_addr, 16);
    }

    struct sockaddr_nl kern = { 0 };
    kern.nl_family = AF_NETLINK;
    ssize_t s = sendto (fd, &msg, sizeof (msg), 0,
                        (struct sockaddr *) &kern, sizeof (kern));
    if (s != (ssize_t) sizeof (msg))
        return -1;

    char buf[8192];
    ssize_t got = recv (fd, buf, sizeof (buf), 0);
    if (got <= 0)
        return -1;

    unsigned int len = (unsigned int) got;
    struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
    for (; NLMSG_OK (nlh, len); nlh = NLMSG_NEXT (nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        if (nlh->nlmsg_type == NLMSG_ERROR)
            return -1;
        if (nlh->nlmsg_type != SOCK_DIAG_BY_FAMILY)
            continue;
        struct inet_diag_msg *r = NLMSG_DATA (nlh);
        *out_uid = (int) r->idiag_uid;
        *out_inode = (unsigned long) r->idiag_inode;
        return 0;
    }
    return -1;
}

static uint64_t mono_now_sec (void); /* fwd-decl from cache section */

static UidCacheBucket *
uid_bucket (int uid)
{
    return &g_uid_cache[(unsigned) uid % UID_CACHE_SLOTS];
}

/* Rebuild the inode->path table for `uid` by walking /proc. Filters by
 * st_uid on each pid dir to avoid touching processes we don't care
 * about. Best-effort: missing entries (race with exit, EPERM on other
 * users) are silently skipped. */
static void
build_uid_cache (int uid)
{
    UidCacheBucket *b = uid_bucket (uid);
    b->uid = uid;
    b->n_entries = 0;
    b->expires_mono = mono_now_sec () + UID_CACHE_TTL_SEC;

    DIR *proc = opendir ("/proc");
    if (!proc)
        return;
    struct dirent *de;
    while ((de = readdir (proc)) != NULL) {
        char *end;
        long pid = strtol (de->d_name, &end, 10);
        if (*end != '\0' || pid <= 0)
            continue;

        char path[64];
        snprintf (path, sizeof (path), "/proc/%ld", pid);
        struct stat st;
        if (stat (path, &st) < 0 || (int) st.st_uid != uid)
            continue;

        snprintf (path, sizeof (path), "/proc/%ld/fd", pid);
        DIR *fdd = opendir (path);
        if (!fdd)
            continue;

        char exe_path[1024];
        exe_path[0] = '\0';

        struct dirent *fde;
        while ((fde = readdir (fdd)) != NULL && b->n_entries < UID_CACHE_INODES) {
            if (fde->d_name[0] == '.')
                continue;
            /* /proc/<pid>/fd/<name> — d_name is up to NAME_MAX (255). */
            char fdpath[320];
            char target[64];
            snprintf (fdpath, sizeof (fdpath), "/proc/%ld/fd/%s", pid,
                      fde->d_name);
            ssize_t n = readlink (fdpath, target, sizeof (target) - 1);
            if (n <= 0)
                continue;
            target[n] = '\0';
            if (strncmp (target, "socket:[", 8) != 0)
                continue;
            unsigned long ino = strtoul (target + 8, NULL, 10);
            if (ino == 0)
                continue;

            if (exe_path[0] == '\0') {
                char exelink[64];
                snprintf (exelink, sizeof (exelink), "/proc/%ld/exe", pid);
                ssize_t e = readlink (exelink, exe_path, sizeof (exe_path) - 1);
                if (e > 0)
                    exe_path[e] = '\0';
                else
                    exe_path[0] = '\0';
            }
            if (exe_path[0] == '\0')
                continue;

            UidPathEntry *u = &b->entries[b->n_entries++];
            u->inode = ino;
            snprintf (u->path, sizeof (u->path), "%s", exe_path);
        }
        closedir (fdd);
    }
    closedir (proc);
}

static const char *
uid_cache_lookup (int uid, unsigned long inode)
{
    UidCacheBucket *b = uid_bucket (uid);
    if (b->uid != uid || b->expires_mono <= mono_now_sec ())
        build_uid_cache (uid);
    if (b->uid != uid)
        return NULL;
    for (int i = 0; i < b->n_entries; i++) {
        if (b->entries[i].inode == inode)
            return b->entries[i].path;
    }
    return NULL;
}

static int
lookup_linux (const HevAppFilterFlow *flow, HevAppFilterLookupResult *out)
{
    int uid = -1;
    unsigned long inode = 0;
    if (linux_diag_query (flow, &uid, &inode) < 0)
        return -1;

    out->uid = uid;
    /* We don't get a pid back from sock_diag — the kernel doesn't track
     * it on the socket. PID lookup would need the /proc scan to remember
     * which pid owned the inode, which is more state. For now, leave
     * pid=-1; matching by `uids` and `apps` (path) still works. */
    out->pid = -1;

    const char *path = uid_cache_lookup (uid, inode);
    if (path)
        snprintf (out->path, sizeof (out->path), "%s", path);
    return 0;
}

#endif /* HAVE_LINUX_LOOKUP */

int
hev_app_filter_lookup (const HevAppFilterFlow *flow,
                       HevAppFilterLookupResult *out)
{
    if (!flow || !out)
        return -1;

    out->pid = -1;
    out->uid = -1;
    out->path[0] = '\0';

    if (g_override)
        return g_override (flow, out);

#if HAVE_MACOS_LOOKUP
    return lookup_macos (flow, out);
#elif defined(_WIN32) || defined(__MSYS__)
    return lookup_windows (flow, out);
#elif HAVE_LINUX_LOOKUP
    return lookup_linux (flow, out);
#else
    /* iOS / Android: in-process lookup is intentionally unsupported;
     * the host VPN extension does filtering. Returning -1 makes callers
     * see lookup-failed and treat the flow as unmatched. */
    (void) flow;
    return -1;
#endif
}
