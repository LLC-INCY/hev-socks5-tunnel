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

#define CACHE_SLOTS    64
#define CACHE_TTL_SEC  60

#if HAVE_MACOS_LOOKUP || defined(_WIN32) || defined(__MSYS__)
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

#endif /* HAVE_INPROC_LOOKUP */

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
#else
    /* Linux / iOS / Android: in-process lookup is intentionally
     * unsupported. On Linux, cgroup-v2 + nft handles enforcement out of
     * band; on mobile platforms, app-filter is configured no-op (the
     * host VPN extension does the filtering). Returning -1 makes
     * callers see lookup-failed and treat the flow as unmatched. */
    (void) flow;
    return -1;
#endif
}
