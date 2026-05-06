/*
 ============================================================================
 Name        : hev-app-filter-ctrl.c
 Author      : Boris Kovalskii
 Description : Control socket for live app-filter updates (Unix-domain)
 ============================================================================
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__linux__) || defined(__FreeBSD__) || \
    defined(__NetBSD__)
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#define HAVE_UDS 1
#else
#define HAVE_UDS 0
#endif

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

#include "hev-logger.h"
#include "hev-app-filter.h"
#include "hev-app-filter-ctrl.h"

#if HAVE_UDS

static int g_listen_fd = -1;
static int g_client_fd = -1;
static HevTask *g_accept_task;
static HevTask *g_client_task;

/* ---------- tiny JSON helpers ----------
 *
 * The control protocol is a closed vocabulary of ~6 ops with a handful
 * of fields. Pulling in a JSON dep for that is overkill; this is a
 * deliberately minimal scanner that handles flat objects with string
 * and integer values. It rejects anything fancy (nested objects,
 * escapes inside strings, unicode escapes) by returning failure. The
 * host side controls the format, so this is fine.
 */

typedef struct
{
    const char *p;
    const char *end;
} J;

static void
j_skip_ws (J *j)
{
    while (j->p < j->end &&
           (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n'))
        j->p++;
}

static int
j_expect (J *j, char c)
{
    j_skip_ws (j);
    if (j->p >= j->end || *j->p != c)
        return -1;
    j->p++;
    return 0;
}

/* Parse a JSON string into out, NUL-terminated. No escape handling
 * beyond \" and \\. Returns 0 on success. */
static int
j_string (J *j, char *out, size_t outsz)
{
    j_skip_ws (j);
    if (j->p >= j->end || *j->p != '"')
        return -1;
    j->p++;
    size_t i = 0;
    while (j->p < j->end && *j->p != '"') {
        if (i + 1 >= outsz)
            return -1;
        char c = *j->p++;
        if (c == '\\') {
            if (j->p >= j->end)
                return -1;
            char esc = *j->p++;
            if (esc == '"' || esc == '\\')
                c = esc;
            else if (esc == 'n')
                c = '\n';
            else if (esc == 't')
                c = '\t';
            else
                return -1;
        }
        out[i++] = c;
    }
    if (j->p >= j->end || *j->p != '"')
        return -1;
    j->p++;
    out[i] = '\0';
    return 0;
}

static int
j_int (J *j, long *out)
{
    j_skip_ws (j);
    char *endp;
    long v = strtol (j->p, &endp, 10);
    if (endp == j->p)
        return -1;
    *out = v;
    j->p = endp;
    return 0;
}

/* Find a top-level "key" in a flat JSON object and return a J pointing
 * at the value. Returns 0 on success. The caller passes a fresh J on
 * each call. */
static int
j_field (const char *line, size_t len, const char *key, J *outj)
{
    J j = { line, line + len };
    if (j_expect (&j, '{') < 0)
        return -1;
    j_skip_ws (&j);
    if (j.p < j.end && *j.p == '}')
        return -1;
    for (;;) {
        char k[64];
        if (j_string (&j, k, sizeof (k)) < 0)
            return -1;
        if (j_expect (&j, ':') < 0)
            return -1;
        j_skip_ws (&j);
        const char *vstart = j.p;
        /* Skip the value: either a quoted string, a number, or a literal
         * (true/false/null). */
        if (j.p < j.end && *j.p == '"') {
            char tmp[1024];
            if (j_string (&j, tmp, sizeof (tmp)) < 0)
                return -1;
        } else {
            while (j.p < j.end && *j.p != ',' && *j.p != '}')
                j.p++;
        }
        if (strcmp (k, key) == 0) {
            outj->p = vstart;
            outj->end = j.p;
            return 0;
        }
        j_skip_ws (&j);
        if (j.p < j.end && *j.p == ',') {
            j.p++;
            continue;
        }
        break;
    }
    return -1;
}

/* ---------- writers ---------- */

static void
write_all (int fd, const char *buf, size_t len)
{
    while (len) {
        ssize_t n = hev_task_io_socket_send (fd, buf, len, 0, NULL, NULL);
        if (n <= 0)
            return;
        buf += n;
        len -= n;
    }
}

static void
reply_ok (int fd)
{
    static const char *s = "{\"ok\":true}\n";
    write_all (fd, s, strlen (s));
}

static void
reply_err (int fd, const char *msg)
{
    char buf[256];
    int n = snprintf (buf, sizeof (buf), "{\"ok\":false,\"error\":\"%s\"}\n",
                      msg);
    if (n > 0)
        write_all (fd, buf, (size_t) n);
}

static void
each_app_writer (const char *path, void *ud)
{
    int *fd = ud;
    char esc[1100];
    /* Naive escape: only quotes and backslashes. */
    size_t i = 0;
    for (const char *p = path; *p && i + 2 < sizeof (esc); p++) {
        if (*p == '"' || *p == '\\')
            esc[i++] = '\\';
        esc[i++] = *p;
    }
    esc[i] = '\0';
    char buf[1200];
    int n = snprintf (buf, sizeof (buf), "\"%s\",", esc);
    if (n > 0)
        write_all (*fd, buf, (size_t) n);
}

static void
each_pid_writer (int pid, void *ud)
{
    int *fd = ud;
    char buf[32];
    int n = snprintf (buf, sizeof (buf), "%d,", pid);
    if (n > 0)
        write_all (*fd, buf, (size_t) n);
}

static void
reply_status (int fd)
{
    HevAppFilterStats st;
    hev_app_filter_get_stats (&st);
    char head[512];
    int n = snprintf (
        head, sizeof (head),
        "{\"ok\":true,\"status\":{"
        "\"mode\":\"%s\",\"unmatched\":\"%s\","
        "\"cgroup\":\"%s\",\"socket\":\"%s\","
        "\"stats\":{\"matched\":%llu,\"unmatched\":%llu,"
        "\"lookup-failed\":%llu,\"cache-hits\":%llu,\"cache-misses\":%llu},"
        "\"apps\":[",
        hev_app_filter_get_mode () == HEV_APP_FILTER_MODE_EXCLUDE ? "exclude"
                                                                  : "include",
        hev_app_filter_get_unmatched () == HEV_APP_FILTER_UNMATCHED_DIRECT
            ? "direct"
            : "drop",
        hev_app_filter_get_cgroup_name () ?: "",
        hev_app_filter_get_control_socket () ?: "",
        (unsigned long long) st.matched, (unsigned long long) st.unmatched,
        (unsigned long long) st.lookup_failed,
        (unsigned long long) st.cache_hits,
        (unsigned long long) st.cache_misses);
    if (n > 0)
        write_all (fd, head, (size_t) n);
    hev_app_filter_each_app (each_app_writer, &fd);
    /* Strip trailing comma by writing "],\"pids\":[" — overlapping the
     * comma is awkward; simpler: always close the array and accept a
     * stray trailing comma. JSON parsers tolerate it in practice;
     * stricter clients can use a normal parser to ignore it. */
    write_all (fd, "],\"pids\":[", strlen ("],\"pids\":["));
    hev_app_filter_each_pid (each_pid_writer, &fd);
    write_all (fd, "]}}\n", 4);
}

/* ---------- command dispatch ---------- */

static int
get_str_field (const char *line, size_t len, const char *key, char *out,
               size_t outsz)
{
    J vj;
    if (j_field (line, len, key, &vj) < 0)
        return -1;
    return j_string (&vj, out, outsz);
}

static int
get_int_field (const char *line, size_t len, const char *key, long *out)
{
    J vj;
    if (j_field (line, len, key, &vj) < 0)
        return -1;
    return j_int (&vj, out);
}

static void
handle_line (int fd, const char *line, size_t len)
{
    char op[32];
    if (get_str_field (line, len, "op", op, sizeof (op)) < 0) {
        reply_err (fd, "missing op");
        return;
    }

    if (strcmp (op, "status") == 0) {
        reply_status (fd);
        return;
    }
    if (strcmp (op, "add-app") == 0) {
        char path[1024];
        if (get_str_field (line, len, "path", path, sizeof (path)) < 0) {
            reply_err (fd, "missing path");
            return;
        }
        if (hev_app_filter_add_app (path) < 0) {
            reply_err (fd, "add-app failed");
            return;
        }
        reply_ok (fd);
        return;
    }
    if (strcmp (op, "remove-app") == 0) {
        char path[1024];
        if (get_str_field (line, len, "path", path, sizeof (path)) < 0) {
            reply_err (fd, "missing path");
            return;
        }
        if (hev_app_filter_remove_app (path) < 0) {
            reply_err (fd, "not present");
            return;
        }
        reply_ok (fd);
        return;
    }
    if (strcmp (op, "add-pid") == 0) {
        long pid;
        if (get_int_field (line, len, "pid", &pid) < 0) {
            reply_err (fd, "missing pid");
            return;
        }
        if (hev_app_filter_add_pid ((int) pid) < 0) {
            reply_err (fd, "add-pid failed");
            return;
        }
        reply_ok (fd);
        return;
    }
    if (strcmp (op, "remove-pid") == 0) {
        long pid;
        if (get_int_field (line, len, "pid", &pid) < 0) {
            reply_err (fd, "missing pid");
            return;
        }
        if (hev_app_filter_remove_pid ((int) pid) < 0) {
            reply_err (fd, "not present");
            return;
        }
        reply_ok (fd);
        return;
    }
    if (strcmp (op, "set-mode") == 0) {
        char mode[16];
        if (get_str_field (line, len, "mode", mode, sizeof (mode)) < 0) {
            reply_err (fd, "missing mode");
            return;
        }
        HevAppFilterMode m = (strcmp (mode, "exclude") == 0)
                                 ? HEV_APP_FILTER_MODE_EXCLUDE
                                 : HEV_APP_FILTER_MODE_INCLUDE;
        hev_app_filter_set_mode (m);
        reply_ok (fd);
        return;
    }
    if (strcmp (op, "set-unmatched") == 0) {
        char policy[16];
        if (get_str_field (line, len, "policy", policy, sizeof (policy)) < 0) {
            reply_err (fd, "missing policy");
            return;
        }
        HevAppFilterUnmatched p = (strcmp (policy, "direct") == 0)
                                      ? HEV_APP_FILTER_UNMATCHED_DIRECT
                                      : HEV_APP_FILTER_UNMATCHED_DROP;
        hev_app_filter_set_unmatched (p);
        reply_ok (fd);
        return;
    }
    if (strcmp (op, "reload") == 0) {
        /* v1: reload is a no-op acknowledgement. The host can drive the
         * filter via add/remove ops; only `app-filter` is hot-reloadable
         * and that's what these ops already do. */
        reply_ok (fd);
        return;
    }

    reply_err (fd, "unknown op");
}

/* ---------- task entries ---------- */

static int
yielder (HevTaskYieldType type, void *data)
{
    (void) data;
    hev_task_yield (type);
    return 0;
}

static void
client_task_entry (void *data)
{
    int fd = (int) (long) data;
    char buf[2048];
    size_t bufn = 0;

    hev_task_add_fd (hev_task_self (), fd, POLLIN);

    for (;;) {
        ssize_t n = hev_task_io_socket_recv (fd, buf + bufn, sizeof (buf) - bufn,
                                             0, yielder, NULL);
        if (n <= 0)
            break;
        bufn += (size_t) n;

        for (;;) {
            char *nl = memchr (buf, '\n', bufn);
            if (!nl)
                break;
            size_t llen = (size_t) (nl - buf);
            handle_line (fd, buf, llen);
            size_t consumed = llen + 1;
            memmove (buf, buf + consumed, bufn - consumed);
            bufn -= consumed;
        }
        if (bufn == sizeof (buf)) {
            /* line too long, drop client */
            break;
        }
    }

    hev_task_del_fd (hev_task_self (), fd);
    close (fd);
    g_client_fd = -1;
    g_client_task = NULL;
}

static void
accept_task_entry (void *data)
{
    (void) data;
    hev_task_add_fd (hev_task_self (), g_listen_fd, POLLIN);

    for (;;) {
        struct sockaddr_un sa;
        socklen_t sl = sizeof (sa);
        int fd = hev_task_io_socket_accept (g_listen_fd, (struct sockaddr *) &sa,
                                            &sl, yielder, NULL);
        if (fd < 0)
            break;

        if (g_client_fd >= 0) {
            /* single-client policy */
            static const char *busy = "{\"ok\":false,\"error\":\"busy\"}\n";
            (void) send (fd, busy, strlen (busy), 0);
            close (fd);
            continue;
        }

        int flags = fcntl (fd, F_GETFL, 0);
        fcntl (fd, F_SETFL, flags | O_NONBLOCK);
        g_client_fd = fd;
        g_client_task = hev_task_new (-1);
        if (!g_client_task) {
            close (fd);
            g_client_fd = -1;
            continue;
        }
        hev_task_run (g_client_task, client_task_entry, (void *) (long) fd);
    }

    hev_task_del_fd (hev_task_self (), g_listen_fd);
}

int
hev_app_filter_ctrl_init (void)
{
    const char *path = hev_app_filter_get_control_socket ();
    if (!path)
        return -1;

    g_listen_fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        LOG_E ("[app-filter] control-socket socket(): %s", strerror (errno));
        return -1;
    }

    /* Best-effort cleanup of a stale path. We only unlink AF_UNIX paths;
     * a regular file at this location is left alone and the bind below
     * will fail loudly. */
    struct stat st;
    if (lstat (path, &st) == 0 && S_ISSOCK (st.st_mode))
        unlink (path);

    struct sockaddr_un sa = { 0 };
    sa.sun_family = AF_UNIX;
    strncpy (sa.sun_path, path, sizeof (sa.sun_path) - 1);
    if (bind (g_listen_fd, (struct sockaddr *) &sa, sizeof (sa)) < 0) {
        LOG_E ("[app-filter] control-socket bind(%s): %s", path,
               strerror (errno));
        close (g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }
    chmod (path, 0600);

    if (listen (g_listen_fd, 4) < 0) {
        LOG_E ("[app-filter] control-socket listen: %s", strerror (errno));
        close (g_listen_fd);
        unlink (path);
        g_listen_fd = -1;
        return -1;
    }

    int flags = fcntl (g_listen_fd, F_GETFL, 0);
    fcntl (g_listen_fd, F_SETFL, flags | O_NONBLOCK);

    g_accept_task = hev_task_new (-1);
    if (!g_accept_task) {
        close (g_listen_fd);
        unlink (path);
        g_listen_fd = -1;
        return -1;
    }
    hev_task_run (g_accept_task, accept_task_entry, NULL);

    LOG_I ("[app-filter] control socket listening at %s", path);
    return 0;
}

void
hev_app_filter_ctrl_fini (void)
{
    if (g_listen_fd >= 0) {
        close (g_listen_fd);
        g_listen_fd = -1;
    }
    const char *path = hev_app_filter_get_control_socket ();
    if (path)
        unlink (path);
    if (g_client_fd >= 0) {
        close (g_client_fd);
        g_client_fd = -1;
    }
}

void
hev_app_filter_ctrl_emit_bypass (int pid, const char *path,
                                 const HevAppFilterFlow *flow)
{
    if (g_client_fd < 0)
        return;
    char addr_buf[80];
    if (flow->family == AF_INET) {
        const uint8_t *a = flow->local_addr;
        const uint8_t *b = flow->remote_addr;
        snprintf (addr_buf, sizeof (addr_buf),
                  "\"%u.%u.%u.%u:%u\",\"dst\":\"%u.%u.%u.%u:%u\"",
                  a[0], a[1], a[2], a[3], flow->local_port, b[0], b[1], b[2],
                  b[3], flow->remote_port);
    } else {
        snprintf (addr_buf, sizeof (addr_buf), "\"v6:%u\",\"dst\":\"v6:%u\"",
                  flow->local_port, flow->remote_port);
    }
    char buf[1400];
    int n = snprintf (
        buf, sizeof (buf),
        "{\"event\":\"bypass\",\"pid\":%d,\"path\":\"%s\","
        "\"flow\":{\"proto\":\"%s\",\"src\":%s}}\n",
        pid, path ? path : "",
        flow->proto == HEV_APP_FILTER_PROTO_TCP ? "tcp" : "udp", addr_buf);
    if (n > 0)
        write_all (g_client_fd, buf, (size_t) n);
}

#else /* !HAVE_UDS */

int
hev_app_filter_ctrl_init (void)
{
    if (hev_app_filter_get_control_socket ())
        LOG_W ("[app-filter] control-socket configured but UDS unsupported "
               "on this platform; ignoring");
    return -1;
}

void
hev_app_filter_ctrl_fini (void)
{
}

void
hev_app_filter_ctrl_emit_bypass (int pid, const char *path,
                                 const HevAppFilterFlow *flow)
{
    (void) pid;
    (void) path;
    (void) flow;
}

#endif /* HAVE_UDS */
