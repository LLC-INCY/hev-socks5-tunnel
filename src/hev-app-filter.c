/*
 ============================================================================
 Name        : hev-app-filter.c
 Author      : Boris Kovalskii
 Description : Per-application routing rules and decision engine
 ============================================================================
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <lwip/ip_addr.h>

#include "hev-logger.h"
#include "hev-app-filter.h"

#define MAX_APPS  256
#define MAX_PIDS  256
#define MAX_UIDS  16

static int g_enabled;
static HevAppFilterMode g_mode = HEV_APP_FILTER_MODE_INCLUDE;
static HevAppFilterUnmatched g_unmatched = HEV_APP_FILTER_UNMATCHED_DROP;

static char g_cgroup_name[128];
static char g_control_socket[256];

static char *g_apps[MAX_APPS];
static int g_apps_n;
static int g_pids[MAX_PIDS];
static int g_pids_n;
static int g_uids[MAX_UIDS];
static int g_uids_n;

static HevAppFilterStats g_stats;

/* In-process lookup is gated identically to hev-app-filter-lookup.c.
 * Keep these in sync. */
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#if (defined(__APPLE__) && defined(TARGET_OS_OSX) && TARGET_OS_OSX) || \
    defined(_WIN32) || defined(__MSYS__)
#define HAVE_INPROC_LOOKUP 1
#else
#define HAVE_INPROC_LOOKUP 0
#endif

/* ---------- helpers ---------- */

static int
str_eq_path (const char *a, const char *b)
{
#if defined(_WIN32) || defined(__MSYS__)
    return strcasecmp (a, b) == 0;
#else
    return strcmp (a, b) == 0;
#endif
}

static int
apps_contains (const char *path)
{
    for (int i = 0; i < g_apps_n; i++)
        if (str_eq_path (g_apps[i], path))
            return 1;
    return 0;
}

static int
pids_contains (int pid)
{
    for (int i = 0; i < g_pids_n; i++)
        if (g_pids[i] == pid)
            return 1;
    return 0;
}

#if HAVE_INPROC_LOOKUP
static int
uids_contains (int uid)
{
    for (int i = 0; i < g_uids_n; i++)
        if (g_uids[i] == uid)
            return 1;
    return 0;
}
#endif

/* ---------- yaml parsing ---------- */

static int
parse_apps_seq (yaml_document_t *doc, yaml_node_t *seq)
{
    if (!seq || seq->type != YAML_SEQUENCE_NODE)
        return -1;
    for (yaml_node_item_t *it = seq->data.sequence.items.start;
         it < seq->data.sequence.items.top; it++) {
        yaml_node_t *n = yaml_document_get_node (doc, *it);
        if (!n || n->type != YAML_SCALAR_NODE)
            continue;
        const char *value = (const char *) n->data.scalar.value;
        if (!value || !*value)
            continue;
        if (g_apps_n >= MAX_APPS) {
            LOG_W ("[app-filter] apps list truncated at %d", MAX_APPS);
            break;
        }
        g_apps[g_apps_n++] = strdup (value);
    }
    return 0;
}

static int
parse_int_seq (yaml_document_t *doc, yaml_node_t *seq, int *out, int *n,
               int max)
{
    if (!seq || seq->type != YAML_SEQUENCE_NODE)
        return -1;
    for (yaml_node_item_t *it = seq->data.sequence.items.start;
         it < seq->data.sequence.items.top; it++) {
        yaml_node_t *node = yaml_document_get_node (doc, *it);
        if (!node || node->type != YAML_SCALAR_NODE)
            continue;
        if (*n >= max)
            break;
        out[(*n)++] = (int) strtol ((const char *) node->data.scalar.value,
                                    NULL, 10);
    }
    return 0;
}

int
hev_app_filter_parse (yaml_document_t *doc, yaml_node_t *base)
{
    if (!base || base->type != YAML_MAPPING_NODE)
        return -1;

    g_enabled = 1;

    for (yaml_node_pair_t *pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *kn = yaml_document_get_node (doc, pair->key);
        yaml_node_t *vn = yaml_document_get_node (doc, pair->value);
        if (!kn || !vn || kn->type != YAML_SCALAR_NODE)
            continue;
        const char *key = (const char *) kn->data.scalar.value;

        if (vn->type == YAML_SCALAR_NODE) {
            const char *v = (const char *) vn->data.scalar.value;
            if (strcmp (key, "mode") == 0) {
                if (strcmp (v, "exclude") == 0)
                    g_mode = HEV_APP_FILTER_MODE_EXCLUDE;
                else
                    g_mode = HEV_APP_FILTER_MODE_INCLUDE;
            } else if (strcmp (key, "unmatched") == 0) {
                if (strcmp (v, "direct") == 0)
                    g_unmatched = HEV_APP_FILTER_UNMATCHED_DIRECT;
                else
                    g_unmatched = HEV_APP_FILTER_UNMATCHED_DROP;
            } else if (strcmp (key, "cgroup-name") == 0) {
                strncpy (g_cgroup_name, v, sizeof (g_cgroup_name) - 1);
            } else if (strcmp (key, "control-socket") == 0) {
                strncpy (g_control_socket, v, sizeof (g_control_socket) - 1);
            }
        } else if (vn->type == YAML_SEQUENCE_NODE) {
            if (strcmp (key, "apps") == 0)
                parse_apps_seq (doc, vn);
            else if (strcmp (key, "pids") == 0)
                parse_int_seq (doc, vn, g_pids, &g_pids_n, MAX_PIDS);
            else if (strcmp (key, "uids") == 0)
                parse_int_seq (doc, vn, g_uids, &g_uids_n, MAX_UIDS);
        }
    }

    LOG_I ("[app-filter] enabled mode=%s unmatched=%s apps=%d pids=%d "
           "uids=%d cgroup=%s socket=%s",
           g_mode == HEV_APP_FILTER_MODE_EXCLUDE ? "exclude" : "include",
           g_unmatched == HEV_APP_FILTER_UNMATCHED_DIRECT ? "direct" : "drop",
           g_apps_n, g_pids_n, g_uids_n,
           g_cgroup_name[0] ? g_cgroup_name : "(none)",
           g_control_socket[0] ? g_control_socket : "(none)");

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(__MSYS__)
    if (g_apps_n > 0 && g_cgroup_name[0] == 0) {
        LOG_W ("[app-filter] apps list set on Linux without cgroup-name; "
               "host app must install nft cgroupv2 rules — hev does no "
               "in-process lookup on Linux.");
    }
#endif
    return 0;
}

int
hev_app_filter_enabled (void)
{
    return g_enabled;
}

void
hev_app_filter_flow_from_lwip (HevAppFilterFlow *out, int proto,
                               const void *src_ip_v, uint16_t src_port,
                               const void *dst_ip_v, uint16_t dst_port)
{
    const ip_addr_t *src = src_ip_v;
    const ip_addr_t *dst = dst_ip_v;

    memset (out, 0, sizeof (*out));
    out->proto = (proto == IPPROTO_UDP) ? HEV_APP_FILTER_PROTO_UDP
                                        : HEV_APP_FILTER_PROTO_TCP;

    if (IP_IS_V6 (src) || IP_IS_V6 (dst)) {
        out->family = AF_INET6;
        memcpy (out->local_addr, ip_2_ip6 (src)->addr, 16);
        memcpy (out->remote_addr, ip_2_ip6 (dst)->addr, 16);
    } else {
        out->family = AF_INET;
        uint32_t s = ip_2_ip4 (src)->addr;
        uint32_t d = ip_2_ip4 (dst)->addr;
        memcpy (out->local_addr, &s, 4);
        memcpy (out->remote_addr, &d, 4);
    }
    out->local_port = src_port;
    out->remote_port = dst_port;
}

HevAppFilterMode
hev_app_filter_get_mode (void)
{
    return g_mode;
}

HevAppFilterUnmatched
hev_app_filter_get_unmatched (void)
{
    return g_unmatched;
}

const char *
hev_app_filter_get_cgroup_name (void)
{
    return g_cgroup_name[0] ? g_cgroup_name : NULL;
}

const char *
hev_app_filter_get_control_socket (void)
{
    return g_control_socket[0] ? g_control_socket : NULL;
}

/* ---------- decision ---------- */

HevAppFilterDecision
hev_app_filter_decide (const HevAppFilterFlow *flow, int *out_pid,
                       const char **out_path)
{
    if (out_pid)
        *out_pid = -1;
    if (out_path)
        *out_path = NULL;

    if (!g_enabled)
        return HEV_APP_FILTER_DECISION_BRIDGE;

#if HAVE_INPROC_LOOKUP
    HevAppFilterLookupResult r;
    int matched = 0;

    int rc = hev_app_filter_lookup (flow, &r);
    if (rc < 0) {
        g_stats.lookup_failed++;
        /* Treat lookup-failed as unmatched. */
        if (g_mode == HEV_APP_FILTER_MODE_INCLUDE) {
            g_stats.unmatched++;
            return (g_unmatched == HEV_APP_FILTER_UNMATCHED_DROP)
                       ? HEV_APP_FILTER_DECISION_DROP
                       : HEV_APP_FILTER_DECISION_BRIDGE;
        }
        /* exclude mode: lookup failed, default safe is to bridge. */
        g_stats.unmatched++;
        return HEV_APP_FILTER_DECISION_BRIDGE;
    }

    if (r.pid >= 0 && pids_contains (r.pid))
        matched = 1;
    else if (r.uid >= 0 && uids_contains (r.uid))
        matched = 1;
    else if (r.path[0] && apps_contains (r.path))
        matched = 1;

    if (out_pid)
        *out_pid = r.pid;
    if (out_path && r.path[0]) {
        /*
         * The lookup result is on the caller's stack. We can't return a
         * pointer into it; for the control-socket bypass event the caller
         * needs a stable string. We strdup once per BYPASS event below.
         */
        *out_path = NULL;
    }

    if (g_mode == HEV_APP_FILTER_MODE_INCLUDE) {
        if (matched) {
            g_stats.matched++;
            return HEV_APP_FILTER_DECISION_BRIDGE;
        }
        g_stats.unmatched++;
        return (g_unmatched == HEV_APP_FILTER_UNMATCHED_DROP)
                   ? HEV_APP_FILTER_DECISION_DROP
                   : HEV_APP_FILTER_DECISION_BRIDGE;
    } else {
        /* exclude mode: matched = bypass, otherwise bridge. */
        if (matched) {
            g_stats.matched++;
            return HEV_APP_FILTER_DECISION_BYPASS;
        }
        g_stats.unmatched++;
        return HEV_APP_FILTER_DECISION_BRIDGE;
    }
#else
    /* Linux: no in-process lookup; everything bridges. The cgroup-v2 +
     * nft path on the host kernel decides what reaches our TUN. */
    (void) flow;
    return HEV_APP_FILTER_DECISION_BRIDGE;
#endif
}

void
hev_app_filter_get_stats (HevAppFilterStats *out)
{
    if (out)
        *out = g_stats;
}

/* ---------- live updates ---------- */

int
hev_app_filter_add_app (const char *path)
{
    if (!path || !*path)
        return -1;
    if (apps_contains (path))
        return 0;
    if (g_apps_n >= MAX_APPS)
        return -1;
    g_apps[g_apps_n++] = strdup (path);
    return 0;
}

int
hev_app_filter_remove_app (const char *path)
{
    for (int i = 0; i < g_apps_n; i++) {
        if (str_eq_path (g_apps[i], path)) {
            free (g_apps[i]);
            g_apps[i] = g_apps[--g_apps_n];
            return 0;
        }
    }
    return -1;
}

int
hev_app_filter_add_pid (int pid)
{
    if (pids_contains (pid))
        return 0;
    if (g_pids_n >= MAX_PIDS)
        return -1;
    g_pids[g_pids_n++] = pid;
    return 0;
}

int
hev_app_filter_remove_pid (int pid)
{
    for (int i = 0; i < g_pids_n; i++) {
        if (g_pids[i] == pid) {
            g_pids[i] = g_pids[--g_pids_n];
            return 0;
        }
    }
    return -1;
}

int
hev_app_filter_set_mode (HevAppFilterMode mode)
{
    g_mode = mode;
    return 0;
}

int
hev_app_filter_set_unmatched (HevAppFilterUnmatched policy)
{
    g_unmatched = policy;
    return 0;
}

void
hev_app_filter_each_app (HevAppFilterAppIter cb, void *ud)
{
    for (int i = 0; i < g_apps_n; i++)
        cb (g_apps[i], ud);
}

void
hev_app_filter_each_pid (HevAppFilterPidIter cb, void *ud)
{
    for (int i = 0; i < g_pids_n; i++)
        cb (g_pids[i], ud);
}

void
hev_app_filter_fini (void)
{
    for (int i = 0; i < g_apps_n; i++)
        free (g_apps[i]);
    g_apps_n = 0;
    g_pids_n = 0;
    g_uids_n = 0;
    g_enabled = 0;
    g_cgroup_name[0] = '\0';
    g_control_socket[0] = '\0';
    memset (&g_stats, 0, sizeof (g_stats));
}
