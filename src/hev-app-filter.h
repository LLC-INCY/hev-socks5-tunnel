/*
 ============================================================================
 Name        : hev-app-filter.h
 Author      : Boris Kovalskii
 Description : Per-application routing rules and decision engine
 ============================================================================
 */

#ifndef __HEV_APP_FILTER_H__
#define __HEV_APP_FILTER_H__

#include <stdint.h>
#include <yaml.h>

#include "hev-app-filter-lookup.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    HEV_APP_FILTER_MODE_INCLUDE = 0,
    HEV_APP_FILTER_MODE_EXCLUDE = 1,
} HevAppFilterMode;

typedef enum
{
    HEV_APP_FILTER_UNMATCHED_DROP = 0,
    HEV_APP_FILTER_UNMATCHED_DIRECT = 1,
} HevAppFilterUnmatched;

typedef enum
{
    /* Bridge into SOCKS5 (the existing default behaviour). */
    HEV_APP_FILTER_DECISION_BRIDGE = 0,
    /* Drop the flow at the lwIP boundary. */
    HEV_APP_FILTER_DECISION_DROP = 1,
    /* Caller must arrange host-side bypass (control socket / nft / WFP). */
    HEV_APP_FILTER_DECISION_BYPASS = 2,
} HevAppFilterDecision;

/*
 * Parse the `app-filter:` mapping node. Returns 0 on success, -1 on
 * malformed config. Safe to call before init.
 */
int hev_app_filter_parse (yaml_document_t *doc, yaml_node_t *base);

/* Returns 1 if `app-filter:` was present in config, 0 otherwise. */
int hev_app_filter_enabled (void);

/* Build a flow descriptor. The ip arguments are pointers to lwIP's
 * ip_addr_t (typed as void* so this header doesn't depend on lwIP).
 * src_* is the host-process side; dst_* is the remote endpoint the app
 * is talking to. */
void hev_app_filter_flow_from_lwip (HevAppFilterFlow *out, int proto,
                                    const void *src_ip, uint16_t src_port,
                                    const void *dst_ip, uint16_t dst_port);

/* Mode / unmatched policy / cgroup name accessors. */
HevAppFilterMode hev_app_filter_get_mode (void);
HevAppFilterUnmatched hev_app_filter_get_unmatched (void);
const char *hev_app_filter_get_cgroup_name (void);
const char *hev_app_filter_get_control_socket (void);

/*
 * Decide what to do with a new flow. `flow` carries the 5-tuple. On
 * platforms with in-process lookup (macOS, Windows) this calls into
 * hev_app_filter_lookup; on Linux it returns BRIDGE because cgroup-v2
 * + nft handle enforcement out of band.
 *
 * When the result is BYPASS, *out_pid and *out_path are populated so
 * the caller can emit a control-socket event. Both pointers may be NULL.
 */
HevAppFilterDecision
hev_app_filter_decide (const HevAppFilterFlow *flow, int *out_pid,
                       const char **out_path);

/* Counters surfaced via the control socket's status op. */
typedef struct
{
    uint64_t matched;
    uint64_t unmatched;
    uint64_t lookup_failed;
    uint64_t cache_hits;
    uint64_t cache_misses;
} HevAppFilterStats;

void hev_app_filter_get_stats (HevAppFilterStats *out);

/* Live-update API used by the control socket. */
int hev_app_filter_add_app (const char *path);
int hev_app_filter_remove_app (const char *path);
int hev_app_filter_add_pid (int pid);
int hev_app_filter_remove_pid (int pid);
int hev_app_filter_set_mode (HevAppFilterMode mode);
int hev_app_filter_set_unmatched (HevAppFilterUnmatched policy);

/*
 * Iterate the current rule set. The callback receives borrowed pointers;
 * do not retain them past the call.
 */
typedef void (*HevAppFilterAppIter) (const char *path, void *ud);
typedef void (*HevAppFilterPidIter) (int pid, void *ud);

void hev_app_filter_each_app (HevAppFilterAppIter cb, void *ud);
void hev_app_filter_each_pid (HevAppFilterPidIter cb, void *ud);

void hev_app_filter_fini (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_APP_FILTER_H__ */
