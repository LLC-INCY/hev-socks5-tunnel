/*
 ============================================================================
 Name        : hev-app-filter-lookup.h
 Author      : Boris Kovalskii
 Description : Per-OS PID/exe lookup for app-filter
 ============================================================================
 */

#ifndef __HEV_APP_FILTER_LOOKUP_H__
#define __HEV_APP_FILTER_LOOKUP_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    HEV_APP_FILTER_PROTO_TCP = 6,
    HEV_APP_FILTER_PROTO_UDP = 17,
} HevAppFilterProto;

typedef struct _HevAppFilterFlow HevAppFilterFlow;

struct _HevAppFilterFlow
{
    HevAppFilterProto proto;
    /* Local = host process side. v4-mapped if family is v4. */
    uint8_t  local_addr[16];
    uint8_t  remote_addr[16];
    uint16_t local_port;
    uint16_t remote_port;
    /* Address family: AF_INET or AF_INET6. */
    int      family;
};

typedef struct _HevAppFilterLookupResult HevAppFilterLookupResult;

struct _HevAppFilterLookupResult
{
    int  pid;          /* -1 on failure */
    int  uid;          /* -1 if unknown */
    char path[1024];   /* empty string on failure */
};

/*
 * Resolve the host process that owns `flow`. On failure, sets pid=-1 and
 * leaves path empty; never crashes regardless of the flow contents.
 *
 * Returns 0 on success, -1 on lookup failure (e.g. no socket matched, or
 * the owner is in another security domain).
 *
 * Uses a process-internal pid->path cache with a TTL chosen by the
 * implementation (currently 60s). Thread-unsafe: callers in this codebase
 * run on hev-task cooperative scheduling on a single OS thread.
 */
int hev_app_filter_lookup (const HevAppFilterFlow *flow,
                           HevAppFilterLookupResult *out);

/* Drop the pid->path cache. Call on app-filter reload. */
void hev_app_filter_lookup_cache_clear (void);

/*
 * Test seam. When `fn` is non-NULL it is called instead of the OS-specific
 * resolver; pass NULL to restore the real implementation. Used by the
 * lookup-failure unit test to inject deterministic results.
 */
typedef int (*HevAppFilterLookupFn) (const HevAppFilterFlow *flow,
                                     HevAppFilterLookupResult *out);

void hev_app_filter_lookup_set_override (HevAppFilterLookupFn fn);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_APP_FILTER_LOOKUP_H__ */
