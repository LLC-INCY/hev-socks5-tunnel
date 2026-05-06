/*
 ============================================================================
 Name        : hev-app-filter-ctrl.h
 Author      : Boris Kovalskii
 Description : Control socket for live app-filter updates
 ============================================================================
 */

#ifndef __HEV_APP_FILTER_CTRL_H__
#define __HEV_APP_FILTER_CTRL_H__

#include "hev-app-filter-lookup.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bind the control socket if app-filter.control-socket is set. Returns
 * 0 on success, -1 on failure or when no socket is configured. Safe to
 * call from main(); spawns a hev-task to accept connections. */
int hev_app_filter_ctrl_init (void);

void hev_app_filter_ctrl_fini (void);

/* Emit a `bypass` event to the connected client (if any). No-op when no
 * client is attached. */
void hev_app_filter_ctrl_emit_bypass (int pid, const char *path,
                                      const HevAppFilterFlow *flow);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_APP_FILTER_CTRL_H__ */
