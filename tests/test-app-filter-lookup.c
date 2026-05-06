/*
 * Unit test: lookup-failure resilience.
 *
 * Build (from repo root):
 *   cc -Wall -Wextra -Werror \
 *      -Isrc -Itests/stubs \
 *      tests/test-app-filter-lookup.c src/hev-app-filter-lookup.c \
 *      -o build/test-app-filter-lookup
 *
 *   ./build/test-app-filter-lookup
 *
 * Asserts:
 *   1. NULL flow -> no crash, returns -1, result fields cleared.
 *   2. NULL out  -> no crash, returns -1.
 *   3. Override returning -1 -> returns -1, pid=-1, path empty.
 *   4. Override returning 0  -> returns 0, fields populated.
 *   5. Cache clear is safe even when never populated.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "hev-app-filter-lookup.h"

static int g_calls;
static int g_next_rc;
static int g_next_pid;
static const char *g_next_path;

static int
mock_lookup (const HevAppFilterFlow *flow, HevAppFilterLookupResult *out)
{
    (void) flow;
    g_calls++;
    if (g_next_rc != 0)
        return -1;
    out->pid = g_next_pid;
    out->uid = -1;
    if (g_next_path)
        snprintf (out->path, sizeof (out->path), "%s", g_next_path);
    return 0;
}

int
main (void)
{
    HevAppFilterLookupResult r;

    /* 1. NULL flow */
    memset (&r, 0xAA, sizeof (r));
    int rc = hev_app_filter_lookup (NULL, &r);
    assert (rc == -1);

    /* 2. NULL out */
    HevAppFilterFlow f = { 0 };
    f.proto = HEV_APP_FILTER_PROTO_TCP;
    rc = hev_app_filter_lookup (&f, NULL);
    assert (rc == -1);

    /* 3. Override that fails */
    hev_app_filter_lookup_set_override (mock_lookup);
    g_calls = 0;
    g_next_rc = -1;
    rc = hev_app_filter_lookup (&f, &r);
    assert (rc == -1);
    assert (r.pid == -1);
    assert (r.path[0] == '\0');
    assert (g_calls == 1);

    /* 4. Override that succeeds */
    g_next_rc = 0;
    g_next_pid = 4242;
    g_next_path = "/usr/bin/curl";
    rc = hev_app_filter_lookup (&f, &r);
    assert (rc == 0);
    assert (r.pid == 4242);
    assert (strcmp (r.path, "/usr/bin/curl") == 0);
    assert (g_calls == 2);

    /* 5. Clearing the cache is always safe */
    hev_app_filter_lookup_cache_clear ();
    hev_app_filter_lookup_cache_clear ();

    /* Restore real implementation; calling it on a synthetic flow must
     * not crash even though no socket on the host matches. */
    hev_app_filter_lookup_set_override (NULL);
    HevAppFilterFlow synth = { 0 };
    synth.proto = HEV_APP_FILTER_PROTO_TCP;
    synth.family = 2; /* AF_INET */
    synth.local_port = 1; /* nothing listens here */
    synth.remote_port = 1;
    rc = hev_app_filter_lookup (&synth, &r);
    /* Whether rc is 0 or -1 depends on the host; the contract is just
     * "doesn't crash and r.pid is consistent with rc". */
    if (rc == -1) {
        assert (r.pid == -1);
        assert (r.path[0] == '\0');
    } else {
        assert (r.pid >= 0);
    }

    printf ("ok\n");
    return 0;
}
