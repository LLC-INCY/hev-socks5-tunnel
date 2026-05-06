/*
 * macOS smoke test: open a listener on an ephemeral port, fork a curl-like
 * client that connects to it, then run the lookup against the client's
 * 5-tuple and assert we found the right PID and an exe path.
 *
 * Build:
 *   cc -Wall -Wextra -Werror -Isrc -Itests/stubs \
 *      tests/smoke-app-filter-lookup-macos.c src/hev-app-filter-lookup.c \
 *      -o build/smoke-app-filter-lookup
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hev-app-filter-lookup.h"

int
main (void)
{
    int srv = socket (AF_INET, SOCK_STREAM, 0);
    assert (srv >= 0);
    int yes = 1;
    setsockopt (srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes));

    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    sa.sin_port = 0;
    assert (bind (srv, (struct sockaddr *) &sa, sizeof (sa)) == 0);
    socklen_t sl = sizeof (sa);
    assert (getsockname (srv, (struct sockaddr *) &sa, &sl) == 0);
    assert (listen (srv, 4) == 0);
    uint16_t srv_port = ntohs (sa.sin_port);
    fprintf (stderr, "server on 127.0.0.1:%u\n", srv_port);

    pid_t kid = fork ();
    assert (kid >= 0);
    if (kid == 0) {
        int c = socket (AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in d = { 0 };
        d.sin_family = AF_INET;
        d.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
        d.sin_port = htons (srv_port);
        if (connect (c, (struct sockaddr *) &d, sizeof (d)) < 0) {
            perror ("child connect");
            _exit (1);
        }
        sleep (3); /* keep socket open while parent looks it up */
        _exit (0);
    }

    int conn = accept (srv, NULL, NULL);
    assert (conn >= 0);
    struct sockaddr_in peer = { 0 };
    socklen_t pl = sizeof (peer);
    assert (getpeername (conn, (struct sockaddr *) &peer, &pl) == 0);
    uint16_t peer_port = ntohs (peer.sin_port);
    fprintf (stderr, "child connected from 127.0.0.1:%u\n", peer_port);

    HevAppFilterFlow f = { 0 };
    f.proto = HEV_APP_FILTER_PROTO_TCP;
    f.family = AF_INET;
    /* "Local" in our schema = host-process side = the child's source. */
    uint32_t loop = htonl (INADDR_LOOPBACK);
    memcpy (f.local_addr, &loop, 4);
    memcpy (f.remote_addr, &loop, 4);
    f.local_port = peer_port;
    f.remote_port = srv_port;

    HevAppFilterLookupResult r;
    int rc = hev_app_filter_lookup (&f, &r);
    fprintf (stderr, "lookup rc=%d pid=%d path=%s\n", rc, r.pid, r.path);

    int ok = (rc == 0 && r.pid == kid && r.path[0] != '\0');

    close (conn);
    close (srv);
    int status;
    waitpid (kid, &status, 0);

    if (ok) {
        printf ("ok\n");
        return 0;
    }
    fprintf (stderr, "FAIL: expected pid=%d, got rc=%d pid=%d\n",
             kid, rc, r.pid);
    return 1;
}
