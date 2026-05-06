/*
 * Parse a test app-filter YAML block and assert the state.
 *
 * Build (after main project so libyaml is built):
 *   cc -Wall -Wextra -Werror -Isrc -Itests/stubs \
 *      -Ithird-part/yaml/include \
 *      tests/test-app-filter-parse.c \
 *      src/hev-app-filter.c src/hev-app-filter-lookup.c \
 *      third-part/yaml/bin/libyaml.a \
 *      -o build/test-app-filter-parse
 *
 *   ./build/test-app-filter-parse
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <yaml.h>

#include "hev-app-filter.h"

void
each_app_cb (const char *path, void *ud)
{
    int *counts = ud;
    if (strcmp (path, "/usr/bin/curl") == 0)
        counts[0]++;
    else if (strcmp (path, "com.apple.Safari") == 0)
        counts[1]++;
}

static const char *YAML_DOC =
    "app-filter:\n"
    "  mode: include\n"
    "  apps:\n"
    "    - \"/usr/bin/curl\"\n"
    "    - \"com.apple.Safari\"\n"
    "  pids: [12345, 6789]\n"
    "  uids: [501]\n"
    "  unmatched: drop\n"
    "  control-socket: \"/tmp/foo.sock\"\n";

int
main (void)
{
    yaml_parser_t parser;
    yaml_document_t doc;
    yaml_parser_initialize (&parser);
    yaml_parser_set_input_string (&parser, (const unsigned char *) YAML_DOC,
                                  strlen (YAML_DOC));
    if (!yaml_parser_load (&parser, &doc)) {
        fprintf (stderr, "yaml load fail\n");
        return 1;
    }
    yaml_node_t *root = yaml_document_get_root_node (&doc);
    assert (root && root->type == YAML_MAPPING_NODE);
    /* The root is { app-filter: { ... } }. Get the sub-node. */
    yaml_node_pair_t *pair = root->data.mapping.pairs.start;
    yaml_node_t *kn = yaml_document_get_node (&doc, pair->key);
    yaml_node_t *vn = yaml_document_get_node (&doc, pair->value);
    assert (kn && strcmp ((const char *) kn->data.scalar.value, "app-filter")
            == 0);

    int rc = hev_app_filter_parse (&doc, vn);
    assert (rc == 0);
    yaml_document_delete (&doc);
    yaml_parser_delete (&parser);

    assert (hev_app_filter_enabled ());
    assert (hev_app_filter_get_mode () == HEV_APP_FILTER_MODE_INCLUDE);
    assert (hev_app_filter_get_unmatched () == HEV_APP_FILTER_UNMATCHED_DROP);
    assert (strcmp (hev_app_filter_get_control_socket (), "/tmp/foo.sock")
            == 0);

    int counts[2] = { 0, 0 };
    extern void each_app_cb (const char *path, void *ud);
    hev_app_filter_each_app (each_app_cb, counts);
    assert (counts[0] == 1 && counts[1] == 1);

    /* Live-update API */
    assert (hev_app_filter_add_app ("/usr/bin/wget") == 0);
    assert (hev_app_filter_add_app ("/usr/bin/wget") == 0); /* dedupe */
    assert (hev_app_filter_remove_app ("/usr/bin/wget") == 0);
    assert (hev_app_filter_remove_app ("/usr/bin/wget") == -1);

    assert (hev_app_filter_add_pid (777) == 0);
    assert (hev_app_filter_remove_pid (777) == 0);

    /* Set-mode round-trip */
    hev_app_filter_set_mode (HEV_APP_FILTER_MODE_EXCLUDE);
    assert (hev_app_filter_get_mode () == HEV_APP_FILTER_MODE_EXCLUDE);

    hev_app_filter_fini ();
    assert (!hev_app_filter_enabled ());

    printf ("ok\n");
    return 0;
}
