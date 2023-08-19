#pragma once

#include <stdbool.h>
#include <sqlite3.h>
#include <zyre.h>

typedef struct _replayer_t replayer_t;

replayer_t* replayer_new(bool ipv6, bool verbose, int udp_beacon_port, const char *iface, int start_delay_s);
void replayer_destroy(replayer_t **self_p);

bool replayer_setup_curve(replayer_t *self, const char *curve_dir, const char *curve_key_file, const char *curve_zap_domain);
bool replayer_load_database(replayer_t *self, const char *database_filename, const char *database_table);
void replayer_enable_statistics(replayer_t *self, bool enabled);

int replayer_run(replayer_t *self, int argc, char *argv[], int next_arg_index);

void replayer_reset_statistics(replayer_t *self);
void replayer_print_statistics(replayer_t *self);
