#pragma once

#include <stdbool.h>
#include <sqlite3.h>
#include <zyre.h>

typedef struct _recorder_t recorder_t;

recorder_t* recorder_new(bool ipv6, bool verbose, int udp_beacon_port, const char *iface);
void recorder_destroy(recorder_t **self_p);

bool recorder_setup_curve(recorder_t *self, const char *curve_dir, const char *curve_key_file, const char *curve_zap_domain);
bool recorder_setup_database(recorder_t *self, const char *database_filename, const char *database_table);
void recorder_enable_statistics(recorder_t *self, bool enabled);
void recorder_set_formatter_func(recorder_t *self, char* (*func)(zmsg_t *msg));

int recorder_run(recorder_t *self, int argc, char *argv[], int next_arg_index);

void recorder_reset_statistics(recorder_t *self);
void recorder_print_statistics(recorder_t *self);
