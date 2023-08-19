#include "replayer.h"
#include "utils.h"
#include <sys/timerfd.h>

struct _replayer_t {
    zhash_t *db_uuid_to_zyre_hash;
    zactor_t *auth;
    zcert_t *cert;
    char *curve_zap_domain;
    sqlite3 *db;
    sqlite3_stmt *data_query;
    unsigned long long start_timestamp;
    int next_msg_timerfd;

    const char *next_msg_peer_uuid;
    const char *next_msg_shout_group;
    const void *next_msg_payload;
    int next_msg_payload_size;

    int udp_beacon_port;
    char *iface;
    int start_delay_s;
    bool start_delay_running;

    bool stats_enabled;
    bool verbose;

    unsigned long long stats_total_rows;
    unsigned long long stats_row_counter;
    unsigned long long stats_previous_row_counter;
    unsigned long long stats_last_printout_time;
};


volatile bool s_replayer_main_interrupted = false;


static void s_replayer_destroy_zyre(void *data)
{
    zyre_t *z = (zyre_t*)data;
    zyre_stop(z);
    zyre_destroy(&z);
}


static void s_replayer_signal_handler(int signal_num)
{
    (void)signal_num; // suppress unused parameter
    s_replayer_main_interrupted = true;
}


replayer_t* replayer_new(bool ipv6, bool verbose, int udp_beacon_port, const char *iface, int start_delay_s)
{
    replayer_t *self = (replayer_t*)zmalloc(sizeof(replayer_t));
    assert(self);

    self->db_uuid_to_zyre_hash = zhash_new();
    assert(self->db_uuid_to_zyre_hash);

    self->verbose = verbose;

    self->udp_beacon_port = udp_beacon_port;
    zsys_info("UDP beacon discovery port: %d", self->udp_beacon_port);

    if (iface) {
        self->iface = strdup(iface);
        if (!self->iface) {
            free(self);
            return NULL;
        }
    }
    zsys_info("Network interface: %s", self->iface ? self->iface : "(default)");

    zsys_set_ipv6(ipv6);
    zsys_info(ipv6 ? "IPv6 enabled" : "IPv6 disabled");

    self->start_delay_s = start_delay_s;
    zsys_info("Replay start delay: %d seconds", self->start_delay_s);

    self->next_msg_timerfd = -1;

    return self;
}


void replayer_destroy(replayer_t **self_p)
{
    assert(self_p);
    if (*self_p) {
        replayer_t *self = *self_p;

        zhash_destroy(&self->db_uuid_to_zyre_hash);

        if (self->iface) {
            free(self->iface);
            self->iface = NULL;
        }

        if (self->curve_zap_domain) {
            free(self->curve_zap_domain);
            self->curve_zap_domain = NULL;
        }

        if (self->data_query)
            sqlite3_finalize(self->data_query);
        sqlite3_close(self->db);

        zactor_destroy(&self->auth);
        zcert_destroy(&self->cert);

        if (self->next_msg_timerfd >= 0)
            close(self->next_msg_timerfd);

        free(self);
        *self_p = NULL;
    }
}


bool replayer_setup_curve(replayer_t *self, const char *curve_dir, const char *curve_key_file, const char *curve_zap_domain)
{
    assert(self);

    if (!zsys_has_curve()) {
        zsys_error("Unable to initialize CURVE, because it is not enabled in zsys");
        return false;
    }

    self->auth = zactor_new(zauth, NULL);
    if (!self->auth) {
        zsys_error("Failed to initialize zauth");
        return false;
    }

    if (self->verbose) {
        zstr_sendx(self->auth, "VERBOSE", NULL);
        zsock_wait(self->auth);
    }

    if (streq(curve_dir, "CURVE_ALLOW_ANY")) {
        zsys_info("Certificate checking disabled; all CURVE peers allowed");
        zstr_sendx(self->auth, "CURVE", CURVE_ALLOW_ANY, NULL);
    } else {
        zsys_info("Using CURVE public keys from directory: %s", curve_dir);
        zstr_sendx(self->auth, "CURVE", curve_dir, NULL);
    }
    zsock_wait(self->auth);

    if (curve_key_file) {
        zsys_info("Using CURVE private key from file: %s", curve_key_file);
        self->cert = zcert_load(curve_key_file);
    } else {
        zsys_warning("CURVE private key not specified");
        self->cert = zcert_new();
    }
    if (!self->cert) {
        zsys_error("Failed to create zcert");
        return false;
    }

    if (curve_zap_domain)
        self->curve_zap_domain = strdup(curve_zap_domain);

    return true;
}


bool replayer_load_database(replayer_t *self, const char *database_filename, const char *database_table)
{
    static const int SQLITE_BUSY_TIMEOUT_MS = 100;

    assert(self);

    zsys_info("Replaying from database file \"%s\" from table \"%s\"", database_filename, database_table);

    int rc = sqlite3_open(database_filename, &self->db);
    if (rc != SQLITE_OK) {
        printf("Unable to open file: %s\n", sqlite3_errmsg(self->db));
        return false;
    }

    if (sqlite3_busy_timeout(self->db, SQLITE_BUSY_TIMEOUT_MS) != SQLITE_OK) {
        zsys_warning("Unable to set SQLite busy timeout");
    }

    zsys_info("Finding all peers from the recording and starting them...");

    char sql_buffer[1024];
    snprintf(
            sql_buffer,
            sizeof(sql_buffer),
            "SELECT DISTINCT peer_uuid, peer_name FROM \"%s\"",
            database_table
            );
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(self->db, sql_buffer, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf(
                "Failed to prepare statement for select: %s\n",
                sqlite3_errmsg(self->db)
              );
        return false;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *uuid = sqlite3_column_text(stmt, 0);
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        if (uuid && name) {
            zyre_t *zyre = zyre_new((const char *)name);
            assert(zyre);

            zsys_info("Created Zyre node, name=%s, uuid=%s", zyre_name(zyre), zyre_uuid(zyre));

            if (self->verbose)
                zyre_set_verbose(zyre);

            zyre_set_port(zyre, self->udp_beacon_port);

            if (self->iface)
                zyre_set_interface(zyre, self->iface);
            if (self->curve_zap_domain)
                zyre_set_zap_domain(zyre, self->curve_zap_domain);
            if (self->cert)
                zyre_set_zcert(zyre, self->cert);

            zyre_start(zyre);

            if (zhash_insert(self->db_uuid_to_zyre_hash, (const char *)uuid, zyre) != 0) {
                zsys_error("Failed to add Zyre node to hash container");
                zyre_stop(zyre);
                zyre_destroy(&zyre);
                return false;
            }

            zhash_freefn(self->db_uuid_to_zyre_hash, (const char *)uuid, s_replayer_destroy_zyre);
        }
    }

    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        zsys_info("All peers started");
    } else if (rc == SQLITE_ERROR) {
        zsys_error("Error occurred while executing prepared SQL statement: %s", sqlite3_errmsg(self->db));
        return false;
    } else {
        zsys_error("Prepared SQL statement failed with return code %d (%s)", sqlite3_errcode(self->db), sqlite3_errmsg(self->db));
        return false;
    }

    zsys_info("Counting recording rows...");

    snprintf(
            sql_buffer,
            sizeof(sql_buffer),
            "SELECT COUNT(*) FROM \"%s\" WHERE shout_group IS NOT NULL",
            database_table
            );
    rc = sqlite3_prepare_v2(self->db, sql_buffer, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf(
                "Failed to prepare statement for select: %s\n",
                sqlite3_errmsg(self->db)
              );
        return false;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        self->stats_total_rows = (unsigned long long)sqlite3_column_int64(stmt, 0);
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    if (rc == SQLITE_ERROR) {
        zsys_error("Error occurred while executing prepared SQL statement: %s", sqlite3_errmsg(self->db));
        return false;
    } else if (rc != SQLITE_DONE) {
        zsys_error("Prepared SQL statement failed with return code %d (%s)", sqlite3_errcode(self->db), sqlite3_errmsg(self->db));
        return false;
    }
    zsys_info("Recording has %lld rows", self->stats_total_rows);

    zsys_info("Preparing data query...");

    snprintf(
            sql_buffer,
            sizeof(sql_buffer),
            "SELECT timestamp, "
                "timestamp - (first_value(timestamp) OVER ()) AS time_from_start, "
                "peer_uuid, shout_group, payload FROM \"%s\" WHERE shout_group IS NOT NULL ORDER BY timestamp ASC",
            database_table
            );
    rc = sqlite3_prepare_v2(self->db, sql_buffer, -1, &self->data_query, NULL);
    if (rc != SQLITE_OK) {
        printf(
                "Failed to prepare statement for select: %s\n",
                sqlite3_errmsg(self->db)
              );
        return false;
    }

    zsys_info("Data query ready. Start delay...");

    return true;
}


void replayer_enable_statistics(replayer_t *self, bool enabled)
{
    assert(self);
    self->stats_enabled = enabled;
}


int replayer_run(replayer_t *self, int argc, char *argv[], int next_arg_index)
{
    assert(self);

    zpoller_t *poller = zpoller_new(NULL);
    if (!poller) {
        zsys_error("Failed to create zpoller");
        return 1;
    }

    for (void *zi = zhash_first(self->db_uuid_to_zyre_hash); zi != NULL; zi = zhash_next(self->db_uuid_to_zyre_hash)) {
        zyre_t *zi_ref = (zyre_t*)zi;
        zpoller_add(poller, zyre_socket(zi_ref));
    }

    replayer_reset_statistics(self);

    if (sqlite3_step(self->data_query) == SQLITE_ROW) {
        self->next_msg_peer_uuid = (const char*)sqlite3_column_text(self->data_query, 2);
        self->next_msg_shout_group = (const char*)sqlite3_column_text(self->data_query, 3);
        self->next_msg_payload = sqlite3_column_blob(self->data_query, 4);
        self->next_msg_payload_size = sqlite3_column_bytes(self->data_query, 4);
    } else {
        self->next_msg_peer_uuid = NULL;
        self->next_msg_shout_group = NULL;
        self->next_msg_payload = NULL;
        self->next_msg_payload_size = 0;
    }

    self->next_msg_timerfd = timerfd_create(CLOCK_REALTIME, 0);
    if (self->next_msg_timerfd < 0) {
        zsys_error("Unable to create timerfd");
        return 1;
    }
    struct itimerspec next_msg_timerspec = {0};
    next_msg_timerspec.it_value.tv_sec = (time_t)self->start_delay_s;
    timerfd_settime(self->next_msg_timerfd, 0, &next_msg_timerspec, NULL);
    self->start_delay_running = true;
    zpoller_add(poller, &self->next_msg_timerfd);

    zsys_handler_set(s_replayer_signal_handler);

    while (!s_replayer_main_interrupted) {
        const void *which = zpoller_wait(poller, 1000);

        if (which == NULL) {
            if (zpoller_terminated(poller)) {
                zsys_info("Terminating...");
                s_replayer_main_interrupted = true;
            }
        } else if (which == &self->next_msg_timerfd) {
            if (self->verbose)
                zsys_debug("Shouting next message");

            self->stats_row_counter++;

            if (self->next_msg_peer_uuid && self->next_msg_shout_group && self->next_msg_payload) {
                zyre_t *zi = (zyre_t*)zhash_lookup(self->db_uuid_to_zyre_hash, self->next_msg_peer_uuid);
                if (zi) {
                    zframe_t *frame = zframe_new(self->next_msg_payload, self->next_msg_payload_size);
                    if (frame) {
                        zmsg_t *msg = zmsg_decode(frame);
                        if (msg) {
                            if (zyre_shout(zi, self->next_msg_shout_group, &msg) != 0) {
                                zsys_error("Failed to shout message");
                            }
                        }
                        zmsg_destroy(&msg);
                    }
                    zframe_destroy(&frame);
                } else {
                    zsys_error("Unexpected peer UUID in database; message skipped: %s", self->next_msg_peer_uuid);
                }
            }

            if (self->start_delay_running) {
                self->start_delay_running = false;
                self->start_timestamp = get_time_in_microseconds();
                zsys_info("Replaying...");
            }

            int rc = sqlite3_step(self->data_query);
            if (rc == SQLITE_ROW) {
                unsigned long long time_from_start = (unsigned long long)sqlite3_column_int64(self->data_query, 1);
                self->next_msg_peer_uuid = (const char*)sqlite3_column_text(self->data_query, 2);
                self->next_msg_shout_group = (const char*)sqlite3_column_text(self->data_query, 3);
                self->next_msg_payload = sqlite3_column_blob(self->data_query, 4);
                self->next_msg_payload_size = sqlite3_column_bytes(self->data_query, 4);

                next_msg_timerspec.it_interval.tv_sec = 0;
                next_msg_timerspec.it_interval.tv_nsec = 0;
                next_msg_timerspec.it_value.tv_sec = (time_t)((self->start_timestamp + time_from_start) / 1000000ULL);
                next_msg_timerspec.it_value.tv_nsec = (long)(
                        (
                         (self->start_timestamp + time_from_start)
                         - ((unsigned long long)next_msg_timerspec.it_value.tv_sec * 1000000ULL)
                        ) * 1000ULL
                );

                timerfd_settime(self->next_msg_timerfd, TFD_TIMER_ABSTIME, &next_msg_timerspec, NULL);
            } else if (rc == SQLITE_DONE) {
                zsys_info("End of recording reached");
                s_replayer_main_interrupted = true;
            } else if (rc == SQLITE_ERROR) {
                zsys_error("Error occurred while executing prepared SQL statement: %s", sqlite3_errmsg(self->db));
                s_replayer_main_interrupted = true;
            } else {
                zsys_error("Prepared SQL statement failed with return code %d (%s)", sqlite3_errcode(self->db), sqlite3_errmsg(self->db));
                s_replayer_main_interrupted = true;
            }
        } else {
            for (void *zi = zhash_first(self->db_uuid_to_zyre_hash); zi != NULL; zi = zhash_next(self->db_uuid_to_zyre_hash)) {
                zyre_t *zi_ref = (zyre_t*)zi;
                if (zyre_socket(zi_ref) == which) {
                    zyre_event_t *event = zyre_event_new(zi_ref);
                    if (event) {
                        if (self->verbose)
                            zyre_event_print(event);
                        zyre_event_destroy(&event);
                    }
                    break;
                }
            }
        }

        if (self->stats_enabled) {
            if (get_time_in_microseconds() > (self->stats_last_printout_time + 1000000ULL)) {
                self->stats_last_printout_time = get_time_in_microseconds();
                replayer_print_statistics(self);
            }
        }
    }

    zpoller_destroy(&poller);

    zsys_info("Waiting couple of seconds to make sure all messages have been delivered...");
    zclock_sleep(2000);

    return 0;
}


void replayer_reset_statistics(replayer_t *self)
{
    assert(self);
    self->stats_row_counter = 0;
    self->stats_previous_row_counter = 0;
    self->stats_last_printout_time = get_time_in_microseconds();
}


void replayer_print_statistics(replayer_t *self)
{
    assert(self);

    unsigned long long row_rate = self->stats_row_counter - self->stats_previous_row_counter;

    zsys_info(
            "Stats: %lld / %lld rows done, %lld /s",
            self->stats_row_counter,
            self->stats_total_rows,
            row_rate
            );

    self->stats_previous_row_counter = self->stats_row_counter;
}
