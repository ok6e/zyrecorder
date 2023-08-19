#include "recorder.h"
#include "utils.h"

struct _recorder_t {
    zyre_t *zyre;
    zactor_t *auth;
    zcert_t *cert;
    sqlite3 *db;
    sqlite3_stmt *insert;

    char* (*formatter_func)(zmsg_t *msg);

    bool stats_enabled;
    bool verbose;

    unsigned long long stats_shouts_counter;
    unsigned long long stats_whispers_counter;
    unsigned long long stats_previous_total_counter;
    unsigned long long stats_last_printout_time;
};


static void s_recorder_handle_join_event(recorder_t *self, zyre_event_t *event);
static void s_recorder_handle_shout_event(recorder_t *self, zyre_event_t *event);
static void s_recorder_handle_whisper_event(recorder_t *self, zyre_event_t *event);
static bool s_recorder_store_message(
        recorder_t *self,
        unsigned long long event_time,
        const char *peer_uuid,
        const char *peer_name,
        const char *shout_group,
        const void *payload_data,
        int payload_size,
        const char *pretty_print
        );


recorder_t* recorder_new(bool ipv6, bool verbose, int udp_beacon_port, const char *iface)
{
    recorder_t *self = (recorder_t*)zmalloc(sizeof(recorder_t));
    assert(self);

    self->verbose = verbose;

    zsys_set_ipv6(ipv6);
    zsys_info(ipv6 ? "IPv6 enabled" : "IPv6 disabled");

    self->zyre = zyre_new("zyrecorder");
    assert(self->zyre);

    zsys_info("Created Zyre node, name=%s, uuid=%s", zyre_name(self->zyre), zyre_uuid(self->zyre));

    if (self->verbose)
        zyre_set_verbose(self->zyre);

    zyre_set_port(self->zyre, udp_beacon_port);
    zsys_info("UDP beacon discovery port: %d", udp_beacon_port);

    if (iface)
        zyre_set_interface(self->zyre, iface);
    zsys_info("Network interface: %s", iface ? iface : "(default)");

    return self;
}


void recorder_destroy(recorder_t **self_p)
{
    assert(self_p);
    if (*self_p) {
        recorder_t *self = *self_p;

        if (self->insert)
            sqlite3_finalize(self->insert);

        sqlite3_close(self->db);

        if (self->zyre) {
            zyre_stop(self->zyre);
            zyre_destroy(&self->zyre);
        }

        zactor_destroy(&self->auth);
        zcert_destroy(&self->cert);

        free(self);
        *self_p = NULL;
    }
}


bool recorder_setup_curve(recorder_t *self, const char *curve_dir, const char *curve_key_file, const char *curve_zap_domain)
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

    zyre_set_zap_domain(self->zyre, curve_zap_domain);
    zsys_info("CURVE ZAP domain: %s", curve_zap_domain);

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
    zyre_set_zcert(self->zyre, self->cert);

    return true;
}


bool recorder_setup_database(recorder_t *self, const char *database_filename, const char *database_table)
{
    static const int SQLITE_BUSY_TIMEOUT_MS = 100;

    assert(self);

    zsys_info("Recording to database file \"%s\" to table \"%s\"", database_filename, database_table);

    int rc = sqlite3_open(database_filename, &self->db);
    if (rc != SQLITE_OK) {
        printf("Unable to open file: %s\n", sqlite3_errmsg(self->db));
        return false;
    }

    if (sqlite3_busy_timeout(self->db, SQLITE_BUSY_TIMEOUT_MS) != SQLITE_OK) {
        zsys_warning("Unable to set SQLite busy timeout");
    }

    char sql_buffer[1024];
    snprintf(
            sql_buffer,
            sizeof(sql_buffer),
            "CREATE TABLE IF NOT EXISTS \"%s\" (timestamp INTEGER, peer_uuid TEXT, peer_name TEXT, shout_group TEXT, payload BLOB, pretty_print TEXT)",
            database_table
            );
    rc = sqlite3_exec(self->db, sql_buffer, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        printf(
                "Failed to create table \"%s\" in database \"%s\": %s\n",
                database_table,
                database_filename,
                sqlite3_errmsg(self->db)
                );
        return false;
    }

    snprintf(
            sql_buffer,
            sizeof(sql_buffer),
            "INSERT INTO \"%s\" (timestamp, peer_uuid, peer_name, shout_group, payload, pretty_print) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            database_table
            );
    rc = sqlite3_prepare_v2(self->db, sql_buffer, -1, &self->insert, NULL);
    if (rc != SQLITE_OK) {
        printf(
                "Failed to prepare statement for insert: %s\n",
                sqlite3_errmsg(self->db)
              );
        return false;
    }

    return true;
}


void recorder_enable_statistics(recorder_t *self, bool enabled)
{
    assert(self);
    self->stats_enabled = enabled;
}


void recorder_set_formatter_func(recorder_t *self, char* (*func)(zmsg_t *msg))
{
    assert(self);
    self->formatter_func = func;
}


int recorder_run(recorder_t *self, int argc, char *argv[], int next_arg_index)
{
    assert(self);
    
    zyre_start(self->zyre);

    if (next_arg_index < argc) {
        zsys_info("Joining these groups explicitly:");
        for (int i = next_arg_index; i < argc; ++i) {
            zyre_join(self->zyre, argv[i]);
            zsys_info(" - %s", argv[i]);
        }
    }

    zpoller_t *poller = zpoller_new(zyre_socket(self->zyre), NULL);
    if (!poller) {
        zsys_error("Failed to create zpoller");
        return 1;
    }

    recorder_reset_statistics(self);

    bool terminated = false;

    while (!terminated) {
        const void *which = zpoller_wait(poller, 1000);

        if (which == NULL) {
            if (zpoller_terminated(poller)) {
                zsys_info("Terminating...");
                terminated = true;
            }
        } else if (which == zyre_socket(self->zyre)) {
            zyre_event_t *event = zyre_event_new(self->zyre);
            if (event) {
                if (self->verbose)
                    zyre_event_print(event);

                if (streq(zyre_event_type(event), "JOIN")) {
                    s_recorder_handle_join_event(self, event);
                } else if (streq(zyre_event_type(event), "SHOUT")) {
                    s_recorder_handle_shout_event(self, event);
                } else if (streq(zyre_event_type(event), "WHISPER")) {
                    s_recorder_handle_whisper_event(self, event);
                }

                zyre_event_destroy(&event);
            }
        }

        if (self->stats_enabled) {
            if (get_time_in_microseconds() > (self->stats_last_printout_time + 1000000ULL)) {
                self->stats_last_printout_time = get_time_in_microseconds();
                recorder_print_statistics(self);
            }
        }
    }

    zpoller_destroy(&poller);

    return 0;
}


static void s_recorder_handle_join_event(recorder_t *self, zyre_event_t *event)
{
    assert(self);
    zyre_join(self->zyre, zyre_event_group(event));
    zsys_info("Updated group memberships due to JOIN event:");
    zlist_t *own_groups = zyre_own_groups(self->zyre);
    if (own_groups) {
        const char *group = zlist_first(own_groups);
        while (group) {
            zsys_info(" - %s", group);
            group = zlist_next(own_groups);
        }
        zlist_destroy(&own_groups);
    }
}


static void s_recorder_handle_shout_event(recorder_t *self, zyre_event_t *event)
{
    assert(self);
    unsigned long long event_time = get_time_in_microseconds();

    zmsg_t *msg = zyre_event_get_msg(event);
    if (!msg) {
        zsys_error("Failed to extract payload from SHOUT event");
        return;
    }

    zframe_t *encoded_frame = zmsg_encode(msg);
    if (!encoded_frame) {
        zsys_error("Failed to encode SHOUT event payload into a single zframe");
        zmsg_destroy(&msg);
        return;
    }

    char* pretty_print = (self->formatter_func != NULL) ? (*self->formatter_func)(msg) : NULL;

    bool recorded_successfully = s_recorder_store_message(
            self,
            event_time,
            zyre_event_peer_uuid(event),
            zyre_event_peer_name(event),
            zyre_event_group(event),
            zframe_data(encoded_frame),
            zframe_size(encoded_frame),
            pretty_print
          );

    if (recorded_successfully && self->stats_enabled)
        self->stats_shouts_counter++;

    if (pretty_print)
        free(pretty_print);
    zframe_destroy(&encoded_frame);
    zmsg_destroy(&msg);
}


static void s_recorder_handle_whisper_event(recorder_t *self, zyre_event_t *event)
{
    assert(self);
    unsigned long long event_time = get_time_in_microseconds();

    zmsg_t *msg = zyre_event_get_msg(event);
    if (!msg) {
        zsys_error("Failed to extract payload from WHISPER event");
        return;
    }

    zframe_t *encoded_frame = zmsg_encode(msg);
    if (!encoded_frame) {
        zsys_error("Failed to encode WHISPER event payload into a single zframe");
        zmsg_destroy(&msg);
        return;
    }

    char* pretty_print = (self->formatter_func != NULL) ? (*self->formatter_func)(msg) : NULL;

    bool recorded_successfully = s_recorder_store_message(
            self,
            event_time,
            zyre_event_peer_uuid(event),
            zyre_event_peer_name(event),
            NULL,
            zframe_data(encoded_frame),
            zframe_size(encoded_frame),
            pretty_print
          );

    if (recorded_successfully && self->stats_enabled)
        self->stats_whispers_counter++;

    if (pretty_print)
        free(pretty_print);
    zframe_destroy(&encoded_frame);
    zmsg_destroy(&msg);
}


static bool s_recorder_store_message(
        recorder_t *self,
        unsigned long long event_time,
        const char *peer_uuid,
        const char *peer_name,
        const char *shout_group,
        const void *payload_data,
        int payload_size,
        const char *pretty_print
        )
{
    assert(self);
    int rc0 = sqlite3_bind_int64(self->insert, 1, event_time);
    int rc1 = sqlite3_bind_text(self->insert, 2, peer_uuid,  -1, SQLITE_TRANSIENT);
    int rc2 = sqlite3_bind_text(self->insert, 3, peer_name, -1, SQLITE_TRANSIENT);
    int rc3;
    if (shout_group)
        rc3 = sqlite3_bind_text(self->insert, 4, shout_group, -1, SQLITE_TRANSIENT);
    else
        rc3 = sqlite3_bind_null(self->insert, 4);
    int rc4 = sqlite3_bind_blob(self->insert, 5, payload_data, payload_size, SQLITE_TRANSIENT);
    int rc5;
    if (pretty_print)
        rc5 = sqlite3_bind_text(self->insert, 6, pretty_print, -1, SQLITE_TRANSIENT);
    else
        rc5 = sqlite3_bind_null(self->insert, 6);

    if (
           (rc0 != SQLITE_OK) 
        || (rc1 != SQLITE_OK)
        || (rc2 != SQLITE_OK)
        || (rc3 != SQLITE_OK)
        || (rc4 != SQLITE_OK)
        || (rc5 != SQLITE_OK)
    ) {
        zsys_error(
                "Failed to bind all SQL parameters: %d,%d,%d,%d,%d,%d",
                rc0, rc1, rc2, rc3, rc4, rc5
                );
        return false;
    }

    bool recorded_successfully = false;

    int rc_step = sqlite3_step(self->insert);
    if (rc_step == SQLITE_DONE) {
        recorded_successfully = true;
    } else if (rc_step == SQLITE_ERROR) {
        recorded_successfully = false;
        zsys_error("Error occurred while executing prepared SQL statement: %s", sqlite3_errmsg(self->db));
    } else {
        recorded_successfully = false;
        zsys_error("Prepared SQL statement failed with return code %d (%s)", sqlite3_errcode(self->db), sqlite3_errmsg(self->db));
    }

    sqlite3_reset(self->insert);
    sqlite3_clear_bindings(self->insert);

    return recorded_successfully;
}


void recorder_reset_statistics(recorder_t *self)
{
    assert(self);
    self->stats_shouts_counter = 0;
    self->stats_whispers_counter = 0;
    self->stats_previous_total_counter = 0;
    self->stats_last_printout_time = get_time_in_microseconds();
}


void recorder_print_statistics(recorder_t *self)
{
    assert(self);

    unsigned long long msg_rate = (self->stats_shouts_counter + self->stats_whispers_counter) - self->stats_previous_total_counter;

    zsys_info(
            "Stats: %lld shouts, %lld whispers, %lld total, %lld /s",
            self->stats_shouts_counter,
            self->stats_whispers_counter,
            self->stats_shouts_counter + self->stats_whispers_counter,
            msg_rate
            );

    self->stats_previous_total_counter = self->stats_shouts_counter + self->stats_whispers_counter;
}
