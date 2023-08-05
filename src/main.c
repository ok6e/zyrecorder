#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <ctype.h>
#include <zyre.h>
#include <zyre_library.h>
#include "zyrecorder_version.h"

// TYPES //////////////////////////////////////////////////////////////////////

struct statistics {
    unsigned long long shouts_counter;
    unsigned long long whispers_counter;

    unsigned long long previous_total_counter;

    unsigned long long last_printout_time;
};

// GLOBALS ////////////////////////////////////////////////////////////////////

static zyre_t               *g_zyre         = NULL;
static zactor_t             *g_auth         = NULL;
static sqlite3              *g_db           = NULL;
static sqlite3_stmt         *g_insert       = NULL;

static bool                 g_stats_enabled = false;
static struct statistics    g_stats;

// FUNCTION PROTOTYPES ////////////////////////////////////////////////////////

static void cleanup(void);

static bool setup_zyre(bool ipv6, bool verbose, int udp_beacon_port, const char *iface);
static bool setup_curve(bool verbose, const char *curve_dir, const char *curve_key_file, const char *curve_zap_domain);
static bool setup_database(const char *database_filename, const char *database_table);

static void handle_join_event(zyre_event_t *event);
static void handle_shout_event(zyre_event_t *event);
static void handle_whisper_event(zyre_event_t *event);

static bool record(
        unsigned long long event_time,
        const char *peer_uuid,
        const char *peer_name,
        const char *shout_group,
        const void *payload_data,
        int payload_size
        );

static unsigned long long get_time_in_microseconds(void);

static void reset_statistics(void);
static void print_statistics(void);

// FUNCTIONS //////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    char    *iface              = NULL;
    bool    verbose             = false;
    bool    ipv6                = false;
    char    *curve              = NULL;
    char    *curve_key_file     = NULL;
    char    *curve_zap_domain   = ZAP_DOMAIN_DEFAULT;
    int     udp_beacon_port     = 5670;
    char    *database_filename  = NULL;
    char    *database_table     = NULL;

    printf("zyrecorder (%s)\n", ZYRECORDER_VERSION);

    int c = 0;
    while ((c = getopt(argc, argv, "hi:p:sv6c:C:z:")) != -1) {
        switch (c) {
        case 'i':
            iface = optarg;
            break;
        case 'p':
            udp_beacon_port = atoi(optarg);
            break;
        case 's':
            g_stats_enabled = true;
            break;
        case 'v':
            verbose = true;
            break;
        case '6':
            ipv6 = true;
            break;
        case 'c':
            curve = optarg;
            break;
        case 'C':
            curve_key_file = optarg;
            break;
        case 'z':
            curve_zap_domain = optarg;
            break;
        default:
            printf("Usage: zyrecorder [options] <file> <table> [groups...]\n");
            printf("\n");
            printf("Records messages from a ZMQ Zyre network into an SQLite file.\n");
            printf("\n");
            printf("Options:\n");
            printf("  -h                Show this help\n");
            printf("  -i <interface>    Connect using the specified interface\n");
            printf("  -p <port>         Set UDP beacon discovery port (default 5670)\n");
            printf("  -s                Print periodic statistics\n");
            printf("  -v                Verbose logging\n");
            printf("  -6                Use IPv6\n");
            printf("  -c <public-dir>   Use CURVE encryption\n");
            printf("                    Allowed public keys are read from <public-dir>\n");
            printf("                    Use \"CURVE_ALLOW_ALL\" to disable certificate checking\n");
            printf("                    You probably want to define option \"-C\" as well\n");
            printf("  -C <key-file>     When using CURVE, use <key-file> as our own private key\n");
            printf("  -z <zap-domain>   Set specific ZAP domain for CURVE encryption\n");
            return 1;
        }
    }

    if (optind >= argc) {
        printf("You must specify a database file for the recording. See -h for help.\n");
        return 1;
    } else {
        database_filename = argv[optind];
    }
    optind++;

    if (optind >= argc) {
        printf("You must specify a database table for the recording. See -h for help.\n");
        return 1;
    } else {
        database_table = argv[optind];
        if ((strlen(database_table) < 1) || (strlen(database_table) > 128)) {
            printf("Database table name should be 1 to 128 characters long.\n");
            return 1;
        }
        if (isdigit(database_table[0])) {
            printf("Database table name shall not start with a digit.\n");
            return 1;
        }
        for (size_t i = 0; i < strlen(database_table); ++i) {
            if ((!isalnum(database_table[i])) && (database_table[i] != '_')) {
                printf("Database table name shall only consist of characters: A-Z a-z 0-9 _\n");
                return 1;
            }
        }
    }
    optind++;

    zsys_info("Recording to database file \"%s\" to table \"%s\"", database_filename, database_table);

    if (!setup_zyre(ipv6, verbose, udp_beacon_port, iface)) {
        cleanup();
        return 1;
    }

    if (curve) {
        zsys_info("Enabling CURVE encryption");
        if (!setup_curve(verbose, curve, curve_key_file, curve_zap_domain)) {
            cleanup();
            return 1;
        }
    }

    if (!setup_database(database_filename, database_table)) {
        cleanup();
        return 1;
    }
    
    zyre_start(g_zyre);

    if (optind < argc) {
        zsys_info("Joining these groups explicitly:");
        for (int i = optind; i < argc; ++i) {
            zyre_join(g_zyre, argv[i]);
            zsys_info(" - %s", argv[i]);
        }
    }

    zpoller_t *poller = zpoller_new(zyre_socket(g_zyre), NULL);
    if (!poller) {
        zsys_error("Failed to create zpoller");
        cleanup();
        return 1;
    }

    reset_statistics();

    bool terminated = false;

    while (!terminated) {
        const void *which = zpoller_wait(poller, 1000);
        if (which == NULL) {
            if (zpoller_terminated(poller)) {
                zsys_info("Terminating...");
                terminated = true;
            }
        } else if (which == zyre_socket(g_zyre)) {
            zyre_event_t *event = zyre_event_new(g_zyre);
            if (event) {
                if (verbose)
                    zyre_event_print(event);

                if (streq(zyre_event_type(event), "JOIN")) {
                    handle_join_event(event);
                } else if (streq(zyre_event_type(event), "SHOUT")) {
                    handle_shout_event(event);
                } else if (streq(zyre_event_type(event), "WHISPER")) {
                    handle_whisper_event(event);
                }

                zyre_event_destroy(&event);
            }
        }

        if (g_stats_enabled) {
            if (get_time_in_microseconds() > (g_stats.last_printout_time + 1000000ULL)) {
                g_stats.last_printout_time = get_time_in_microseconds();
                print_statistics();
            }
        }
    }

    cleanup();
    return 0;
}


static void cleanup(void)
{
    zsys_debug("Cleaning up...");

    if (g_insert) {
        sqlite3_finalize(g_insert);
    }

    sqlite3_close(g_db);

    if (g_zyre) {
        zyre_stop(g_zyre);
        zyre_destroy(&g_zyre);
    }

    zactor_destroy(&g_auth);
}


static bool setup_zyre(bool ipv6, bool verbose, int udp_beacon_port, const char *iface)
{
    zsys_set_ipv6(ipv6);
    zsys_info(ipv6 ? "IPv6 enabled" : "IPv6 disabled");

    g_zyre = zyre_new("zyrecorder");
    if (!g_zyre) {
        zsys_error("Failed to create Zyre node");
        return false;
    }
    zsys_info("Created Zyre node, name=%s, uuid=%s", zyre_name(g_zyre), zyre_uuid(g_zyre));

    if (verbose)
        zyre_set_verbose(g_zyre);

    zyre_set_port(g_zyre, udp_beacon_port);
    zsys_info("UDP beacon discovery port: %d", udp_beacon_port);

    if (iface)
        zyre_set_interface(g_zyre, iface);
    zsys_info("Network interface: %s", iface ? iface : "(default)");

    return true;
}


static bool setup_curve(bool verbose, const char *curve_dir, const char *curve_key_file, const char *curve_zap_domain)
{
    if (!zsys_has_curve()) {
        zsys_error("Unable to initialize CURVE, because it is not enabled in zsys");
        return false;
    }

    g_auth = zactor_new(zauth, NULL);
    if (!g_auth) {
        zsys_error("Failed to initialize zauth");
        return false;
    }

    if (verbose) {
        zstr_sendx(g_auth, "VERBOSE", NULL);
        zsock_wait(g_auth);
    }

    if (streq(curve_dir, "CURVE_ALLOW_ANY")) {
        zsys_info("Certificate checking disabled; all CURVE peers allowed");
        zstr_sendx(g_auth, "CURVE", CURVE_ALLOW_ANY, NULL);
    } else {
        zsys_info("Using CURVE public keys from directory: %s", curve_dir);
        zstr_sendx(g_auth, "CURVE", curve_dir, NULL);
    }
    zsock_wait(g_auth);

    zyre_set_zap_domain(g_zyre, curve_zap_domain);
    zsys_info("CURVE ZAP domain: %s", curve_zap_domain);

    zcert_t *cert = NULL;
    if (curve_key_file) {
        zsys_info("Using CURVE private key from file: %s", curve_key_file);
        cert = zcert_load(curve_key_file);
    } else {
        zsys_warning("CURVE private key not specified");
        cert = zcert_new();
    }
    if (!cert) {
        zsys_error("Failed to create zcert");
        return false;
    }
    zyre_set_zcert(g_zyre, cert);

    return true;
}


static bool setup_database(const char *database_filename, const char *database_table)
{
    static const int SQLITE_BUSY_TIMEOUT_MS = 100;

    int rc = sqlite3_open(database_filename, &g_db);
    if (rc != SQLITE_OK) {
        printf("Unable to open file: %s\n", sqlite3_errmsg(g_db));
        return false;
    }

    if (sqlite3_busy_timeout(g_db, SQLITE_BUSY_TIMEOUT_MS) != SQLITE_OK) {
        zsys_warning("Unable to set SQLite busy timeout");
    }

    char sql_buffer[256];
    snprintf(
            sql_buffer,
            256,
            "CREATE TABLE IF NOT EXISTS \"%s\" (timestamp INTEGER, peer_uuid TEXT, peer_name TEXT, shout_group TEXT, payload BLOB)",
            database_table
            );
    rc = sqlite3_exec(g_db, sql_buffer, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        printf(
                "Failed to create table \"%s\" in database \"%s\": %s\n",
                database_table,
                database_filename,
                sqlite3_errmsg(g_db)
                );
        return false;
    }

    snprintf(
            sql_buffer,
            256,
            "INSERT INTO \"%s\" (timestamp, peer_uuid, peer_name, shout_group, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
            database_table
            );
    rc = sqlite3_prepare_v2(g_db, sql_buffer, -1, &g_insert, NULL);
    if (rc != SQLITE_OK) {
        printf(
                "Failed to prepare statement for insert: %s\n",
                sqlite3_errmsg(g_db)
              );
        return false;
    }

    return true;
}


static void handle_join_event(zyre_event_t *event)
{
    zyre_join(g_zyre, zyre_event_group(event));
    zsys_info("Updated group memberships due to JOIN event:");
    zlist_t *own_groups = zyre_own_groups(g_zyre);
    if (own_groups) {
        const char *group = zlist_first(own_groups);
        while (group) {
            zsys_info(" - %s", group);
            group = zlist_next(own_groups);
        }
        zlist_destroy(&own_groups);
    }
}


static void handle_shout_event(zyre_event_t *event)
{
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

    bool recorded_successfully = record(
            event_time,
            zyre_event_peer_uuid(event),
            zyre_event_peer_name(event),
            zyre_event_group(event),
            zframe_data(encoded_frame),
            zframe_size(encoded_frame)
          );

    if (recorded_successfully && g_stats_enabled)
        g_stats.shouts_counter++;

    zframe_destroy(&encoded_frame);
    zmsg_destroy(&msg);
}


static void handle_whisper_event(zyre_event_t *event)
{
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

    bool recorded_successfully = record(
            event_time,
            zyre_event_peer_uuid(event),
            zyre_event_peer_name(event),
            NULL,
            zframe_data(encoded_frame),
            zframe_size(encoded_frame)
          );

    if (recorded_successfully && g_stats_enabled)
        g_stats.whispers_counter++;

    zframe_destroy(&encoded_frame);
    zmsg_destroy(&msg);
}


static bool record(
        unsigned long long event_time,
        const char *peer_uuid,
        const char *peer_name,
        const char *shout_group,
        const void *payload_data,
        int payload_size
        )
{
    int rc0 = sqlite3_bind_int64(g_insert, 1, event_time);
    int rc1 = sqlite3_bind_text(g_insert, 2, peer_uuid,  -1, SQLITE_TRANSIENT);
    int rc2 = sqlite3_bind_text(g_insert, 3, peer_name, -1, SQLITE_TRANSIENT);
    int rc3;
    if (shout_group)
        rc3 = sqlite3_bind_text(g_insert, 4, shout_group, -1, SQLITE_TRANSIENT);
    else
        rc3 = sqlite3_bind_null(g_insert, 4);
    int rc4 = sqlite3_bind_blob(g_insert, 5, payload_data, payload_size, SQLITE_TRANSIENT);

    if (
           (rc0 != SQLITE_OK) 
        || (rc1 != SQLITE_OK)
        || (rc2 != SQLITE_OK)
        || (rc3 != SQLITE_OK)
        || (rc4 != SQLITE_OK)
    ) {
        zsys_error("Failed to bind all SQL parameters");
        return false;
    }

    bool recorded_successfully = false;

    int rc5 = sqlite3_step(g_insert);
    if (rc5 == SQLITE_DONE) {
        recorded_successfully = true;
    } else if (rc5 == SQLITE_ERROR) {
        recorded_successfully = false;
        zsys_error("Error occurred while executing prepared SQL statement: %s", sqlite3_errmsg(g_db));
    } else {
        recorded_successfully = false;
        zsys_error("Prepared SQL statement failed with return code %d (%s)", sqlite3_errcode(g_db), sqlite3_errmsg(g_db));
    }

    sqlite3_reset(g_insert);
    sqlite3_clear_bindings(g_insert);

    return recorded_successfully;
}


static unsigned long long get_time_in_microseconds(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((unsigned long long)(tv.tv_sec) * 1000000ULL) + (unsigned long long)(tv.tv_usec);
}


static void reset_statistics(void)
{
    g_stats.shouts_counter = 0;
    g_stats.whispers_counter = 0;

    g_stats.previous_total_counter = 0;

    g_stats.last_printout_time = get_time_in_microseconds();
}


static void print_statistics(void)
{
    unsigned long long msg_rate = (g_stats.shouts_counter + g_stats.whispers_counter) - g_stats.previous_total_counter;

    zsys_info(
            "Stats: %lld shouts, %lld whispers, %lld total, %lld /s",
            g_stats.shouts_counter,
            g_stats.whispers_counter,
            g_stats.shouts_counter + g_stats.whispers_counter,
            msg_rate
            );

    g_stats.previous_total_counter = g_stats.shouts_counter + g_stats.whispers_counter;
}
