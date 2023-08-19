#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <ctype.h>
#include <zyre.h>
#include <zyre_library.h>
#include "zyrecorder_version.h"
#include "formatters.h"
#include "recorder.h"
#include "replayer.h"


enum action_t {
    ACTION_RECORD, ACTION_REPLAY
};


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
    bool    enable_stats        = false;
    int     replay_start_delay  = 2;

    char* (*formatter_func)(zmsg_t *msg) = NULL;

    printf("zyrecorder (%s)\n", ZYRECORDER_VERSION);

    int c = 0;
    while ((c = getopt(argc, argv, "hi:p:sv6c:C:z:f:d:")) != -1) {
        switch (c) {
        case 'i':
            iface = optarg;
            break;
        case 'p':
            udp_beacon_port = atoi(optarg);
            break;
        case 's':
            enable_stats = true;
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
        case 'f': {
            formatter_func = resolve_formatter_func_from_arg(optarg);
            if (formatter_func == NULL) {
                printf("Unknown formatter specified: %s\n", optarg);
                return 1;
            }
                  } break;
        case 'd':
            replay_start_delay = atoi(optarg);
            break;
        default:
            printf("Usage:\n");
            printf("  zyrecorder [options] record <file> <table> [groups...]\n");
            printf("      Records messages from a ZMQ Zyre network into an SQLite table.\n");
            printf("      SHOUT and WHISPER messages are both recorded.\n");
            printf("\n");
            printf("  zyrecorder [options] replay <file> <table>\n");
            printf("      Replay the recorded SQLite table back to the ZMQ Zyre network.\n");
            printf("      Messages are sent in chronological order based on the \"timestamp\" column.\n");
            printf("      Only SHOUT messages are sent.\n");
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
            printf("  -f <formatter>    Use <formatter> to generate pretty-printed outputs of messages\n");
            printf("                    Available formatters: 1string, nstrings\n");
            printf("  -d <seconds>      Wait before replaying to make sure all peers have been discovered first\n");
            printf("                    Default: 2 seconds\n");
            return 1;
        }
    }

    enum action_t action;

    if (optind >= argc) {
        printf("Specify either \"record\" or \"replay\" action. See -h for help.\n");
        return 1;
    } else {
        if (streq(argv[optind], "record")) {
            action = ACTION_RECORD;
        } else if (streq(argv[optind], "replay")) {
            action = ACTION_REPLAY;
        } else {
            printf("Unknown action \"%s\". See -h for help.\n", argv[optind]);
            return 1;
        }
    }
    optind++;

    if (optind >= argc) {
        printf("You must specify a database file. See -h for help.\n");
        return 1;
    } else {
        database_filename = argv[optind];
    }
    optind++;

    if (optind >= argc) {
        printf("You must specify a database table. See -h for help.\n");
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

    if (action == ACTION_RECORD) {

        recorder_t *recorder = recorder_new(ipv6, verbose, udp_beacon_port, iface);

        if (curve) {
            zsys_info("Enabling CURVE encryption");
            if (!recorder_setup_curve(recorder, curve, curve_key_file, curve_zap_domain)) {
                recorder_destroy(&recorder);
                return 1;
            }
        }

        if (!recorder_setup_database(recorder, database_filename, database_table)) {
            recorder_destroy(&recorder);
            return 1;
        }

        recorder_enable_statistics(recorder, enable_stats);
        recorder_set_formatter_func(recorder, formatter_func);

        int rc = recorder_run(recorder, argc, argv, optind);

        recorder_destroy(&recorder);
        return rc;

    } else if (action == ACTION_REPLAY) {

        replayer_t *replayer = replayer_new(ipv6, verbose, udp_beacon_port, iface, replay_start_delay);

        if (curve) {
            zsys_info("Enabling CURVE encryption");
            if (!replayer_setup_curve(replayer, curve, curve_key_file, curve_zap_domain)) {
                replayer_destroy(&replayer);
                return 1;
            }
        }

        if (!replayer_load_database(replayer, database_filename, database_table)) {
            replayer_destroy(&replayer);
            return 1;
        }

        replayer_enable_statistics(replayer, enable_stats);

        int rc = replayer_run(replayer, argc, argv, optind);

        replayer_destroy(&replayer);
        return rc;

    }

    printf("Unimplemented action\n");
    return 1;
}
