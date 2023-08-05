#pragma once

#include <zyre.h>

char* formatter_1string(zmsg_t *msg);
char* formatter_nstrings(zmsg_t *msg);

char* (*resolve_formatter_func_from_arg(const char *arg))(zmsg_t *msg)
{
    if (streq(arg, "1string")) {
        return &formatter_1string;
    } else if (streq(arg, "nstrings")) {
        return &formatter_nstrings;
    }
    return NULL;
}
