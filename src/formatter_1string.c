#include <zyre.h>

// The formatter MUST allocate memory from heap for the returned string.
// The returned string MUST be NULL-terminated.
// Caller is responsible for freeing the returned string.

// "1string" formatter is for single frame plain text messages.

char* formatter_1string(zmsg_t *msg)
{
    return zmsg_popstr(msg);
}
