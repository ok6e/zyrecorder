#include "utils.h"
#include <unistd.h>
#include <sys/time.h>

unsigned long long get_time_in_microseconds(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((unsigned long long)(tv.tv_sec) * 1000000ULL) + (unsigned long long)(tv.tv_usec);
}
