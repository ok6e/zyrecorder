#include <zyre.h>

// The formatter MUST allocate memory from heap for the returned string.
// The returned string MUST be NULL-terminated.
// Caller is responsible for freeing the returned string.

// "nstrings" formatter is for multi-frame plain text strings.
// For pretty-print, a concatenated string is created with newlines
// separating the individual frames.

char* formatter_nstrings(zmsg_t *msg)
{
    if (zmsg_size(msg) == 0)
        return NULL;

    const size_t num_frames = zmsg_size(msg);

    char** frame_strings = (char**)calloc(num_frames, sizeof(char*));
    if (!frame_strings)
        return NULL;
    size_t full_length = 0;
    for (size_t i = 0; i < num_frames; ++i) {
        frame_strings[i] = zmsg_popstr(msg);
        full_length += strlen(frame_strings[i]);
        // Add one byte for newline, except for the last frame
        if (i < (num_frames - 1))
            full_length++;
    }

    char* result = (char*)calloc(full_length + 1, sizeof(char)); // add one for terminating NULL
    if (!result) {
        for (size_t i = 0; i < num_frames; ++i)
            free(frame_strings[i]);
        free(frame_strings);
        return NULL;
    }

    for (size_t i = 0; i < num_frames; ++i) {
        strcat(result, frame_strings[i]);
        // Add newline, except for the last frame
        if (i < (num_frames - 1))
            strcat(result, "\n");
    }

    for (size_t i = 0; i < num_frames; ++i)
        free(frame_strings[i]);
    free(frame_strings);

    return result;
}
