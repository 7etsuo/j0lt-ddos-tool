#ifndef RESULT_H
#define RESULT_H

typedef enum
{
    RESULT_SUCCESS,     // Indicates successful operation
    RESULT_FAIL_INIT,   // Initialization failure
    RESULT_FAIL_IO,     // Input/output failure
    RESULT_FAIL_NET,    // Network related failure
    RESULT_FAIL_ARG,    // Invalid arguments provided
    RESULT_FAIL_MEM,    // Memory allocation failure
    RESULT_FAIL_PERM,   // Permissions or access failure
    RESULT_FAIL_UNKNOWN // Unknown or unspecified error
} Result_T;

#endif // RESULT_H