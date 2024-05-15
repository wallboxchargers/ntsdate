/*
 * OPTEE has access to the plugin by the UUID
 */
#define SYSLOG_PLUGIN_UUID { 0xb9d47a5e, 0x31df, 0x4955, \
        { 0xad, 0x5e, 0x6d, 0x5e, 0x76, 0xad, 0x92, 0x19} }

/* plugin cmd */
#define TO_SYSLOG_CMD 0

/* Log severities. Copied from syslog.h */
typedef enum {
 LOG_EMERG   = 0,   /* system is unusable */
 LOG_ALERT   = 1,   /* action must be taken immediately */
 LOG_CRIT    = 2,   /* critical conditions */
 LOG_ERR     = 3,   /* error conditions */
 LOG_WARNING = 4,   /* warning conditions */
 LOG_NOTICE  = 5,   /* normal but significant condition */
 LOG_INFO    = 6,   /* informational */
 LOG_DEBUG   = 7,   /* debug-level messages */
} syslogLevel;
