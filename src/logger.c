#include "logger.h"
#include "includes.h"
#include "utils.h"
#include <syslog.h>

static BOOL logger_console = TRUE;
static int logger_level = LOG_LEVEL_ERROR;

void logger_init(BOOL console, int loglevel)
{
    logger_console = console;
    logger_level = loglevel;
}

void logger_error(char *fmt, ...)
{
    char pre_fmt[512];
    snprintf(pre_fmt, 512, MCACHEFS_LOG_SUBSYS_ "ERROR: %s%s", fmt, logger_console ? "\n" : "");

    va_list arguments;
    va_start(arguments, fmt);

    if (logger_console)
        vfprintf(stderr, pre_fmt, arguments);
    else
        vsyslog(LOG_ERR, pre_fmt, arguments);

    va_end(arguments);

    exit(-1);
}

void logger_warning(char *fmt, ...)
{
    if (logger_level < LOG_LEVEL_WARN)
        return;

    char pre_fmt[512];
    snprintf(pre_fmt, 512, MCACHEFS_LOG_SUBSYS_ "WARNING: %s%s", fmt, logger_console ? "\n" : "");

    va_list arguments;
    va_start(arguments, fmt);

    if (logger_console)
        vfprintf(stderr, pre_fmt, arguments);
    else
        vsyslog(LOG_ERR, pre_fmt, arguments);

    va_end(arguments);
}

void logger_info(char *fmt, ...)
{
    if (logger_level < LOG_LEVEL_INFO)
        return;

    char pre_fmt[512];
    snprintf(pre_fmt, 512, MCACHEFS_LOG_SUBSYS_ "INFO: %s%s", fmt, logger_console ? "\n" : "");

    va_list arguments;
    va_start(arguments, fmt);

    if (logger_console)
        vfprintf(stderr, pre_fmt, arguments);
    else
        vsyslog(LOG_ERR, pre_fmt, arguments);

    va_end(arguments);
}

void logger_debug(char *fmt, ...)
{
    if (logger_level < LOG_LEVEL_DEBUG)
        return;

    char pre_fmt[512];
    snprintf(pre_fmt, 512, MCACHEFS_LOG_SUBSYS_ "DEBUG: %s%s", fmt, logger_console ? "\n" : "");

    va_list arguments;
    va_start(arguments, fmt);

    if (logger_console)
        vfprintf(stderr, pre_fmt, arguments);
    else
        vsyslog(LOG_ERR, pre_fmt, arguments);

    va_end(arguments);
}
