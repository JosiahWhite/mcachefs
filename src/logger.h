#ifndef LOGGER_H
#define LOGGER_H

#include "includes.h"
#include <stdarg.h>

#define MCACHEFS_LOG_SUBSYS "mCacheFS"
#define _MCACHEFS_LOG_SUBSYS " " MCACHEFS_LOG_SUBSYS
#define MCACHEFS_LOG_SUBSYS_ MCACHEFS_LOG_SUBSYS " "
#define MCACHEFS_LOG_SUBSYS__ MCACHEFS_LOG_SUBSYS ": "

enum
{
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_DEBUG = 3
};

void logger_init(BOOL console, int loglevel);
void logger_error(char *fmt, ...);
void logger_warning(char *fmt, ...);
void logger_info(char *fmt, ...);
void logger_debug(char *fmt, ...);

#endif
