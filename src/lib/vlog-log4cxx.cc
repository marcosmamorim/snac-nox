/* Copyright 2008 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "vlog.hh"

#include <cstdarg>
#include "log4cxx/logger.h"

using namespace vigil;

static const int LOG_BUFFER_LEN = 2048;

::log4cxx::LevelPtr
Vlog::LEVEL_EMER = ::log4cxx::Level::getFatal();

::log4cxx::LevelPtr
Vlog::LEVEL_ERR = ::log4cxx::Level::getError();

::log4cxx::LevelPtr
Vlog::LEVEL_WARN = ::log4cxx::Level::getWarn();

::log4cxx::LevelPtr
Vlog::LEVEL_INFO = ::log4cxx::Level::getInfo();

::log4cxx::LevelPtr
Vlog::LEVEL_DBG = ::log4cxx::Level::getDebug();

#define VLOG_FORMAT()                                   \
    va_list args;                                       \
    va_start(args, format);                             \
    char msg[LOG_BUFFER_LEN];                           \
    ::vsnprintf(msg, sizeof msg, format, args);         \
    va_end(args);

namespace vigil {

Vlog&
vlog()
{
    static Vlog* the_vlog = new Vlog();
    return *the_vlog;
}

}

void
Vlog::log(Module module, Level level, const char *format, ...)
{
    if (module->isEnabledFor(level)) {
        VLOG_FORMAT();
        module->forcedLog(level, msg, LOG4CXX_LOCATION);
    }
}

Vlog::Module
Vlog::get_module_val(const char* name, bool create)
{
    return log4cxx::Logger::getLogger(name);
}

Vlog_module::Vlog_module(const char *module_name)
    : logger(log4cxx::Logger::getLogger(module_name))
{

}

Vlog_module::~Vlog_module()
{

}

void Vlog_module::emer(const char *format, ...)
{
    if (logger->isFatalEnabled()) {
        VLOG_FORMAT();
        logger->forcedLog(::log4cxx::Level::getFatal(), msg, LOG4CXX_LOCATION);
    }
}

void Vlog_module::err(const char *format, ...)
{
    if (logger->isErrorEnabled()) {
        VLOG_FORMAT();
        logger->forcedLog(::log4cxx::Level::getError(), msg, LOG4CXX_LOCATION);
    }
}

void Vlog_module::warn(const char *format, ...)
{
    if (logger->isWarnEnabled()) {
        VLOG_FORMAT();
        logger->forcedLog(::log4cxx::Level::getWarn(), msg, LOG4CXX_LOCATION);
    }
}

void Vlog_module::info(const char *format, ...)
{
    if (logger->isInfoEnabled()) {
        VLOG_FORMAT();
        logger->forcedLog(::log4cxx::Level::getInfo(), msg, LOG4CXX_LOCATION);
    }
}

void Vlog_module::dbg(const char *format, ...)
{
    if (logger->isDebugEnabled()) {
        VLOG_FORMAT();
        logger->forcedLog(::log4cxx::Level::getDebug(), msg, LOG4CXX_LOCATION);
    }
}
