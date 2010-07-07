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
#include "resolver.hh"
#include <cerrno>
#include <netdb.h>
#include "netinet++/ipaddr.hh"
#include "vlog.hh"

namespace vigil {

static Vlog_module log("resolver");

void get_host_by_name(const std::string& name, Get_host_by_name_cb cb)
{
    in_addr a;
    if (inet_aton(name.c_str(), &a)) {
        cb(0, ntohl(a.s_addr));
    } else {
        // FIXME: need to be asynchronous
        struct hostent* he = gethostbyname2(name.c_str(), AF_INET);
        if (!he) {
            log.warn("%s: gethostbyname: %s", name.c_str(),
                     h_errno == HOST_NOT_FOUND ? "host not found"
                     : h_errno == TRY_AGAIN ? "try again"
                     : h_errno == NO_RECOVERY ? "unrecoverable error"
                     : h_errno == NO_ADDRESS ? "host has no address"
                     : "unknown error");
            cb((h_errno == HOST_NOT_FOUND ? ENOENT
                : h_errno == TRY_AGAIN ? EINTR
                : h_errno == NO_RECOVERY ? EIO
                : h_errno == NO_ADDRESS ? ENODEV
                : EINVAL), ipaddr());
        } else {
            cb(0, ntohl(*(uint32_t*) he->h_addr));
        }
    }
}

} // namespace vigil
