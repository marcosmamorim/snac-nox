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
#include "auth-event.hh"

namespace vigil {

Auth_event::Auth_event(Action a, datapathid dp, uint16_t pt,
                       ethernetaddr dl, uint32_t nw, bool owns,
                       const std::string& hname, const std::string& uname,
                       uint32_t i_timeout, uint32_t h_timeout)
    : Event(static_get_name()), action(a), datapath_id(dp),
      port(pt), dladdr(dl), nwaddr(nw), owns_dl(owns),
      hostname(hname), username(uname), inactivity_timeout(i_timeout),
      hard_timeout(h_timeout), to_post(NULL)
{ }

}
