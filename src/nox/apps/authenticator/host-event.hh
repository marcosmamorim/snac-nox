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
#ifndef HOST_EVENT_HH
#define HOST_EVENT_HH 1

#include <boost/noncopyable.hpp>
#include <stdint.h>
#include <string>

#include "event.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"

/*
 * Host join/leave event.
 *
 * Advertises a host as having joined or left a location the network.  The
 * location is defined by a switch/port pair, a link layer address, and
 * optionally a network layer address.
 *
 * Currently, Authenticator only throws a host join event when the host is
 * first seen at the location, and not for each new IP seen on that host.  An
 * IP will only be included if it defines the host (when the host is located
 * behind a router).  IP information for hosts will instead need to be obtained
 * from the bindings component.
 *
 * All integer values are stored in host byte order, and should be passed in as
 * such.
 */

namespace vigil {

struct Host_event
    : public Event,
      boost::noncopyable
{
    enum Action {
        JOIN,
        LEAVE
    };

    Host_event(Action, datapathid, uint16_t,
               ethernetaddr, uint32_t, const std::string&);

    // -- only for use within python
    Host_event() : Event(static_get_name()) { }

    static const Event_name static_get_name() {
        return "Host_event";
    }

    Action        action;
    datapathid    datapath_id;
    uint16_t      port;
    ethernetaddr  dladdr;
    uint32_t      nwaddr;   // set to zero if no IP needed to define host
    std::string   name;
};

} // namespace vigil

#endif /* host-event.hh */
