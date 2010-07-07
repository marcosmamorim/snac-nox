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
#ifndef BCAST_IN_HH
#define BCAST_IN_HH 1

#include <list>
#include "flow.hh"
#include "flow-in.hh"
#include "netinet++/datapathid.hh"
#include "packet-in.hh"

/*
 * Event thrown instead of Flow_in_event when a broadcast flow is received in
 * order to provide admins with a hook to specially process bcast flows.
 * Bcast_resolve component currently listens for this event but just spawns off
 * a Flow_in_event without any special processing.
 */
namespace vigil {

struct Broadcast_in_event
    : public Event
{
    Broadcast_in_event(const Flow&,
                       const timeval&,
                       const Packet_in_event&);

    ~Broadcast_in_event() { }

    static const Event_name static_get_name() {
        return "Broadcast_in_event";
    }

    Flow flow;
    timeval received;
    ConnPtr source;
    ConnPtr route_source;
    boost::shared_ptr<std::vector<uint32_t> > src_addr_groups;
    boost::shared_ptr<std::vector<uint32_t> > dst_addr_groups;
    bool src_dl_authed;
    bool src_nw_authed;
    datapathid datapath_id;
    boost::shared_ptr<Buffer> buf;
    size_t total_len;
    uint32_t buffer_id;
    uint8_t reason;

    Broadcast_in_event(const Broadcast_in_event&);
    Broadcast_in_event& operator=(const Broadcast_in_event&);

}; // class Broadcast_in_event

} // namespace vigil

#endif // BCAST_IN_HH
