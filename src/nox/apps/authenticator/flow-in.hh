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
#ifndef FLOW_IN_HH
#define FLOW_IN_HH 1

#include <list>
#include <sys/time.h>
#include <vector>
#include "flow.hh"
#include "packet-in.hh"
#include "pyrt/pyglue.hh"

/*
 * Flow-in event.  Posted when a new flow request comes up to the Controller.
 * Endpoints have been associated with their principals in the form of
 * Connector objects.  Because no access point information is known about the
 * destination, more than one Connector may be associated with the destination
 * if the adresses have been authenticated at multiple locations.  src/dst
 * dl/nw_authed signals which addresses have been authenticated and were thus
 * used to find the Connector record(s).  If for example a flow sender's IP
 * address has not been authenticated, but its MAC address has, a Flow-in event
 * could be created with the Connector record for just that MAC address and
 * 'src_nw_authed' set to false to signal that the IP address has not been
 * authenticated.  Likewise, if neither a flow's MAC or IP addresses has been
 * bound, the Connector object for the sender's AP alone can be passed in with
 * src_dl_authed/nw_authed == false.  As of right now, there shouldn't be any
 * scenarios where src/dst_nw_authed == true and src/dst_dl_authed == false.
 * The one subtlety is that if src_dl_authed == true, even if the destination
 * addresses have not been authenticated, their static bindings will be looked
 * up to obtain some idea of who the source is trying to connect to in order to
 * evaluate policy more accurately.  Here dst_dl/nw_authed will still be set to
 * false.
 *
 * The 'Flow' struct itself currently stores values in network byte order (will
 * eventually change?), however all other other integer values are stored in
 * host byte order, and should be passed in as such.
 *
 * The active attribute signals whether or not the flow should still be
 * considered as a valid flow request in the system.  It serves as a fast check
 * for critical components wanting to act only on flows of this type.  This
 * attribute could show up as false if a policy function has consumed the flow,
 * or sepl has been configured to enforce policy and none of the flow's
 * destinations were permitted.
 */

namespace vigil {

/*
 * Connector Object Description:
 * -----------------------------
 * location:        switch/port location of Connector - upper 16 bits are port,
 *                  lower 48 are datapathid
 * ap, host:        principals in the ID form defined in authenticator.cc
 * hostgroups:      Groups the AP + host are a member of
 * users:           Users logged on to the machine along with the groups they
 *                  are a member of.
 * n_bindings       Num bindings pointing to this location (for correct Host
 *                  leave event postings).
 * last_active:     Time of last activity for host
 * hard_timeout:    Hard timeout for host.
 * inactivity_len:  Seconds of inactivity after which host will timeout
 */

struct user_info {
    uint32_t user;
    std::vector<uint32_t> groups;
};

struct Connector {
    uint64_t location;
    bool is_internal;
    uint32_t ap;
    uint32_t host;
    std::vector<uint32_t> hostgroups;
    std::list<user_info> users;
    uint32_t n_bindings;
    time_t last_active;
    time_t hard_timeout;
    uint32_t inactivity_len;
};

typedef boost::shared_ptr<Connector> ConnPtr;
typedef std::list<ConnPtr> ConnList;

struct Broadcast_in_event;

struct Flow_in_event
    : public Event
{
    Flow_in_event(const Flow& flow_,
                  const timeval& received_,
                  const Packet_in_event& pi);

    Flow_in_event(const Broadcast_in_event&);

    Flow_in_event() : Event(static_get_name()) { }

    ~Flow_in_event() { }

    static const Event_name static_get_name() {
        return "Flow_in_event";
    }

    static const uint32_t NOT_ROUTED = UINT32_MAX - 1;
    static const uint32_t BROADCASTED = UINT32_MAX;

    struct DestinationInfo {
        ConnPtr connector;
        bool allowed;
        std::vector<uint32_t> waypoints;
        hash_set<uint32_t> rules;
    };

    typedef std::vector<DestinationInfo> DestinationList;

    Flow flow;
    bool active;  // If flow can still be "acted" upon or it has been consumed
                  // by some part of the system.
    bool fn_applied;  // If a function consumed the flow.
    timeval received;
    ConnPtr source;
    ConnPtr route_source;
    DestinationList destinations;
    ConnList route_destinations; // if populated, dest locations for routing,
                                 // else 'destinations' locations used.
    uint32_t routed_to;          // idx of dest location used to route flow in
                                 // either 'route_destinations' or 'destinations'
    boost::shared_ptr<std::vector<uint32_t> > src_addr_groups;
    boost::shared_ptr<std::vector<uint32_t> > dst_addr_groups;
    bool src_dl_authed;
    bool src_nw_authed;
    bool dst_dl_authed;
    bool dst_nw_authed;
    datapathid datapath_id;
    boost::shared_ptr<Buffer> buf;
    size_t total_len;
    uint32_t buffer_id;
    uint8_t reason;

    Flow_in_event(const Flow_in_event&);
    Flow_in_event& operator=(const Flow_in_event&);

    void set_destination_list(const ConnList& conns);

}; // class Flow_in_event

#ifdef TWISTED_ENABLED

PyObject*
route_source_to_python(const ConnPtr&);

PyObject*
route_destinations_to_python(const ConnList&);

#endif

} // namespace vigil

#endif // FLOW_IN_HH
