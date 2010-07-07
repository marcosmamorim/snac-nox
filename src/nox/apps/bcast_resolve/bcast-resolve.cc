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
#include "bcast-resolve.hh"

#include <boost/bind.hpp>

#include "assert.hh"
#include "authenticator/flow-in.hh"

#include "authenticator/bcast-in.hh"
#include "netinet++/arp.hh"
#include "vlog.hh"

using namespace vigil;
using namespace vigil::applications;

namespace vigil {
namespace applications {

static Vlog_module lg("bcast");

Bcast_resolve::Bcast_resolve(const container::Context* c,
                             const xercesc::DOMNode*)
    : Component(c), auth(0)
{

}

Bcast_resolve::~Bcast_resolve()
{

}

void
Bcast_resolve::getInstance(const container::Context* ctxt,
                           Bcast_resolve*& r)
{
    r = dynamic_cast<Bcast_resolve*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(Bcast_resolve).name())));
}

void
Bcast_resolve::configure(const container::Configuration*)
{
    resolve(auth);

    register_handler<Broadcast_in_event>
        (boost::bind(&Bcast_resolve::handle_bcast_in, this, _1));
}

void
Bcast_resolve::install()
{

}

Disposition
Bcast_resolve::handle_bcast_in(const Event& e)
{
    const Broadcast_in_event& bi = assert_cast<const Broadcast_in_event&>(e);

//     if (bi.flow.dl_type == arp::ETHTYPE) {
//         uint64_t mac;
//         // Note: if this code is reinstated, then the following will need
//         // adjustment, because nw_dst is no longer extracted from ARP
//         // packets (for alignment with the OpenFlow spec).
//         uint32_t nw_dst = ntohl(bi.flow.nw_dst);
//         if (get_mac(nw_dst, mac)) {
//             ethernetaddr eth(mac);
//             Authenticator::HostMap::const_iterator host;
//             if (auth->get_connector(eth, nw_dst, host)) {
//                 post(new Flow_in_event(host->second, bi));
//                 return CONTINUE;
//             }
//         }
//     }

// get groups?
    Flow_in_event *fi = new Flow_in_event(bi);
    fi->dst_dl_authed = fi->dst_nw_authed = false;
    fi->destinations.resize(1);
    fi->destinations.front().allowed = true;
    ConnPtr& dst = fi->destinations.front().connector;
    dst.reset(new Connector());
    dst->location = 0;
    dst->ap = dst->host = 0;
    dst->users.push_front(user_info());
    dst->users.front().user = 0;
    post(fi);
    return CONTINUE;
}

bool
Bcast_resolve::get_mac(uint32_t ip, uint64_t& mac)
{
    lg.dbg("Bcast_resolve: Not attempting to retrieve MAC recorded for ip %u", ip);
    return false;
}

} // namespace applications
} // namespace vigil

namespace {

REGISTER_COMPONENT(container::Simple_component_factory<Bcast_resolve>,
                   Bcast_resolve);

}
