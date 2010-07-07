/* Copyright 2008, 2009 (C) Nicira, Inc.
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
#include "authenticator.hh"

#include <boost/bind.hpp>
#include <inttypes.h>

#include "kernel.hh"
#include "assert.hh"
#include "bcast-in.hh"
#include "bindings_storage/bindings_storage.hh"
#include "bootstrap-complete.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "directory/group_change_event.hh"
#include "directory/group_event.hh"
#include "directory/location_del_event.hh"
#include "directory/netinfo_mod_event.hh"
#include "directory/principal_event.hh"
#include "discovery/link-event.hh"
#include "net/ethernet.h"
#include "flow_util.hh"
#include "host-event.hh"
#include "port-status.hh"
#include "user-event.hh"
#include "vlog.hh"
#include "openflow-default.hh"

#define DP_MASK         0xffffffffffffULL
#define NAME_TIMEOUT    120
#define ADDR_TIMEOUT    120
#define HOST_TIMEOUT    300
#define TIMER_INTERVAL  30

#define UNAUTHENTICATED_NAME   "discovered;unauthenticated"
#define AUTHENTICATED_NAME     "discovered;authenticated"
#define UNKNOWN_NAME           "discovered;unknown"

#define SWITCH_GROUP           "discovered;switch_management_ports"

#define EMPTY_PRINCE     ((Directory::Principal_Type)UINT32_MAX)
#define EMPTY_GROUP      ((Directory::Group_Type)UINT32_MAX)

#define LOC_FROM_DP_PORT(dp, pt) ((dp).as_host() + (((uint64_t)(pt)) << 48))

namespace vigil {
namespace applications {

static Vlog_module lg("authenticator");
static const std::string app_name("authenticator");

static const datapathid zero_dp = datapathid::from_host(0);

const uint32_t Authenticator::UNAUTHENTICATED_ID;
const uint32_t Authenticator::AUTHENTICATED_ID;
const uint32_t Authenticator::UNKNOWN_ID;
const uint32_t Authenticator::START_ID;

Authenticator::Authenticator(const container::Context* c,
                             const xercesc::DOMNode*)
    : Component(c), bindings(0), dirmanager(0),
      topology(0), user_log(0), expire_timer(TIMER_INTERVAL),
      default_host_timeout(HOST_TIMEOUT), lookup_unauth_dst(true),
      counter(START_ID), raw_of(new uint8_t[sizeof *ofm])
{
    reset_names();

    unauth_sw_groups.status.locked = false;
    unauth_sw_groups.id = UNAUTHENTICATED_ID;
    unauth_loc_groups.status.locked = false;
    unauth_loc_groups.id = UNAUTHENTICATED_ID;
    unauth_host_groups.status.locked = false;
    unauth_host_groups.id = UNAUTHENTICATED_ID;
    unauth_user_groups.status.locked = false;
    unauth_user_groups.id = UNAUTHENTICATED_ID;

    host_info.netinfos.push_back(directory::NetInfo());
    switchkey.insert("dpid");
    lockey.insert("dpid");
    lockey.insert("port");
    dlkey.insert("dladdr");
    nwkey.insert("nwaddr");

    ofm = (ofp_flow_mod*) raw_of.get();
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(sizeof *ofm);
    ofm->header.xid = 0;
    ofm->cookie = 0;
    ofm->command = htons(OFPFC_DELETE);
    ofm->idle_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->out_port = htons(OFPP_NONE);
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
    ofm->flags = htons(ofd_flow_mod_flags());
}

void
Authenticator::getInstance(const container::Context* ctxt,
                           Authenticator*& h)
{
    h = dynamic_cast<Authenticator*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(Authenticator).name())));
}

void
Authenticator::configure(const Configuration*)
{
    resolve(bindings);
    resolve(dirmanager);
    resolve(topology);
    resolve(routing_mod);
    resolve(user_log);

    register_event(Auth_event::static_get_name());
    register_event(Host_event::static_get_name());
    register_event(User_event::static_get_name());

    register_handler<Bootstrap_complete_event>
        (boost::bind(&Authenticator::handle_bootstrap, this, _1));
    register_handler<Datapath_join_event>
        (boost::bind(&Authenticator::handle_datapath_join, this, _1));
    register_handler<Datapath_leave_event>
        (boost::bind(&Authenticator::handle_data_leave, this, _1));
    register_handler<Port_status_event>
        (boost::bind(&Authenticator::handle_port_status, this, _1));
    register_handler<Link_event>
        (boost::bind(&Authenticator::handle_link_change, this, _1));
    register_handler<Auth_event>
        (boost::bind(&Authenticator::handle_auth, this, _1));
    register_handler<Packet_in_event>
        (boost::bind(&Authenticator::handle_packet_in, this, _1));
    register_handler<Principal_name_event>
        (boost::bind(&Authenticator::rename_principal, this, _1));
    register_handler<Location_delete_event>
        (boost::bind(&Authenticator::delname_location, this, _1));
    register_handler<Group_name_event>
        (boost::bind(&Authenticator::rename_group, this, _1));
    register_handler<Group_change_event>
        (boost::bind(&Authenticator::modify_group, this, _1));
    register_handler<NetInfo_mod_event>
        (boost::bind(&Authenticator::handle_netinfo_change, this, _1));
}

void
Authenticator::install()
{
    Flow_util *flow_util;
    resolve(flow_util);
    flow_util->fns.register_function("authenticate_host",
                                     boost::bind(&Authenticator::auth_host, this, _1));
    timeval tv = { expire_timer, 0 };
    post(boost::bind(&Authenticator::remove_expired_hosts, this), tv);
}

const std::string&
Authenticator::get_authenticated_name()
{
    static const std::string name(AUTHENTICATED_NAME);
    return name;
}

const std::string&
Authenticator::get_unauthenticated_name()
{
    static const std::string name(UNAUTHENTICATED_NAME);
    return name;
}

const std::string&
Authenticator::get_unknown_name()
{
    static const std::string name(UNKNOWN_NAME);
    return name;
}

// Mangling suffixes

static const char *switch_s    = "_s";
static const char *location_s  = "_l";
static const char *host_s      = "_h";
static const char *user_s      = "_u";

static const char *switch_gs   = "_sg";
static const char *location_gs = "_lg";
static const char *host_gs     = "_hg";
static const char *user_gs     = "_ug";
static const char *dladdr_gs   = "_dg";
static const char *nwaddr_gs   = "_ng";

static const char *empty_s     = "";

inline
const char *
get_suffix(const std::string& name, Directory::Principal_Type ptype,
           Directory::Group_Type gtype, bool is_principal)
{
    if (is_principal) {
        if (name == UNAUTHENTICATED_NAME || name == AUTHENTICATED_NAME || name == UNKNOWN_NAME) {
            return "";
        }
        switch (ptype) {
        case Directory::SWITCH_PRINCIPAL:
            return switch_s;
        case Directory::LOCATION_PRINCIPAL:
            return location_s;
        case Directory::HOST_PRINCIPAL:
            return host_s;
        case Directory::USER_PRINCIPAL:
            return user_s;
        default:
            VLOG_ERR(lg, "Cannot mangled unknown principal type %u.", ptype);
        }
    } else {
        switch (gtype) {
        case Directory::SWITCH_PRINCIPAL_GROUP:
            return switch_gs;
        case Directory::LOCATION_PRINCIPAL_GROUP:
            return location_gs;
        case Directory::HOST_PRINCIPAL_GROUP:
            return host_gs;
        case Directory::USER_PRINCIPAL_GROUP:
            return user_gs;
        case Directory::DLADDR_GROUP:
            return dladdr_gs;
        case Directory::NWADDR_GROUP:
            return nwaddr_gs;
        default:
            VLOG_ERR(lg, "Cannot mangled unknown grouptype %u.", gtype);
        }
    }
    return empty_s;
}


bool
Authenticator::rename(const std::string& old_name, const std::string& new_name,
                      Directory::Principal_Type ptype,
                      Directory::Group_Type gtype, bool is_principal)
{
    std::string old_mangled = old_name + get_suffix(old_name, ptype, gtype, is_principal);
    std::string new_mangled;

    NameMap::iterator found = names.find(old_mangled);
    if (found == names.end()) {
        return false;
    }

    if (new_name != "") {
        new_mangled = new_name + get_suffix(new_name, ptype, gtype, is_principal);
        if (new_mangled == old_mangled) {
            return false;
        }

        uint32_t id = found->second;
        NameMap::iterator name = names.find(new_mangled);
        if (name != names.end()) {
            VLOG_WARN(lg, "Rename to existing name %s.", new_mangled.c_str());
            name->second = id;
        } else {
            names[new_mangled] = id;
        }

        names.erase(old_mangled);
        ids[id].name = new_name;
    }
    return true;
}

uint32_t
Authenticator::get_id(const std::string& name, Directory::Principal_Type ptype,
                      Directory::Group_Type gtype, bool is_principal, bool incr)
{
    NameMap::const_iterator found = names.find(name);
    if (found != names.end() && found->second < START_ID) {
        return found->second;
    }

    const char *suffix = get_suffix(name, ptype, gtype, is_principal);
    std::string mangled = name + suffix;

    found = names.find(mangled);
    if (found != names.end()) {
        uint32_t id = found->second;
        if (incr) {
            ++(ids[id].refcount);
        } else {
            ids[id].expire += NAME_TIMEOUT; // in case refcount is set to zero
        }
        return id;
    }

    uint32_t loop = counter;
    do {
        if (ids.find(counter) == ids.end()) {
            names[mangled] = counter;
            if (incr) {
                ids[counter] = IDEntry(1, 0, name, suffix);
            } else {
                timeval curtime = { 0, 0 };
                gettimeofday(&curtime, NULL);
                ids[counter] = IDEntry(0, curtime.tv_sec + NAME_TIMEOUT, name, suffix);
            }
            if (counter == UINT32_MAX) {
                counter = START_ID;
                return UINT32_MAX;
            }
            return counter++;
        }
        if (counter == UINT32_MAX) {
            counter = START_ID;
        } else {
            ++counter;
        }
    } while (loop != counter);

    VLOG_ERR(lg, "No more name IDs to allocate, returning AUTHENTICATED_ID.");
    return AUTHENTICATED_ID;
}

const std::string&
Authenticator::get_name(uint32_t id) const
{
    IDMap::const_iterator name = ids.find(id);
    if (name != ids.end()) {
        return name->second.name;
    }
    VLOG_DBG(lg, "No name stored under id %"PRIu32", returning unknown name.", id);
    return get_unknown_name();
}

bool
Authenticator::get_principal_type(uint32_t id, Directory::Principal_Type& ptype) const
{
    IDMap::const_iterator entry = ids.find(id);
    if (entry != ids.end()) {
        const char *s = entry->second.suffix;
        if (s == switch_s) {
            ptype = Directory::SWITCH_PRINCIPAL;
        } else if (s == location_s) {
            ptype = Directory::LOCATION_PRINCIPAL;
        } else if (s == host_s) {
            ptype = Directory::HOST_PRINCIPAL;
        } else if (s == user_s) {
            ptype = Directory::USER_PRINCIPAL;
        } else {
            return false;
        }
        return true;
    }
    return false;
}

bool
Authenticator::get_group_type(uint32_t id, Directory::Group_Type& gtype) const
{
    IDMap::const_iterator entry = ids.find(id);
    if (entry != ids.end()) {
        const char *s = entry->second.suffix;
        if (s == switch_gs) {
            gtype = Directory::SWITCH_PRINCIPAL_GROUP;
        } else if (s == location_gs) {
            gtype = Directory::LOCATION_PRINCIPAL_GROUP;
        } else if (s == host_gs) {
            gtype = Directory::HOST_PRINCIPAL_GROUP;
        } else if (s == user_gs) {
            gtype = Directory::USER_PRINCIPAL_GROUP;
        } else if (s == dladdr_gs) {
            gtype = Directory::DLADDR_GROUP;
        } else if (s == nwaddr_gs) {
            gtype = Directory::NWADDR_GROUP;
        } else {
            return false;
        }
        return true;
    }
    return false;
}

void
Authenticator::increment_id(uint32_t id)
{
    if (id < START_ID) {
        return;
    }

    IDMap::iterator entry = ids.find(id);
    if (entry == ids.end()) {
        VLOG_ERR(lg, "increment_id: ID %"PRIu32" does not exist in IDMap.", id);
        return;
    }

    // check for MAX?
    ++entry->second.refcount;
}


void
Authenticator::decrement_id(uint32_t id)
{
    if (id < START_ID) {
        return;
    }

    IDMap::iterator entry = ids.find(id);
    if (entry == ids.end()) {
        VLOG_ERR(lg, "decrement_id: ID %"PRIu32" does not exists in IDMap.", id);
        return;
    } else if (entry->second.refcount == 0) {
        VLOG_ERR(lg, "decrement_id: ID %"PRIu32" already at refcount == 0.", id);
        entry->second.expire += NAME_TIMEOUT;
        return;
    }

    if (--(entry->second.refcount) == 0) {
        timeval curtime = { 0, 0 };
        gettimeofday(&curtime, NULL);
        entry->second.expire = curtime.tv_sec + NAME_TIMEOUT;
    }
}


void
Authenticator::increment_ids(const std::list<uint32_t>& ids)
{
    for (std::list<uint32_t>::const_iterator iter = ids.begin();
         iter != ids.end(); ++iter)
    {
        increment_id(*iter);
    }
}


void
Authenticator::decrement_ids(const std::list<uint32_t>& ids)
{
    for (std::list<uint32_t>::const_iterator iter = ids.begin();
         iter != ids.end(); ++iter)
    {
        decrement_id(*iter);
    }
}


void
Authenticator::decrement_ids(const std::vector<uint32_t>& ids)
{
    for (std::vector<uint32_t>::const_iterator iter = ids.begin();
         iter != ids.end(); ++iter)
    {
        decrement_id(*iter);
    }
}


void
Authenticator::decrement_conn(const ConnPtr& conn)
{
    decrement_id(conn->ap);
    decrement_id(conn->host);
    decrement_ids(conn->hostgroups);
    for (std::list<user_info>::const_iterator iter = conn->users.begin();
         iter != conn->users.end(); ++iter)
    {
        decrement_id(iter->user);
        decrement_ids(iter->groups);
    }
}


void
Authenticator::reset_names()
{
    names.clear();
    ids.clear();
    names[get_unauthenticated_name()] = UNAUTHENTICATED_ID;
    ids[UNAUTHENTICATED_ID] = IDEntry(1, 0, get_unauthenticated_name(), empty_s);
    names[get_authenticated_name()] = AUTHENTICATED_ID;
    ids[AUTHENTICATED_ID] = IDEntry(1, 0, get_authenticated_name(), empty_s);
    names[get_unknown_name()] = UNKNOWN_ID;
    ids[UNKNOWN_ID] = IDEntry(1, 0, get_unknown_name(), empty_s);
    counter = START_ID;
}


// Exposes methods to reset expiration times of hosts.  Returns true if
// Connector found, else false.

void
Authenticator::set_host_timeout(const datapathid& dpid, uint16_t port,
                                const ethernetaddr& dladdr, uint32_t nwaddr,
                                uint32_t sec, bool set_inactivity)
{
    HostMap::iterator dlconns;
    NWMap::iterator nwconns;
    ConnList::iterator conn;

    bool found = get_conn(LOC_FROM_DP_PORT(dpid, port), dladdr.hb_long(),
                          nwaddr, dlconns, nwconns, conn);
    if (dlconns != hosts.end() && dlconns->second.status.locked) {
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::set_host_timeout,
                        this, dpid, port, dladdr, nwaddr, sec, set_inactivity));
        return;
    } else if (found) {
        if (set_inactivity) {
            (*conn)->inactivity_len = sec;
        } else {
            timeval curtime = { 0, 0 };
            gettimeofday(&curtime, NULL);
            (*conn)->hard_timeout = curtime.tv_sec + sec;
        }
    }
}

void
Authenticator::reset_last_active(const datapathid& dpid, uint16_t port,
                                 const ethernetaddr& dladdr, uint32_t nwaddr)
{
    HostMap::iterator dlconns;
    NWMap::iterator nwconns;
    ConnList::iterator conn;

    bool found = get_conn(LOC_FROM_DP_PORT(dpid, port), dladdr.hb_long(),
                          nwaddr, dlconns, nwconns, conn);
    if (dlconns != hosts.end() && dlconns->second.status.locked) {
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::reset_last_active,
                        this, dpid, port, dladdr, nwaddr));
        return;
    } else if (found) {
        timeval curtime = { 0, 0 };
        gettimeofday(&curtime, NULL);
        (*conn)->last_active = curtime.tv_sec;
    }
}

void
Authenticator::unlock_status(UpdateStatus *status)
{
    status->locked = false;
    std::list<EmptyCb> cbs;
    cbs.swap(status->waiters);
    while (!cbs.empty()) {
        cbs.front()();
        cbs.pop_front();
    }
}

void
Authenticator::post_event(Event *event)
{
    post(event);
}

Disposition
Authenticator::handle_bootstrap(const Event& e)
{
    auto_auth_hosts = ctxt->get_kernel()->get("sepl_enforcer",
                                              INSTALLED) == NULL;
    const std::string& name = get_unauthenticated_name();
    get_info_groups(&unauth_sw_groups, name, Directory::SWITCH_PRINCIPAL);
    get_info_groups(&unauth_loc_groups, name, Directory::LOCATION_PRINCIPAL);
    get_info_groups(&unauth_host_groups, name, Directory::HOST_PRINCIPAL);
    get_info_groups(&unauth_user_groups, name, Directory::USER_PRINCIPAL);
    return CONTINUE;
}

void
Authenticator::remove_src_location(const ethernetaddr& dladdr) {
    HostMap::iterator dlconns;
    NWMap::iterator nwconns;

    uint64_t dl_hb = dladdr.hb_long();
    dlconns = hosts.find(dl_hb);
    if (dlconns == hosts.end()) {
        return;
    }
    VLOG_ERR(lg, "Forgetting MAC address %"PRIx64" registered at %d locations.", dl_hb, dlconns->second.nws.size());
    NWMap::iterator ip(dlconns->second.nws.begin());
    for (; ip != dlconns->second.nws.end(); ++ip) {
        if (ip->first != 0) {
            for (ConnList::iterator loc = ip->second.conns.begin();
                    loc != ip->second.conns.end(); ++loc)
            {
                // We need to poison if someone is flapping between APs
                // while doing DHCP
                post_leave(dlconns, ip, loc, true, " (MAC leave)");
            }
        }
    }
}

// Packet-in handler.  Associates packet with store Connectors

Disposition
Authenticator::handle_packet_in(const Event& e)
{
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);

    Flow flow(htons(pi.in_port), *(pi.buf));
    if (flow.dl_type == ethernet::LLDP) {
        return CONTINUE;
    }

    EventCb empty;
    timeval cur_time = { 0 , 0 };
    gettimeofday(&cur_time, NULL);

    if (flow.dl_dst.is_broadcast() || flow.dl_dst.is_multicast()) {
        //To address the DHCP issue where reply is sent to old location
        if ((flow.nw_src == 0) && (ntohs(flow.dl_type) == ETHERTYPE_IP)) {
            remove_src_location(flow.dl_src);
        }
        set_flow_in(new Broadcast_in_event(flow, cur_time, pi), empty);
    } else {
        set_flow_in(new Flow_in_event(flow, cur_time, pi), empty);
    }
    return CONTINUE;
}

void
Authenticator::set_flow_in(Event *event, const EventCb& cb)
{
    Flow_in_event *fi = dynamic_cast<Flow_in_event*>(event);
    HostMap::iterator dlconns;
    NWMap::iterator nwconns;
    if (fi == NULL) {
        Broadcast_in_event *bi = static_cast<Broadcast_in_event*>(event);
        if (bi->source == NULL ) {
            if (!get_addr_conns(bi->flow.dl_src, ntohl(bi->flow.nw_src),
                                dlconns, nwconns, bi, cb))
            {
                return;
            }
            bi->src_addr_groups = nwconns->second.addr_groups;
            if (!set_flow_src_conn(bi->datapath_id, ntohs(bi->flow.in_port),
                                   bi->flow.dl_src, bi->received.tv_sec, dlconns,
                                   nwconns, bi->source, bi->route_source,
                                   bi->src_addr_groups, bi->src_dl_authed,
                                   bi->src_nw_authed, bi, cb))
            {
                return;
            }
        }

        if (bi->dst_addr_groups == NULL) {
            if (!get_addr_conns(bi->flow.dl_dst, ntohl(bi->flow.nw_dst),
                                dlconns, nwconns, bi, cb))
            {
                return;
            }
            bi->dst_addr_groups = nwconns->second.addr_groups;
        }
        if (cb.empty()) {
            post(event);
        } else {
            cb(event);
        }
        return;
    }

    if (fi->source == NULL) {
        if (!get_addr_conns(fi->flow.dl_src, ntohl(fi->flow.nw_src),
                            dlconns, nwconns, fi, cb))
        {
            return;
        }

        fi->src_addr_groups = nwconns->second.addr_groups;
        if (!set_flow_src_conn(fi->datapath_id, ntohs(fi->flow.in_port),
                               fi->flow.dl_src, fi->received.tv_sec, dlconns, nwconns,
                               fi->source, fi->route_source, fi->src_addr_groups,
                               fi->src_dl_authed, fi->src_nw_authed, fi, cb))
        {
            return;
        }
    }

    if (fi->destinations.empty()) {
        if (!get_addr_conns(fi->flow.dl_dst, ntohl(fi->flow.nw_dst),
                            dlconns, nwconns, fi, cb))
        {
            return;
        }

        fi->dst_addr_groups = nwconns->second.addr_groups;
        if (!set_flow_dst_conn(dlconns, nwconns, fi->src_dl_authed, fi, cb)) {
            return;
        }
    }

    if (cb.empty()) {
        post(event);
    } else {
        cb(event);
    }
}

bool
Authenticator::get_addr_conns(const ethernetaddr& dladdr, uint32_t nwaddr,
                              HostMap::iterator& dlconns,
                              NWMap::iterator& nwconns, Event *to_post,
                              const EventCb& cb)
{
    uint64_t dl_hb = dladdr.hb_long();
    dlconns = hosts.find(dl_hb);
    bool new_dl = false;
    if (dlconns == hosts.end()) {
        new_dl = true;
        dlconns = hosts.insert(std::make_pair(dl_hb, DLEntry())).first;
        dlconns->second.status.locked = true;
    }

    if (dlconns->second.status.locked) {
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::set_flow_in, this, to_post, cb));
        VLOG_DBG(lg, "Queuing flow-in for locked dlconns "
                 "dl:%"PRIx64" nw:%"PRIx32".", dl_hb, nwaddr);
        if (new_dl) {
            new_dl_entry(dlconns, dladdr, true);
        }
        return false;
    }

    if (nwaddr != 0 && dlconns->second.router && !is_internal_ip(nwaddr)) {
        if (dlconns->second.zero != NULL) {
            nwconns = dlconns->second.nws.find(0);
            return true;
        }
        nwaddr = 0;
    }

    nwconns = dlconns->second.nws.find(nwaddr);
    if (nwconns != dlconns->second.nws.end()) {
        return true;
    }

    nwconns = dlconns->second.nws.insert(std::make_pair(nwaddr, NWEntry())).first;
    dlconns->second.status.locked = true;
    dlconns->second.status.waiters.push_back(
        boost::bind(&Authenticator::set_flow_in, this, to_post, cb));
    VLOG_DBG(lg, "Queuing flow-in for new addr groups "
             "dl:%"PRIx64" nw:%"PRIx32".", dl_hb, nwaddr);
    new_nw_entry(dlconns, nwconns, dladdr, true);
    return false;
}


void
Authenticator::make_primary(const ethernetaddr& dladdr, uint32_t nwaddr,
                            const time_t& cur_time,
                            NWEntry& nwentry,
                            ConnList::iterator& citer,
                            bool wildcard_nw)
{
    (*citer)->last_active = cur_time;
    ConnList& conns = nwentry.conns;
    if ((*citer)->is_internal) {
        for (ConnList::iterator ins = conns.begin(); ins != conns.end(); ++ins) {
            if ((*ins)->is_internal) {
                if (citer != ins) {
                    // want to poison here?!
                    conns.splice(ins, conns, citer);
                }
                break;
            }
        }
    } else {
        ConnList::iterator begin(conns.begin());
        if (citer != begin) {
            if (!is_internal_mac(dladdr.hb_long())) {
                poison_ap(*begin, dladdr, nwaddr, wildcard_nw);
            }
            conns.splice(begin, conns, citer);
        }
    }
}


void
Authenticator::remove_internal_hosts(const datapathid& dp, uint16_t port,
                                     HostMap::iterator& dlconns,
                                     NWMap::iterator& nwconns)
{
    Routing_module::RouteId rid;
    rid.src = dp;
    for (ConnList::iterator internal = nwconns->second.conns.begin();
         internal != nwconns->second.conns.end();)
    {
        rid.dst = datapathid::from_host((*internal)->location & DP_MASK);
        if ((*internal)->is_internal
            && routing_mod->is_on_path_location(rid, port,
                                                (uint16_t)((*internal)->location >> 48)))
        {
            post_leave(dlconns, nwconns, internal, false, " (internal port)");
        } else {
            ++internal;
        }
    }
}

bool
Authenticator::get_on_path_conn(const datapathid& dp, uint16_t port,
                                NWEntry& nwentry,
                                ConnList::iterator& conn)
{
    Routing_module::RouteId rid;
    rid.dst = dp;
    for (conn = nwentry.conns.begin(); conn != nwentry.conns.end(); ++conn) {
        uint64_t src_dp = (*conn)->location & DP_MASK;
        uint16_t src_port = (uint16_t)((*conn)->location >> 48);
        VLOG_DBG(lg, "checking on path loc:%"PRIx64":%"PRIu16"",
                 src_dp, src_port);

        rid.src = datapathid::from_host(src_dp);
        if (routing_mod->is_on_path_location(rid, src_port, port)) {
            return true;
        }
    }
    return false;
}


bool
Authenticator::set_flow_src_conn(const datapathid& dp, uint16_t port,
                                 const ethernetaddr& dladdr,
                                 const time_t& cur_time,
                                 const HostMap::iterator& dlconns,
                                 const NWMap::iterator& nwconns, ConnPtr& source,
                                 ConnPtr& route_source,
                                 boost::shared_ptr<std::vector<uint32_t> >& addr_groups,
                                 bool& dl_authed, bool& nw_authed,
                                 Event *to_post, const EventCb& cb)
{
    uint64_t loc = LOC_FROM_DP_PORT(dp, port);
    ConnList::iterator citer;
    bool internal = false;
    if (get_conn(loc, nwconns->second, citer)) {
        source = *citer;
        dl_authed = true;
        nw_authed = nwconns->first != 0;
        if (cb.empty()) {
            make_primary(dladdr, nwconns->first, cur_time, nwconns->second,
                         citer, nwconns->first == 0 &&
                         (dlconns->second.gateway || dlconns->second.router));
        }
        return true;
    } else if ((internal = topology->is_internal(dp, port)) == true
               && get_on_path_conn(dp, port, nwconns->second, citer))
    {
        source = *citer;
        dl_authed = true;
        nw_authed = nwconns->first != 0;
        return true;
    } else if (nwconns->first != 0 && dlconns->second.router
               && dlconns->second.zero != NULL)
    {
        do {
            bool make_pri = false;
            if (get_conn(loc, *(dlconns->second.zero), citer)) {
                make_pri = true;
            } else if (!internal
                       || !get_on_path_conn(dp, port, *(dlconns->second.zero), citer))
            {
                VLOG_DBG(lg, "Location not on path of router locations.");
                break;
            }

            NWLookup::iterator nw = nwhosts.find(nwconns->first);
            if (nw == nwhosts.end()) {
                VLOG_DBG(lg, "nwaddr of authed source not found.");
                loc = (*citer)->location;
                internal = (*citer)->is_internal;
                break;
            }

            NWEntry *nwentry = nw->second.front();
            if (nwentry->status->locked) {
                nwentry->status->waiters.push_back(
                    boost::bind(&Authenticator::set_flow_in, this, to_post, cb));
                VLOG_DBG(lg, "Queuing flow-in for locked router nwconns %"PRIx32".",
                         nw->first);
                return false;
            }
            source = nwentry->conns.front();
            route_source = *citer;
            dl_authed = true;
            nw_authed = true;

            if (make_pri && cb.empty()) {
                make_primary(dladdr, 0, cur_time, *(dlconns->second.zero),
                             citer, true);
            }
            return true;
        } while (0);
    } else {
        VLOG_DBG(lg, "Didn't match any source conditions.");
    }

    if (cb.empty() && (auto_auth_hosts || is_internal_mac(dlconns->first))) {
        auth_ev_host(to_post);
    } else {
        VLOG_DBG(lg, "Setting source to temporary loc:%"PRIx64":%"PRIu16" "
                 "dl:%"PRIx64" nw:%"PRIx32".", loc & DP_MASK,
                 (uint16_t)(loc >> 48), dladdr.hb_long(), nwconns->first);
        // should dl_authed be true if router?
        dl_authed = nw_authed = false;
        get_temp_conn(&source, loc, internal, UNAUTHENTICATED_ID,
                      boost::bind(&Authenticator::set_flow_in, this, to_post, cb));
    }
    return false;
}

bool
Authenticator::set_flow_dst_conn(const HostMap::iterator& dlconns,
                                 const NWMap::iterator& nwconns,
                                 bool lookup_dst,
                                 Flow_in_event *fi, const EventCb& cb)
{
    fi->dst_dl_authed = fi->dst_nw_authed = false;
    if (!nwconns->second.conns.empty()) {
        fi->dst_dl_authed = true;
        fi->dst_nw_authed = nwconns->first != 0;
        fi->set_destination_list(nwconns->second.conns);
        return true;
    } else if (nwconns->first != 0
               && dlconns->second.zero != NULL
               && !dlconns->second.zero->conns.empty())
    {
        fi->dst_dl_authed = true;

        if (dlconns->second.router) {
            NWLookup::iterator nw = nwhosts.find(nwconns->first);
            if (nw != nwhosts.end()) {
                NWEntry *nwentry = nw->second.front();
                if (nwentry->status->locked) {
                    nwentry->status->waiters.push_back(
                        boost::bind(&Authenticator::set_flow_in, this, fi, cb));
                    VLOG_DBG(lg, "Queuing flow-in for locked router nwconns %"PRIx32".",
                             nw->first);
                    return false;
                }
                fi->dst_nw_authed = true;
                fi->set_destination_list(nwentry->conns);
                fi->route_destinations = dlconns->second.zero->conns;
                return true;
            }
        }

        fi->route_destinations = dlconns->second.zero->conns;
    }

    fi->destinations.resize(1);
    Flow_in_event::DestinationInfo& destination = fi->destinations.front();
    destination.allowed = true;
    if (!lookup_dst) {
        VLOG_DBG(lg, "Setting dst to temporary dl:%"PRIx64" nw:%"PRIx32".",
                 dlconns->first, nwconns->first);
        EmptyCb cb2;
        if (cb.empty()) {
            cb2 = boost::bind(&Authenticator::post_event, this, fi);
        } else {
            cb2 = boost::bind(&Authenticator::set_flow_in, this, fi, cb);
        }
        get_temp_conn(&destination.connector, 0, false, UNAUTHENTICATED_ID, cb2);
        return false;
    }

    VLOG_DBG(lg, "Setting dst to looked up temporary dl:%"PRIx64" nw:%"PRIx32".",
             dlconns->first, nwconns->first);
    // don't check for gateway attribute else create names for all internet hosts
    get_host(zero_dp, 0, fi->flow.dl_dst, nwconns->first,
             boost::bind(&Authenticator::post_unauth_dst_flow, this, _1, fi, cb),
             nwconns->first == 0 || !(dlconns->second.router));
    return false;
}


void
Authenticator::get_temp_conn(ConnPtr *conn, uint64_t loc, bool is_internal,
                             uint32_t host, const EmptyCb& cb)
{
    conn->reset(new Connector());
    const ConnPtr& c= *conn;
    c->location = loc;
    c->is_internal = is_internal;
    c->host = host;
    c->users.push_front(user_info());
    c->users.front().user = UNAUTHENTICATED_ID;
    c->n_bindings = 1;
    c->last_active = c->hard_timeout = 0;
    c->inactivity_len = 0;
    set_groups(c, cb, false);
}


void
Authenticator::post_unauth_dst_flow(const std::string& hostname,
                                    Flow_in_event *fi, const EventCb& cb)
{
    uint32_t host = UNAUTHENTICATED_ID;
    if (hostname != get_unknown_name()) {
        host = get_id(hostname, Directory::HOST_PRINCIPAL, EMPTY_GROUP, true, false);
    }

    EmptyCb cb2;
    if (cb.empty()) {
        cb2 = boost::bind(&Authenticator::post_event, this, fi);
    } else {
        cb2 = boost::bind(&Authenticator::set_flow_in, this, fi, cb);
    }

    get_temp_conn(&(fi->destinations.front().connector), 0, false, host, cb2);
}


// Throws auth event if host should automatically be authed
// right now always auths..

void
Authenticator::auth_ev_host(Event *event)
{
    Flow_in_event *fi = dynamic_cast<Flow_in_event*>(event);
    if (fi == NULL) {
        Broadcast_in_event *bi = static_cast<Broadcast_in_event*>(event);
        auth_bi_host(*bi);
    } else {
        auth_host(*fi);
    }
    delete event;
}

void
Authenticator::auth_bi_host(const Broadcast_in_event& bi)
{
    Packet_in_event *npi = new Packet_in_event(bi.datapath_id,
                                               ntohs(bi.flow.in_port), bi.buf,
                                               bi.total_len, bi.buffer_id,
                                               bi.reason);
    auth_host2(npi, bi.flow.dl_src, bi.flow.dl_src.hb_long(),
               ntohl(bi.flow.nw_src));
}


void
Authenticator::auth_host(const Flow_in_event& fi)
{
    Packet_in_event *npi = new Packet_in_event(fi.datapath_id,
                                               ntohs(fi.flow.in_port), fi.buf,
                                               fi.total_len, fi.buffer_id,
                                               fi.reason);

    auth_host2(npi, fi.flow.dl_src, fi.flow.dl_src.hb_long(),
               ntohl(fi.flow.nw_src));
}

void
Authenticator::auth_host2(Packet_in_event *pi, const ethernetaddr& dl_src,
                          uint64_t dladdr, uint32_t nwaddr)
{
    VLOG_DBG(lg, "Authenticating host loc:%"PRIx64":%"PRIu16" "
             "dl:%"PRIx64" nw:%"PRIx32".", pi->datapath_id.as_host(),
             pi->in_port, dladdr, nwaddr);
    bool owns = true;
    if (nwaddr != 0) {
        bool new_dl = false;
        HostMap::iterator dlconns = hosts.find(dladdr);
        if (dlconns == hosts.end()) {
            new_dl = true;
            dlconns = hosts.insert(std::make_pair(dladdr, DLEntry())).first;
            dlconns->second.status.locked = true;
        }
        if (dlconns->second.status.locked) {
            dlconns->second.status.waiters.push_back(
                boost::bind(&Authenticator::auth_host2, this,
                            pi, dl_src, dladdr, nwaddr));
            VLOG_DBG(lg, "Queuing auth_host for locked dlconns "
                     "dl:%"PRIx64" %"PRIx32".", dladdr, nwaddr);
            if (new_dl) {
                new_dl_entry(dlconns, dl_src, true);
            }
            return;
        }
        // don't look up gateway nwaddrs otherwise will cover all internet
        if (dlconns->second.router) {
            if (is_internal_ip(nwaddr)) {
                owns = false;
            } else {
                nwaddr = 0;
            }
        }
    }
    get_host(pi->datapath_id, pi->in_port, dl_src, nwaddr,
             boost::bind(&Authenticator::auth_host3,
                         this, _1, pi, dl_src, nwaddr, owns), owns);
}

void
Authenticator::auth_host3(const std::string& hostname, Packet_in_event *pi,
                          const ethernetaddr& dl_src, uint32_t nwaddr, bool owns_dl)
{
    Auth_event *ae;
    if (hostname == get_unknown_name()) {
        ae = new Auth_event(Auth_event::AUTHENTICATE,
                            pi->datapath_id, pi->in_port,
                            dl_src, nwaddr, owns_dl,
                            get_authenticated_name(), get_unknown_name(), 0, 0);
    } else {
        ae = new Auth_event(Auth_event::AUTHENTICATE,
                            pi->datapath_id, pi->in_port,
                            dl_src, nwaddr, owns_dl,
                            hostname, get_unknown_name(), 0, 0);
    }
    ae->to_post = pi;
    post(ae);
}


// Handlers for datapath and link changes that remove no longer connected hosts

Disposition
Authenticator::handle_datapath_join(const Event& e)
{
    const Datapath_join_event& dj = assert_cast<const Datapath_join_event&>(e);
    uint64_t dpint = dj.datapath_id.as_host();
    hash_set<uint64_t> points;

    new_switch(dj.datapath_id);
    for (std::vector<Port>::const_iterator iter = dj.ports.begin();
         iter != dj.ports.end(); ++iter)
    {
        uint64_t loc = dpint + (((uint64_t) iter->port_no) << 48);
        if (!(points.insert(loc).second)) {
            VLOG_WARN(lg, "Duplicate dp/port pair %"PRIx64":%"PRIu16" seen in features.",
                      dpint, iter->port_no);
        } else {
            new_location(dj.datapath_id, iter->port_no, loc, iter->name);
        }
    }

    remove_dp_hosts(dpint, points, false, false, " (datapath re-join)");
    remove_dp_locations(dj.datapath_id, dpint, points, false);
    return CONTINUE;
}

Disposition
Authenticator::handle_data_leave(const Event& e)
{
    const Datapath_leave_event& dl = assert_cast<const Datapath_leave_event&>(e);
    hash_set<uint64_t> empty_points;
    uint64_t dpint = dl.datapath_id.as_host();

    remove_dp_hosts(dpint, empty_points, true, false, " (datapath leave)");
    remove_dp_locations(dl.datapath_id, dpint, empty_points, true);
    remove_switch(dl.datapath_id);

    return CONTINUE;
}

Disposition
Authenticator::handle_port_status(const Event& e)
{
    const Port_status_event& ps = assert_cast<const Port_status_event&>(e);
    uint64_t loc = LOC_FROM_DP_PORT(ps.datapath_id, ps.port.port_no);

    if (ps.reason == OFPPR_DELETE) {
        remove_loc_hosts(loc, true, " (port leave)");
        remove_location(ps.datapath_id, ps.port.port_no, loc);
    } else if (ps.reason == OFPPR_ADD) {
        new_location(ps.datapath_id, ps.port.port_no, loc, ps.port.name);
    }

    return CONTINUE;
}

Disposition
Authenticator::handle_link_change(const Event& e)
{
    const Link_event& le = assert_cast<const Link_event&>(e);

    if (le.action == Link_event::ADD) {
        remove_loc_hosts(LOC_FROM_DP_PORT(le.dpdst, le.dport), false,
                         " (internal port)");
    }
    return CONTINUE;
}

// Auth handlers

Disposition
Authenticator::handle_auth(const Event& e)
{
    Auth_event& ae =
        const_cast<Auth_event&>(assert_cast<const Auth_event&>(e));

    if (ae.action == Auth_event::AUTHENTICATE) {
        VLOG_DBG(lg, "Received auth event for loc:%"PRIx64":%"PRIu16" "
                 "dl:%"PRIx64" nw:%"PRIx32".", ae.datapath_id.as_host(),
                 ae.port, ae.dladdr.hb_long(), ae.nwaddr);
        add_auth(ae);
        ae.to_post = NULL;
    } else if (ae.action == Auth_event::DEAUTHENTICATE) {
        del_auth(ae);
        ae.to_post = NULL;
    } else {
        VLOG_WARN(lg, "Unexpected Auth_event type %u.", ae.action);
    }
    return CONTINUE;
}


void
Authenticator::add_auth(const Auth_event& ae)
{
    ConnPtr empty;
    uint64_t dladdr = ae.dladdr.hb_long();
    HostMap::iterator dlconns = hosts.find(dladdr);
    if (dlconns == hosts.end()) {
        dlconns = hosts.insert(std::make_pair(dladdr, DLEntry())).first;
        dlconns->second.status.locked = true;
        VLOG_DBG(lg, "Queuing add auth2 for new dlconns "
                 "dl:%"PRIx64" nw:%"PRIx32".", dladdr, ae.nwaddr);
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::add_auth2, this, ae, empty));
        new_dl_entry(dlconns, ae.dladdr, false);
        return;
    } else if (dlconns->second.status.locked) {
        VLOG_DBG(lg, "Queuing add auth for locked dlconns "
                 "dl:%"PRIx64" nw:%"PRIx32".", dladdr, ae.nwaddr);
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::add_auth, this, ae));
        return;
    }

    add_auth2(ae, empty);
}

// should be called with dlconns locked (or could be locked when called by
// add_auth())

void
Authenticator::add_auth2(const Auth_event& ae, ConnPtr& zconn)
{
    HostMap::iterator dlconns = hosts.find(ae.dladdr.hb_long());
    uint64_t loc = LOC_FROM_DP_PORT(ae.datapath_id, ae.port);
    uint32_t host = get_id(ae.hostname, Directory::HOST_PRINCIPAL,
                           EMPTY_GROUP, true, false);
    uint32_t nwaddr = ae.owns_dl && zconn == NULL ? 0 : ae.nwaddr;

    dlconns->second.status.locked = false;

    NWMap::iterator nwconns;
    ConnList::iterator conn;

    while (true) {
        nwconns = dlconns->second.nws.find(nwaddr);
        if (nwconns == dlconns->second.nws.end()) {
            nwconns = dlconns->second.nws.insert(std::make_pair(
                                                     nwaddr, NWEntry())).first;
            dlconns->second.status.locked = true;
            dlconns->second.status.waiters.push_front(
                boost::bind(&Authenticator::add_auth2,
                            this, ae, zconn));
            VLOG_DBG(lg, "Queuing add auth2 for new addr entry "
                     "dl:%"PRIx64" nw:%"PRIx32".", dlconns->first, nwaddr);
            new_nw_entry(dlconns, nwconns, ae.dladdr, false);
            return;
        }
        if (get_conn(loc, nwconns->second, conn)) {
            uint32_t chost = (*conn)->host;
            if (nwaddr != 0 && ae.owns_dl) {
                if (*conn != zconn) {
                    post_leave(dlconns, nwconns, conn, true, " (re-authenticate)");
                    conn = nwconns->second.conns.end();
                }
            } else if (host == UNKNOWN_ID || chost == host) {
                if (nwaddr != ae.nwaddr) {
                    zconn = *conn;
                    nwaddr = ae.nwaddr;
                    continue;
                }
            } else {
                post_leave(dlconns, nwconns, conn, true, " (re-authenticate)");
                conn = nwconns->second.conns.end();
            }
        } else {
            // want to do this?
            remove_internal_hosts(ae.datapath_id, ae.port, dlconns, nwconns);
        }
        break;
    };

    dlconns->second.status.locked = true;
    VLOG_DBG(lg, "Locking dl:%"PRIx64" nw:%"PRIx32" for authentication.",
             dlconns->first, nwconns->first);

    if (nwconns->first != 0) {
        NWLookup::iterator nw = nwhosts.find(nwconns->first);
        if (nw == nwhosts.end()) {
            nwhosts[nwconns->first] = std::list<NWEntry*>(1, &nwconns->second);
        } else {
            bool found = false;
            for (std::list<NWEntry*>::iterator iter = nw->second.begin();
                 iter != nw->second.end(); ++iter)
            {
                if (*iter == &nwconns->second) {
                    found = true;
                    if (iter != nw->second.begin()) {
                        nw->second.splice(nw->second.begin(), nw->second, iter);
                    }
                    break;
                }
            }
            if (!found) {
                nw->second.push_front(&nwconns->second);
            }
        }
    }

    bool is_internal = topology->is_internal(ae.datapath_id, ae.port);
    if (conn == nwconns->second.conns.end()) {
        if (is_internal || nwconns->second.conns.empty()) {
            conn = nwconns->second.conns.insert(nwconns->second.conns.end(), ConnPtr());
        } else {
            ConnList::iterator iter = nwconns->second.conns.begin();
            while (true) {
                if (iter == nwconns->second.conns.end() || (*iter)->is_internal) {
                    conn = nwconns->second.conns.insert(iter, ConnPtr());
                    break;
                } else {
                    ++iter;
                }
            }
        }
        if (nwaddr != 0 && ae.owns_dl) {
            *conn = zconn;
            ++(*conn)->n_bindings;
            update_conn(*conn, ae, true);
        } else {
            conn->reset(new Connector());
            (*conn)->location = loc;
            (*conn)->is_internal = is_internal;
            (*conn)->n_bindings = 1;
            init_conn(*conn, ae);
        }
    } else {
        update_conn(*conn, ae, false);
    }
}

void
Authenticator::init_conn(ConnPtr& conn, const Auth_event& ae)
{
    uint32_t host = get_id(ae.hostname, Directory::HOST_PRINCIPAL,
                           EMPTY_GROUP, true, true);
    uint32_t user = get_id(ae.username, Directory::USER_PRINCIPAL,
                           EMPTY_GROUP, true, true);
    if (host == UNKNOWN_ID) {
        host = UNAUTHENTICATED_ID;
    } else if (host == AUTHENTICATED_ID) {
        VLOG_WARN(lg, "Host getting authenticated with missing name - unexpected.");
    }
    if (user == UNKNOWN_ID) {
        user = UNAUTHENTICATED_ID;
    }

    conn->host = host;
    conn->users.push_front(user_info());
    conn->users.front().user = user;

    if (is_internal_mac(ae.dladdr.hb_long())
        && (ae.owns_dl || ae.nwaddr == 0))
    {
        EmptyCb init = boost::bind(&Authenticator::init_complete,
                                   this, conn, ae);
        EmptyCb groups = boost::bind(&Authenticator::set_groups, this,
                                     conn, init, true);
        static std::vector<std::string> principal(1, "");
        static std::vector<std::string> empty(0);
        principal[0] = ae.hostname;
        dirmanager->modify_host_group(SWITCH_GROUP, principal, empty, true,
                                      groups, groups);
    } else {
        set_groups(conn, boost::bind(&Authenticator::init_complete,
                                     this, conn, ae), true);
    }
}

void
Authenticator::init_complete(ConnPtr& conn, const Auth_event& ae)
{
    uint32_t nwaddr = ae.owns_dl ? 0 : ae.nwaddr;

    const std::string& hname = get_name(conn->host);
    std::string dlstr = ae.dladdr.string();
    std::string nwstr = ipaddr(nwaddr).string();

    snprintf(buf, 1024, "%s join at {sl} with %s.",
             conn->host == UNAUTHENTICATED_ID ? "unnamed host" :
             "{sh}", nwaddr == 0 ? dlstr.c_str() : nwstr.c_str());
    LogEntry to_log = LogEntry(app_name, LogEntry::INFO, buf);
    to_log.setNameByLocation(ae.datapath_id, ae.port, LogEntry::SRC);
    if (conn->host != UNAUTHENTICATED_ID) {
        bindings->store_binding_state(ae.datapath_id, ae.port, ae.dladdr,
                                      nwaddr, hname, Name::HOST, false);
        to_log.setName(hname, Name::HOST, LogEntry::SRC);
    } else {
        bindings->store_binding_state(ae.datapath_id, ae.port, ae.dladdr,
                                      nwaddr, false);
    }
    post(new Host_event(Host_event::JOIN, ae.datapath_id, ae.port,
                        ae.dladdr, nwaddr, hname));
    VLOG_DBG(lg, "Host %s join at %"PRIx64":%"PRIu16" with %s, %s.",
             hname.c_str(), ae.datapath_id.as_host(), ae.port,
             dlstr.c_str(), nwstr.c_str());
    user_log->log(to_log);

    if (conn->users.front().user != UNAUTHENTICATED_ID) {
        add_user(conn, ae.datapath_id, ae.port, ae.dladdr, nwaddr);
    }

    timeval curtime = { 0, 0 };
    gettimeofday(&curtime, NULL);
    conn->last_active = curtime.tv_sec;

    if (ae.hard_timeout == 0) {
        conn->hard_timeout = 0;
    } else {
        conn->hard_timeout = curtime.tv_sec + ae.hard_timeout;
    }

    if (ae.inactivity_timeout == 0) {
        conn->inactivity_len = default_host_timeout;
    } else {
        conn->inactivity_len = ae.inactivity_timeout;
    }

    unlock_auth(ae, conn, nwaddr == ae.nwaddr);
}

void
Authenticator::unlock_auth(const Auth_event& ae, ConnPtr& conn, bool is_event_ip)
{
    if (!is_event_ip) {
        add_auth2(ae, conn);
        return;
    }

    unlock_auth2(ae);
}


void
Authenticator::unlock_auth2(const Auth_event& ae)
{
    HostMap::iterator dlconns = hosts.find(ae.dladdr.hb_long());
    if (!dlconns->second.status.waiters.empty()) {
        VLOG_DBG(lg, "Unlocking dlconns dl:%"PRIx64" after auth/del_auth.",
                 dlconns->first);
    }

    UpdateStatus status;
    status.waiters.swap(dlconns->second.status.waiters);
    unlock_status(&(dlconns->second.status));
    if (ae.to_post != NULL) {
        post(ae.to_post);
    }
    unlock_status(&status);
}


void
Authenticator::update_conn(ConnPtr& conn, const Auth_event& ae,
                           bool add_nw)
{
    uint32_t id = get_id(ae.username, Directory::USER_PRINCIPAL,
                         EMPTY_GROUP, true, true);
    std::list<user_info>::iterator u;
    if (id != UNKNOWN_ID && !contains_user(conn, id, u)) {
        if (id == UNAUTHENTICATED_ID) {
            VLOG_ERR(lg, "Cannot auth with UNAUTHENTICATED username - use del_auth.");
        } else {
            if (conn->users.front().user == UNAUTHENTICATED_ID) {
                conn->users.front().user = id;
                decrement_ids(conn->users.front().groups);
            } else if (conn->users.front().user == AUTHENTICATED_ID) {
                conn->users.front().user = id;
                decrement_ids(conn->users.front().groups);
                bindings->remove_binding_state(ae.datapath_id, ae.port,
                                               ae.dladdr, add_nw ? 0 : ae.nwaddr,
                                               get_authenticated_name(),
                                               Name::USER);
            } else {
                conn->users.push_front(user_info());
                conn->users.front().user = id;
            }
            set_user_groups(conn->users.begin(),
                            boost::bind(&Authenticator::update_complete,
                                        this, conn, add_nw, true, ae),
                            true);
            return;
        }
    }

    decrement_id(id);
    update_complete(conn, add_nw, false, ae);
}


void
Authenticator::update_complete(ConnPtr& conn, bool add_nw,
                               bool update_user, const Auth_event& ae)
{
    const std::string& hname = get_name(conn->host);

    if (update_user) {
        add_user(conn, ae.datapath_id, ae.port, ae.dladdr,
                 conn->n_bindings == 1 ? ae.nwaddr : 0);
    }

    if (add_nw) {
        bindings->store_binding_state(ae.datapath_id, ae.port, ae.dladdr,
                                      ae.nwaddr, true, 0);
        // added to post leave event for just IP
        post(new Host_event(Host_event::JOIN, ae.datapath_id, ae.port,
                            ae.dladdr, ae.nwaddr, hname));
        std::string nwstr = ipaddr(ae.nwaddr).string();
        VLOG_DBG(lg, "%s added as sending IP on host %s at %"PRIx64":%"PRIu16".",
                 nwstr.c_str(), hname.c_str(), ae.datapath_id.as_host(), ae.port);
        snprintf(buf, 1024, "%s added as sending IP on %s at {sl}.",
                 nwstr.c_str(),
                 conn->host == UNAUTHENTICATED_ID ? "unnamed host" :
                 "{sh}");
        LogEntry to_log = LogEntry(app_name, LogEntry::INFO, buf);
        to_log.setNameByLocation(ae.datapath_id, ae.port, LogEntry::SRC);
        if (conn->host != UNAUTHENTICATED_ID) {
            to_log.setName(hname, Name::HOST, LogEntry::SRC);
        }
        user_log->log(to_log);
    }

    if (ae.inactivity_timeout != 0 && conn->inactivity_len < ae.inactivity_timeout) {
        conn->inactivity_len = ae.inactivity_timeout;
    }

    if (ae.hard_timeout != 0) {
        timeval curtime = { 0, 0 };
        gettimeofday(&curtime, NULL);
        time_t exp(curtime.tv_sec + ae.hard_timeout);
        if (conn->hard_timeout == 0 || conn->hard_timeout > exp) {
            conn->hard_timeout = exp;
        }
    }

    unlock_auth(ae, conn, true);
}

void
Authenticator::del_auth(const Auth_event& ae)
{
    if (ae.datapath_id.as_host() == 0) {
        if (ae.hostname != get_unknown_name()) {
            remove_hosts(true, " (host binding delete)",
                         boost::bind(&Authenticator::remove_host,
                                     this, _1, _2, _3, ae.hostname));
        }
        if (ae.username != get_unknown_name()) {
            map_conns(boost::bind(&Authenticator::delname_user,
                                  this, _1, _2, _3, _4, false),
                      ae.username, Directory::USER_PRINCIPAL, EMPTY_GROUP, true);
        }
        return;
    }

    uint64_t loc(LOC_FROM_DP_PORT(ae.datapath_id, ae.port));
    uint64_t dladdr(ae.dladdr.hb_long());

    HostMap::iterator dlconns;
    NWMap::iterator nwconns;
    ConnList::iterator conn;

    bool found = get_conn(loc, dladdr, ae.nwaddr, dlconns, nwconns, conn);
    if (dlconns != hosts.end() && dlconns->second.status.locked) {
        VLOG_DBG(lg, "Queuing del auth event for locked dlconns "
                 "dl:%"PRIx64" nw:%"PRIx32".", dladdr, ae.nwaddr);
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::del_auth, this, ae));
        return;
    } else if (!found) {
        VLOG_WARN(lg, "loc:%"PRIx64":%"PRIu16" dl:%"PRIx64" nw:%"PRIx32" "
                  "not present to de-auth.",
                  ae.datapath_id.as_host(), ae.port, dladdr, ae.nwaddr);
        if (ae.to_post != NULL) {
            post(ae.to_post);
        }
        return;
    }

    uint32_t host, user;
    host = get_id(ae.hostname, Directory::HOST_PRINCIPAL,
                  EMPTY_GROUP, true, false);
    user = get_id(ae.username, Directory::USER_PRINCIPAL,
                  EMPTY_GROUP, true, false);

    if (user == UNKNOWN_ID
        && host == UNKNOWN_ID)
    {
        post_leave(dlconns, nwconns, conn, true, " (deauthenticate)");
        if (ae.to_post != NULL) {
            post(ae.to_post);
        }
        return;
    }

    bool update_host = false;
    bool update_user = false;

    const ConnPtr& c = *conn;

    if (host != UNKNOWN_ID) {
        if (c->host == host || host == UNAUTHENTICATED_ID) {
            if (c->host != UNAUTHENTICATED_ID) {
                const std::string& hname = get_name(c->host);
                bindings->remove_binding_state(ae.datapath_id, ae.port,
                                               ae.dladdr, ae.nwaddr,
                                               hname, Name::HOST);
                VLOG_DBG(lg, "Hostname %s deauthentication at %"PRIx64":%"PRIu16".",
                         hname.c_str(), ae.datapath_id.as_host(), ae.port);
                snprintf(buf, 1024, "{sh} name deauthentication at {sl}.");
                LogEntry to_log = LogEntry(app_name, LogEntry::INFO, buf);
                to_log.setName(hname, Name::HOST, LogEntry::SRC);
                to_log.setNameByLocation(ae.datapath_id, ae.port, LogEntry::SRC);
                user_log->log(to_log);
                decrement_id(c->ap); // going to be incremented when setting groups
                decrement_id(c->host);
                decrement_ids(c->hostgroups);
                c->host = UNAUTHENTICATED_ID;
                update_host = true;
            }
        } else {
            VLOG_WARN(lg, "Hostname %s on loc:%"PRIx64" dl:%"PRIx64""
                      "nw:%"PRIx32" not present to de-auth.",
                      ae.hostname.c_str(), loc, dladdr, ae.nwaddr);
        }
    }

    if (user != UNKNOWN_ID) {
        uint32_t nwaddr = c->n_bindings == 1 ? ae.nwaddr : 0;
        std::list<user_info>::iterator u;
        if (user == UNAUTHENTICATED_ID) {
            bool poison = true;
            for (u = c->users.begin(); u != c->users.end();) {
                if (u->user != UNAUTHENTICATED_ID) {
                    remove_user(c, u, ae.datapath_id, ae.port, ae.dladdr,
                                nwaddr, true, " (deauthenticate)", poison);
                    poison = false;
                } else {
                    ++u;
                }
            }
        } else if (contains_user(c, user, u)) {
            remove_user(c, u, ae.datapath_id, ae.port, ae.dladdr, nwaddr,
                        true, " (deauthenticate)", true);
        } else {
            VLOG_WARN(lg, "Username %s on loc:%"PRIx64" dl:%"PRIx64" "
                      "nw:%"PRIx32" not present to de-auth.",
                      ae.username.c_str(), loc, dladdr, ae.nwaddr);
        }
        if (c->users.empty()) {
            c->users.push_front(user_info());
            c->users.front().user = UNAUTHENTICATED_ID;
            update_user = true;
        }
    }

    dlconns->second.status.locked = true;
    VLOG_DBG(lg, "Locking dlconns dl:%"PRIx64" for del_auth.", dlconns->first);
    EmptyCb cb = boost::bind(&Authenticator::unlock_auth2, this, ae);
    if (update_host) {
        if (update_user) {
            set_groups(c, cb, true);
        } else {
            set_host_groups(c, cb, true);
        }
    } else if (update_user) {
        set_user_groups(c->users.begin(), cb, true);
    } else {
        cb();
    }
}

bool
Authenticator::contains_user(const ConnPtr& conn, uint32_t user,
                             std::list<user_info>::iterator& u)
{
    u = conn->users.begin();
    for (; u != conn->users.end(); ++u) {
        if (u->user == user) {
            return true;
        }
    }
    return false;
}


void
Authenticator::add_user(const ConnPtr& conn, const datapathid& dp,
                        uint16_t port, const ethernetaddr& dladdr,
                        uint32_t nwaddr)
{
    const std::string& uname = get_name(conn->users.front().user);
    const std::string& hname = get_name(conn->host);

    bindings->store_binding_state(dp, port, dladdr, nwaddr,
                                  uname, Name::USER, false);
    post(new User_event(User_event::JOIN, uname, dp, port,
                        dladdr, nwaddr));
    VLOG_DBG(lg, "User %s join on host %s at ap:%"PRIx64":%"PRIu16".",
             uname.c_str(), hname.c_str(), dp.as_host(), port);
    snprintf(buf, 1024, "User {su} join on %s at {sl}.",
             conn->host == UNAUTHENTICATED_ID ? "unnamed host" :
             "{sh}");
    LogEntry to_log = LogEntry(app_name, LogEntry::INFO, buf);
    to_log.setName(uname, Name::USER, LogEntry::SRC);
    to_log.setNameByLocation(dp, port, LogEntry::SRC);
    if (conn->host != UNAUTHENTICATED_ID) {
        to_log.setName(hname, Name::HOST, LogEntry::SRC);
    }
    user_log->log(to_log);
}


void
Authenticator::remove_user(const ConnPtr& conn, std::list<user_info>::iterator& u,
                           const datapathid& dp, uint16_t port,
                           const ethernetaddr& dladdr, uint32_t nwaddr,
                           bool tell_bindings, const std::string& reason,
                           bool poison)
{
    const std::string& uname = get_name(u->user);
    const std::string& hname = get_name(conn->host);
    if (tell_bindings) {
        bindings->remove_binding_state(dp, port, dladdr, nwaddr, uname, Name::USER);
    }
    post(new User_event(User_event::LEAVE, uname, dp, port, dladdr, nwaddr));
    VLOG_DBG(lg, "User %s leave on host %s at loc:%"PRIx64":%"PRIu16"%s.",
             uname.c_str(), hname.c_str(), dp.as_host(), port, reason.c_str());
    snprintf(buf, 1024, "User {su} leave on %s at {sl}%s.",
             conn->host == UNAUTHENTICATED_ID ? "unnamed_host" :
             "{sh}", reason.c_str());
    LogEntry to_log = LogEntry(app_name, LogEntry::INFO, buf);
    to_log.setName(uname, Name::USER, LogEntry::SRC);
    to_log.setNameByLocation(dp, port, LogEntry::SRC);
    if (conn->host != UNAUTHENTICATED_ID) {
        to_log.setName(hname, Name::HOST, LogEntry::SRC);
    }
    user_log->log(to_log);
    decrement_id(u->user);
    decrement_ids(u->groups);
    u = conn->users.erase(u);

    if (poison) {
        poison_ap(conn, dladdr, nwaddr, nwaddr == 0);
    }
}

void
Authenticator::repost_leave(uint64_t dladdr, uint32_t nwaddr, uint64_t loc,
                            bool poison, const std::string& reason,
                            UpdateStatus& status)
{
    VLOG_DBG(lg, "Queuing post leave %"PRIx64" %"PRIx64" %"PRIx32"",
             loc, dladdr, nwaddr);
    status.waiters.push_back(boost::bind(&Authenticator::redo_leave,
                                         this, dladdr, nwaddr, loc, poison,
                                         reason));
}

void
Authenticator::redo_leave(uint64_t dladdr, uint32_t nwaddr, uint64_t loc,
                          bool poison, const std::string& reason)
{
    HostMap::iterator dlconns;
    NWMap::iterator nwconns;
    ConnList::iterator conn;

    if (get_conn(loc, dladdr, nwaddr, dlconns, nwconns, conn)) {
        post_leave(dlconns, nwconns, conn, poison, reason);
    }
}

// post a host leave event
// if removing nwaddr == 0, other nwaddrs for that mac will get removed

bool
Authenticator::post_leave(HostMap::iterator& dlconns, NWMap::iterator& nwconns,
                          ConnList::iterator& conn, bool poison,
                          const std::string& reason)
{
    if (dlconns->second.status.locked) {
        repost_leave(dlconns->first, nwconns->first, (*conn)->location,
                     poison, reason, dlconns->second.status);
        return false;
    }

    // check works
    datapathid dp = datapathid::from_host((*conn)->location & DP_MASK);
    uint16_t port = (uint16_t)((*conn)->location >> 48);
    ethernetaddr ea = ethernetaddr(dlconns->first);
    if (nwconns->first == 0) {
        NWMap::iterator ip(dlconns->second.nws.begin());
        for (; ip != dlconns->second.nws.end(); ++ip) {
            if (ip->first != 0) {
                for (ConnList::iterator loc = ip->second.conns.begin();
                     loc != ip->second.conns.end();)
                {
                    if ((*loc)->location == (*conn)->location) {
                        post_leave(dlconns, ip, loc, poison,
                                   (*loc == *conn) ? "" : " (MAC leave)");
                    } else {
                        ++loc;
                    }
                }
            }
        }
    }

    const std::string& hname = get_name((*conn)->host);
    std::string dlstr = ethernetaddr(dlconns->first).string();
    std::string nwstr = ipaddr(nwconns->first).string();

    if ((--(*conn)->n_bindings) == 0) {
        bindings->remove_machine(dp, port, ea, nwconns->first, true);
        for (std::list<user_info>::iterator u = (*conn)->users.begin();
             u != (*conn)->users.end();)
        {
            if (u->user != UNAUTHENTICATED_ID) {
                remove_user((*conn), u, dp, port, ea, nwconns->first, false,
                            " (host leave)", false);
            } else {
                ++u;
            }
        }
        post(new Host_event(Host_event::LEAVE, dp, port, ea, nwconns->first, hname));
        VLOG_DBG(lg, "Host %s with %s %s leave on ap:%"PRIx64":%"PRIu16"%s.",
                 hname.c_str(), dlstr.c_str(), nwstr.c_str(), dp.as_host(),
                 port, reason.c_str());
        snprintf(buf, 1024, "%s with %s leave at {sl}%s.",
                 (*conn)->host == UNAUTHENTICATED_ID ? "unnamed host" :
                 "{sh}", nwconns->first == 0 ? dlstr.c_str() :
                 nwstr.c_str(), reason.c_str());
        LogEntry to_log = LogEntry(app_name, LogEntry::INFO, buf);
        to_log.setNameByLocation(dp, port, LogEntry::SRC);
        if ((*conn)->host != UNAUTHENTICATED_ID) {
            to_log.setName(hname, Name::HOST, LogEntry::SRC);
        }
        user_log->log(to_log);
        decrement_conn(*conn);
    } else {
        bindings->remove_machine(dp, port, ea, nwconns->first, false);
        // added to post leave event for just IP
        post(new Host_event(Host_event::LEAVE, dp, port, ea, nwconns->first, hname));
        if (reason != "") {
            VLOG_DBG(lg, "%s removed as sending IP on host %s at %"PRIx64":%"PRIu16"%s.",
                     nwstr.c_str(), hname.c_str(), dp.as_host(), port, reason.c_str());
            snprintf(buf, 1024, "%s removed as sending IP on {sh} at {sl}%s.",
                     nwstr.c_str(), reason.c_str());
            LogEntry to_log = LogEntry(app_name, LogEntry::INFO, buf);
            to_log.setNameByLocation(dp, port, LogEntry::SRC);
            if ((*conn)->host != UNAUTHENTICATED_ID) {
                to_log.setName(hname, Name::HOST, LogEntry::SRC);
            }
            user_log->log(to_log);
        }
    }

    // should do this at all?
    if (poison) {
        if (conn == nwconns->second.conns.begin()
            && !is_internal_mac(dlconns->first))
        {
            poison_ap(*conn, ea, nwconns->first, nwconns->first == 0);
        }
    }

    conn = nwconns->second.conns.erase(conn);
    if (nwconns->second.conns.empty()) {
        timeval curtime = { 0, 0 };
        gettimeofday(&curtime, NULL);
        nwconns->second.timeout = curtime.tv_sec + ADDR_TIMEOUT;
        if (nwconns->first != 0) {
            bool found = false;
            NWLookup::iterator nw = nwhosts.find(nwconns->first);
             if (nw != nwhosts.end()) {
                for (std::list<NWEntry*>::iterator iter = nw->second.begin();
                     iter != nw->second.end(); ++iter)
                {
                    if (*iter == &nwconns->second) {
                        found = true;
                        nw->second.erase(iter);
                        if (nw->second.empty()) {
                            nwhosts.erase(nw);
                        }
                        break;
                    }
                }
            }
            if (!found) {
                VLOG_ERR(lg, "nw:%"PRIx32" not found in nwhosts map.",
                         nwconns->first);
            }
        }
    }
    return true;
}

bool
Authenticator::is_internal_ip(uint32_t nwaddr) const
{
    for (std::vector<ip_subnet>::const_iterator iter = internal_subnets.begin();
         iter != internal_subnets.end(); ++iter)
    {
        VLOG_DBG(lg, "checking internal against nw:%x mask:%x", iter->nwaddr, iter->mask);
        if ((nwaddr & iter->mask) == iter->nwaddr) {
            return true;
        }
    }
    VLOG_DBG(lg, "done checking for internal nw:%x", nwaddr);
    return false;
}

// hold in host byte order in ip_subnet
void
Authenticator::add_internal_subnet(const cidr_ipaddr& cidr)
{
    uint32_t mask = ntohl(cidr.mask);
    ip_subnet sub = { ntohl(cidr.addr.addr), mask };
    internal_subnets.push_back(sub);
}

bool
Authenticator::remove_internal_subnet(const cidr_ipaddr& cidr)
{
    uint32_t ni = ntohl(cidr.addr.addr);
    uint32_t nm = ntohl(cidr.mask);

    for (std::vector<ip_subnet>::iterator iter = internal_subnets.begin();
         iter != internal_subnets.end(); ++iter)
    {
        if (iter->nwaddr == ni && iter->mask == nm) {
            internal_subnets.erase(iter);
            return true;
        }
    }
    return false;
}

void
Authenticator::get_names(const datapathid& dp, uint16_t inport,
                         const ethernetaddr& dlsrc, uint32_t nwsrc,
                         const ethernetaddr& dldst, uint32_t nwdst,
                         PyObject *callable)
{
#ifdef TWISTED_ENABLED
    Flow_in_event *event = new Flow_in_event();
    event->flow.in_port = htons(inport);
    event->flow.dl_src = dlsrc;
    event->flow.nw_src = htonl(nwsrc);
    event->flow.dl_dst = dldst;
    event->flow.nw_dst = htonl(nwdst);
    event->datapath_id = dp;
    Py_INCREF(callable);
    set_flow_in(event, boost::bind(&Authenticator::get_names2, this,
                                   _1, callable));
#else
    VLOG_ERR(lg, "Cannot return names for host if Python disabled.");
#endif
}

#ifdef TWISTED_ENABLED
PyObject *
Authenticator::get_name_list(const std::vector<uint32_t>& groups)
{
    PyObject *pylist = PyList_New(groups.size());
    if (pylist == NULL) {
        VLOG_ERR(lg, "Could not create python list");
        Py_RETURN_NONE;
    }
    std::vector<uint32_t>::const_iterator iter = groups.begin();
    for (uint32_t i = 0; iter != groups.end(); ++i, ++iter)
    {
        if (PyList_SetItem(pylist, i, to_python(get_name(*iter))) != 0) {
            VLOG_ERR(lg, "Could not set group list item");
        }
    }
    return pylist;
}

PyObject*
Authenticator::get_name_dict(Connector& conn)
{
    PyObject *connector = PyDict_New();
    if (connector == NULL) {
        VLOG_ERR(lg, "Could not create python dict");
        Py_RETURN_NONE;
    }
    pyglue_setdict_string(connector, "location", to_python(get_name(conn.ap)));
    pyglue_setdict_string(connector, "host", to_python(get_name(conn.host)));
    pyglue_setdict_string(connector, "hostgroups", get_name_list(conn.hostgroups));
    PyObject *pylist = PyList_New(conn.users.size());
    if (pylist == NULL) {
        VLOG_ERR(lg, "Could not create python list");
        Py_INCREF(Py_None);
        pylist = Py_None;
    } else {
        std::list<user_info>::const_iterator user = conn.users.begin();
        for (uint32_t i = 0; user != conn.users.end(); ++i, ++user) {
            PyObject *tup = PyTuple_New(2);
            if (tup != NULL) {
                PyTuple_SetItem(tup, 0, to_python(get_name(user->user)));
                PyTuple_SetItem(tup, 1, get_name_list(user->groups));
                if (PyList_SetItem(pylist, i, tup) != 0) {
                    VLOG_ERR(lg, "Could not set user list item");
                }
            }
        }
    }
    pyglue_setdict_string(connector, "users", pylist);
    return connector;
}

PyObject*
Authenticator::get_name_conn_list(Flow_in_event::DestinationList& conns)
{
   PyObject *connectors = PyList_New(conns.size());
   if (connectors == NULL) {
       VLOG_ERR(lg, "Could not create python list");
       Py_RETURN_NONE;
   }

   Flow_in_event::DestinationList::const_iterator d(conns.begin());
   for (uint32_t i = 0; d != conns.end(); ++i, ++d) {
       if (PyList_SetItem(connectors, i, get_name_dict(*(d->connector))) != 0) {
           VLOG_ERR(lg, "Could not set connector list item");
       }
   }
   return connectors;
}

void
Authenticator::get_names2(Event *event, PyObject *callable)
{
    Flow_in_event *fi = static_cast<Flow_in_event*>(event);
    PyObject *arg = PyDict_New();
    if (arg == NULL) {
        VLOG_ERR(lg, "Could not create python dict");
        Py_INCREF(Py_None);
        arg = Py_None;
    } else {
        pyglue_setdict_string(arg, "src", get_name_dict(*(fi->source)));
        pyglue_setdict_string(arg, "src_addr_groups", get_name_list(*fi->src_addr_groups));
        pyglue_setdict_string(arg, "dsts", get_name_conn_list(fi->destinations));
        pyglue_setdict_string(arg, "dst_addr_groups", get_name_list(*fi->dst_addr_groups));
    }
    PyObject *ret = PyObject_CallFunctionObjArgs(callable, arg, NULL);
    Py_DECREF(callable);
    Py_DECREF(arg);
    Py_XDECREF(ret);
    delete event;
}
#endif

}
}

REGISTER_COMPONENT(vigil::container::Simple_component_factory<Authenticator>,
                   Authenticator);
