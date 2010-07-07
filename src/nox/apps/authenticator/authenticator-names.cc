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

#include "assert.hh"
#include "directory/group_change_event.hh"
#include "directory/group_event.hh"
#include "directory/location_del_event.hh"
#include "directory/principal_event.hh"
#include "vlog.hh"

#define DP_MASK         0xffffffffffffULL

#define EMPTY_PRINCE     ((Directory::Principal_Type)UINT32_MAX)
#define EMPTY_GROUP      ((Directory::Group_Type)UINT32_MAX)

namespace vigil {
namespace applications {

static Vlog_module lg("authenticator");

void
Authenticator::get_switch(const datapathid& dp, const StringCb& cb)
{
    EmptyCb fail = boost::bind(&Authenticator::generate_switch_name,
                               this, dp, cb);

    switch_info.dpid = dp;
    if (!dirmanager->search_switches(switch_info, switchkey, "",
                                     boost::bind(&Authenticator::get_principal,
                                                 this, _1, cb, fail), fail))
    {
        fail();
    }
}

void
Authenticator::generate_switch_name(const datapathid& dp, const StringCb& cb)
{
    EmptyCb fail = boost::bind(&Authenticator::return_unknown, this, cb);
    if (!dirmanager->get_discovered_switch_name(dp, true, cb, fail)) {
        fail();
    }
}

void
Authenticator::get_location(const datapathid& dp, uint16_t port,
                            const std::string& port_name,
                            const StringCb& cb)
{
    EmptyCb fail = boost::bind(&Authenticator::generate_location_name,
                               this, dp, port, port_name, cb);

    loc_info.dpid = dp;
    loc_info.port = port;
    if (!dirmanager->search_locations(loc_info, lockey, "",
                                      boost::bind(&Authenticator::get_principal,
                                                  this, _1, cb, fail), fail))
    {
        fail();
    }
}

void
Authenticator::generate_location_name(const datapathid& dp, uint16_t port,
                                      const std::string& port_name,
                                      const StringCb& cb)
{
    std::string switch_name = "";
    GroupInfoMap::iterator sw = switches.find(dp.as_host());
    if (sw != switches.end()) {
        if (sw->second.status.locked) {
            sw->second.status.waiters.push_back(
                boost::bind(&Authenticator::generate_location_name,
                            this, dp, port, port_name, cb));
            VLOG_DBG(lg, "Queuing gen_loc_name %"PRIx64":%s.",
                     dp.as_host(), port_name.c_str());
            return;
        }
        switch_name = get_name(sw->second.id);
    }

    EmptyCb fail = boost::bind(&Authenticator::return_unknown, this, cb);

    if (!dirmanager->get_discovered_location_name(switch_name, port_name,
                                                  dp, port, true, cb, fail))
    {
        fail();
    }
}


void
Authenticator::get_host(const datapathid& dp, uint16_t port,
                        const ethernetaddr& dladdr, uint32_t nwaddr,
                        const StringCb& cb, bool owns_dl,
                        uint32_t iteration)
{
    EmptyCb fail = boost::bind(&Authenticator::generate_host_name,
                               this, dladdr, nwaddr, owns_dl, cb);

    // Doesn't own MAC interface, should generate name based on IP only
    if (!owns_dl && nwaddr != 0) {
        host_info.netinfos[0].nwaddr = nwaddr;
        if (!dirmanager->search_hosts(host_info, nwkey, "",
                                      boost::bind(&Authenticator::get_principal,
                                                  this, _1, cb, fail), fail))
        {
            fail();
        }
        return;
    }

    iteration = iteration+1;
    if (iteration != 3) {
        if (iteration == 1) {
            host_info.netinfos[0].dladdr = dladdr;
            EmptyCb none = boost::bind(&Authenticator::get_host,
                                       this, dp, port, dladdr, nwaddr,
                                       cb, owns_dl, iteration);
            if (!dirmanager->search_hosts(host_info, dlkey, "",
                                          boost::bind(&Authenticator::get_principal,
                                                      this, _1, cb, none), fail))
            {
                fail();
            }
            return;
        } else if (nwaddr != 0) {
            host_info.netinfos[0].nwaddr = nwaddr;
            EmptyCb none = boost::bind(&Authenticator::get_host,
                                       this, dp, port, dladdr, nwaddr,
                                       cb, owns_dl, iteration);
            if (!dirmanager->search_hosts(host_info, nwkey, "",
                                          boost::bind(&Authenticator::get_principal,
                                                      this, _1, cb, none), fail))
            {
                fail();
            }
            return;
        } else {
            ++iteration;
        }
    }

    host_info.netinfos[0].dpid = dp;
    host_info.netinfos[0].port = port;
    if (!dirmanager->search_hosts(host_info, lockey, "",
                                  boost::bind(&Authenticator::get_principal,
                                              this, _1, cb, fail), fail))
    {
        fail();
    }
}

void
Authenticator::generate_host_name(const ethernetaddr& dladdr,
                                  uint32_t nwaddr, bool dlname,
                                  const StringCb& cb)
{
    EmptyCb fail = boost::bind(&Authenticator::return_unknown, this, cb);

    if (!dirmanager->get_discovered_host_name(dladdr, nwaddr, dlname, false,
                                              cb, fail))
    {
        fail();
    }
}

void
Authenticator::get_principal(const std::vector<std::string>& rnames,
                             const StringCb& success, const EmptyCb& failcb)
{
    if (rnames.empty()) {
        failcb();
    } else {
        success(rnames[0]);
    }
}

void
Authenticator::return_unknown(const StringCb& cb)
{
    cb(get_unknown_name());
}

Disposition
Authenticator::delname_location(const Event& e)
{
    const Location_delete_event& ld = assert_cast<const Location_delete_event&>(e);

    uint64_t loc = ld.dpid.as_host() + (((uint64_t)(ld.port)) << 48);
    delname_location2(ld.oldname, ld.newname, ld.dpid, ld.port, loc);

    return CONTINUE;
}

void
Authenticator::delname_location2(const std::string& oldname, const std::string& newname,
                                 const datapathid& dpid, uint16_t port, uint64_t loc)
{
    GroupInfoMap::iterator location = locations.find(loc);
    if (location != locations.end()) {
        if (location->second.status.locked) {
            location->second.status.waiters.push_back(
                boost::bind(&Authenticator::delname_location2, this, oldname,
                            newname, dpid, port, loc));
            VLOG_DBG(lg, "Queuing location delete %"PRIx64".", loc);
            return;
        }
        remove_loc_hosts(loc, true, " (location delete)");
        rename(oldname, newname, Directory::LOCATION_PRINCIPAL, EMPTY_GROUP, true);
        bindings->remove_name_for_location(dpid, port, oldname, Name::LOCATION);
        bindings->add_name_for_location(dpid, port, newname, Name::LOCATION);
        decrement_ids(location->second.groups);
        location->second.groups.clear();
        get_info_groups(&location->second, newname, Directory::LOCATION_PRINCIPAL);
    } else {
        rename(oldname, newname, Directory::LOCATION_PRINCIPAL, EMPTY_GROUP, true);
    }
}

// race conditions?!

Disposition
Authenticator::rename_principal(const Event& e)
{
    const Principal_name_event& pn = assert_cast<const Principal_name_event&>(e);
    VLOG_DBG(lg, "Rename from %s to %s.", pn.oldname.c_str(), pn.newname.c_str());

    if (!rename(pn.oldname, pn.newname, pn.type, EMPTY_GROUP, true)
        || pn.newname != "")
    {
        return CONTINUE;
    }

    if (pn.type == Directory::HOST_PRINCIPAL) {
        remove_hosts(true, " (host delete)",
                     boost::bind(&Authenticator::remove_host,
                                 this, _1, _2, _3, pn.oldname));
    } else if (pn.type == Directory::USER_PRINCIPAL) {
        map_conns(boost::bind(&Authenticator::delname_user,
                              this, _1, _2, _3, _4, true),
                  pn.oldname, pn.type, EMPTY_GROUP, true);
    }

    return CONTINUE;
}

Directory::Principal_Type
get_ptype(Directory::Group_Type gtype)
{
    switch(gtype) {
    case Directory::SWITCH_PRINCIPAL_GROUP:
        return Directory::SWITCH_PRINCIPAL;
    case Directory::LOCATION_PRINCIPAL_GROUP:
        return Directory::LOCATION_PRINCIPAL;
    case Directory::HOST_PRINCIPAL_GROUP:
        return Directory::HOST_PRINCIPAL;
    case Directory::USER_PRINCIPAL_GROUP:
        return Directory::USER_PRINCIPAL;
    default:
        return EMPTY_PRINCE;
    }
}

Disposition
Authenticator::rename_group(const Event& e)
{
    const Group_name_event& ge = assert_cast<const Group_name_event&>(e);

    if (!rename(ge.oldname, ge.newname, EMPTY_PRINCE, ge.type, false)
        || ge.newname != "")
    {
        return CONTINUE;
    }

    group_change(get_ptype(ge.type), ge.type, ge.oldname, false);
    return CONTINUE;
}

Disposition
Authenticator::modify_group(const Event& e)
{
    const Group_change_event& gce = assert_cast<const Group_change_event&>(e);

    bool subgroup = gce.change_type == Group_change_event::ADD_SUBGROUP
        || gce.change_type == Group_change_event::DEL_SUBGROUP;

    VLOG_DBG(lg, "Group %s change %s sub:%c.", gce.group_name.c_str(),
             gce.change_name.c_str(), subgroup ? 'T' : 'F');

    group_change(get_ptype(gce.type), gce.type, gce.change_name, !subgroup);
    return CONTINUE;
}

void
Authenticator::group_change(Directory::Principal_Type ptype, Directory::Group_Type gtype,
                            const std::string& change_name, bool is_principal)
{
    MapInfoFn info_fn;
    MapConnFn conn_fn;
    if (!is_principal) {
        if (gtype == Directory::DLADDR_GROUP || gtype == Directory::NWADDR_GROUP) {
            conn_fn = boost::bind(&Authenticator::mod_if_has_addr_group, this,
                                  _1, _2, _3, _4);
        } else {
            info_fn = boost::bind(&Authenticator::mod_if_info_has_group,
                                  this, _1, _2, _3, ptype);
            conn_fn = boost::bind(&Authenticator::mod_if_has_group, this,
                                  _1, _2, _3, _4, gtype);
        }
    } else {
        if (ptype == Directory::LOCATION_PRINCIPAL
            || ptype == Directory::HOST_PRINCIPAL
            || ptype == Directory::USER_PRINCIPAL)
        {
            conn_fn = boost::bind(&Authenticator::mod_if_is_principal,
                                  this, _1, _2, _3, _4, ptype);
            info_fn = boost::bind(&Authenticator::mod_if_info_is_principal,
                                  this, _1, _2, _3, ptype);
        } else if (ptype == Directory::SWITCH_PRINCIPAL) {
            info_fn = boost::bind(&Authenticator::mod_if_is_switch,
                                  this, _1, _2, _3);
        } else if (gtype == Directory::DLADDR_GROUP) {
            uint64_t dladdr = ethernetaddr(change_name).hb_long();
            map_dlconns(dladdr, boost::bind(&Authenticator::mod_if_is_dladdr,
                                            this, _1, _2, _3, _4, dladdr),
                        "temp_addr_group", EMPTY_PRINCE, gtype, false);
            return;
        } else if (gtype == Directory::NWADDR_GROUP) {
            cidr_ipaddr cidr(change_name);
            uint32_t nwaddr = ntohl(cidr.addr.addr);
            uint32_t mask = ntohl(cidr.mask);
            map_conns(boost::bind(&Authenticator::mod_if_is_nwaddr,
                                  this, _1, _2, _3, _4, nwaddr, mask),
                      "temp_addr_group", EMPTY_PRINCE, gtype, false);
            return;
        }
    }

    switch (gtype) {
    case Directory::SWITCH_PRINCIPAL_GROUP:
        map_info(&unauth_sw_groups, info_fn, change_name,
                 ptype, gtype, is_principal);
        map_infos(&switches, info_fn, change_name, ptype,
                  gtype, is_principal);
        break;
    case Directory::LOCATION_PRINCIPAL_GROUP:
        map_info(&unauth_loc_groups, info_fn, change_name,
                 ptype, gtype, is_principal);
        map_infos(&locations, info_fn, change_name, ptype,
                  gtype, is_principal);
        break;
    case Directory::HOST_PRINCIPAL_GROUP:
        map_info(&unauth_host_groups, info_fn, change_name,
                 ptype, gtype, is_principal);
        break;
    case Directory::USER_PRINCIPAL_GROUP:
        map_info(&unauth_user_groups, info_fn, change_name,
                 ptype, gtype, is_principal);
        break;
    case Directory::DLADDR_GROUP:
    case Directory::NWADDR_GROUP:
        if (is_principal) {
            VLOG_ERR(lg, "Do not expect to reach here with is_principal == true.");
        }
        break;
    default:
        VLOG_WARN(lg, "Cannot modify unknown group type %u.", gtype);
        return;
    }

    if (!conn_fn.empty()) {
        map_conns(conn_fn, change_name, ptype, gtype, is_principal);
    }

    return;
}

void
Authenticator::map_conns(const MapConnFn& fn,
                         const std::string& name,
                         Directory::Principal_Type ptype,
                         Directory::Group_Type gtype, bool is_principal)
{
    uint32_t id = get_id(name, ptype, gtype, is_principal, false);

    for (HostMap::iterator dlconns = hosts.begin();
         dlconns != hosts.end(); ++dlconns)
    {
        if (dlconns->second.status.locked) {
            dlconns->second.status.waiters.push_back(
                boost::bind(&Authenticator::map_dlconns, this,
                            dlconns->first, fn, name,
                            ptype, gtype, is_principal));
            VLOG_DBG(lg, "Queueing map_conns %"PRIx64".",
                     dlconns->first);
        } else {
            map_nwconns(dlconns, fn, id, is_principal, gtype);
        }
    }
}

void
Authenticator::map_dlconns(uint64_t dladdr,
                           const MapConnFn& fn,
                           const std::string& name,
                           Directory::Principal_Type ptype,
                           Directory::Group_Type gtype, bool is_principal)
{
    HostMap::iterator dlconns = hosts.find(dladdr);
    if (dlconns == hosts.end()) {
        return;
    } else if (dlconns->second.status.locked) {
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::map_dlconns, this,
                        dladdr, fn, name, ptype, gtype,
                        is_principal));
        VLOG_DBG(lg, "Queueing map_dlconns %"PRIx64".",
                 dladdr);
        return;
    }

    uint32_t id = get_id(name, ptype, gtype, is_principal, false);
    map_nwconns(dlconns, fn, id, is_principal, gtype);
}

void
Authenticator::map_nwconns(HostMap::iterator& dlconns,
                           const MapConnFn& fn, uint32_t id,
                           bool is_principal, Directory::Group_Type gtype)
{
    if (!is_principal && (gtype == Directory::DLADDR_GROUP
                          || gtype == Directory::NWADDR_GROUP))
    {
        ConnPtr empty;
        for (NWMap::iterator nwconns = dlconns->second.nws.begin();
             nwconns != dlconns->second.nws.end(); ++nwconns)
        {
            fn(empty, dlconns, nwconns, id);
        }
    } else {
        for (NWMap::iterator nwconns = dlconns->second.nws.begin();
             nwconns != dlconns->second.nws.end(); ++nwconns)
        {
            for (ConnList::iterator conn = nwconns->second.conns.begin();
                 conn != nwconns->second.conns.end(); ++conn)
            {
                fn(*conn, dlconns, nwconns, id);
            }
        }
    }
}

void
Authenticator::map_infos(GroupInfoMap *infos,
                         const MapInfoFn& fn,
                         const std::string& name,
                         Directory::Principal_Type ptype,
                         Directory::Group_Type gtype, bool is_principal)
{
    uint32_t id = get_id(name, ptype, gtype, is_principal, false);
    for (GroupInfoMap::iterator info = infos->begin();
         info != infos->end(); ++info)
    {
        if (info->second.status.locked) {
            info->second.status.waiters.push_back(
                boost::bind(&Authenticator::map_info, this,
                            infos, info->first, fn, name,
                            ptype, gtype, is_principal));
            VLOG_DBG(lg, "Queueing map_info %"PRIx64".", info->first);
        } else {
            fn(info->second, info->first, id);
        }
    }
}

void
Authenticator::map_info(GroupInfoMap *infos, uint64_t key,
                        const MapInfoFn& fn,
                        const std::string& name,
                        Directory::Principal_Type ptype,
                        Directory::Group_Type gtype,
                        bool is_principal)
{
    GroupInfoMap::iterator info = infos->find(key);
    if (info == infos->end()) {
        return;
    } else if (info->second.status.locked) {
        info->second.status.waiters.push_back(
            boost::bind(&Authenticator::map_info, this,
                        infos, key, fn, name, ptype,
                        gtype, is_principal));
        VLOG_DBG(lg, "Queuing map_info.");
        return;
    }

    uint32_t id = get_id(name, ptype, gtype, is_principal, false);
    fn(info->second, key, id);
}

void
Authenticator::map_info(GroupInfo *info, const MapInfoFn& fn,
                        const std::string& name,
                        Directory::Principal_Type ptype,
                        Directory::Group_Type gtype,
                        bool is_principal)
{
    if (info->status.locked) {
        info->status.waiters.push_back(
            boost::bind(&Authenticator::map_info,
                        this, info, fn, name, ptype, gtype, is_principal));
        VLOG_DBG(lg, "Queuing map_info.");
        return;
    }

    uint32_t id = get_id(name, ptype, gtype, is_principal, false);
    fn(*info, 0, id);
}

// NWEntry if locked, will have been locked by same renaming, so can assume
// it will not be deleted

void
Authenticator::lock_and_set_agroups(uint64_t dladdr, uint32_t nwaddr,
                                    NWEntry *nwentry)
{
    if (nwentry->status->locked) {
        nwentry->status->waiters.push_back(
            boost::bind(&Authenticator::lock_and_set_agroups,
                        this, dladdr, nwaddr, nwentry));
    } else {
        nwentry->status->locked = true;
        decrement_ids(*(nwentry->addr_groups));
        nwentry->addr_groups->clear();
        set_addr_groups(ethernetaddr(dladdr), nwaddr,
                        nwentry, boost::bind(&Authenticator::unlock_status,
                                             this, nwentry->status), true);
    }
}


void
Authenticator::lock_and_set_hgroups(const ConnPtr& conn,
                                    NWEntry *nwentry)
{
    if (nwentry->status->locked) {
        nwentry->status->waiters.push_back(
            boost::bind(&Authenticator::lock_and_set_hgroups,
                        this, conn, nwentry));
    } else {
        nwentry->status->locked = true;
        // gets_incr by set_host_groups
        decrement_id(conn->ap);
        decrement_ids(conn->hostgroups);
        conn->hostgroups.clear();
        set_host_groups(conn, boost::bind(&Authenticator::unlock_status,
                                          this, nwentry->status), true);
    }
}

void
Authenticator::lock_and_set_ugroups(std::list<user_info>::iterator u,
                                    NWEntry *nwentry)
{
    if (nwentry->status->locked) {
        nwentry->status->waiters.push_back(
            boost::bind(&Authenticator::lock_and_set_ugroups,
                        this, u, nwentry));
    } else {
        nwentry->status->locked = true;
        decrement_ids(u->groups);
        u->groups.clear();
        set_user_groups(u, boost::bind(&Authenticator::unlock_status,
                                       this, nwentry->status), true);
    }
}

void
Authenticator::delname_user(const ConnPtr& conn, HostMap::iterator& dlconns,
                            NWMap::iterator& nwconns, uint32_t id, bool deleted)
{
    std::list<user_info>::iterator u;
    if (contains_user(conn, id, u)) {
        remove_user(conn, u, datapathid::from_host(conn->location & DP_MASK),
                    (uint16_t)(conn->location >> 48),
                    ethernetaddr(dlconns->first),
                    conn->n_bindings == 1 ? nwconns->first : 0, true,
                    deleted ? " (user delete)" : " (user deauthenticate)", true);
        if (conn->users.empty()) {
            conn->users.push_back(user_info());
            std::list<user_info>::iterator u = conn->users.begin();
            u->user = UNAUTHENTICATED_ID;
            lock_and_set_ugroups(u, &nwconns->second);
        }
    }
}


void
Authenticator::mod_if_is_dladdr(const ConnPtr& conn,
                                HostMap::iterator& dlconns,
                                NWMap::iterator& nwconns, uint32_t id,
                                uint64_t dladdr)
{
    if (dlconns->first == dladdr) {
        lock_and_set_agroups(dladdr, nwconns->first, &nwconns->second);
    }
}

void
Authenticator::mod_if_is_nwaddr(const ConnPtr& conn,
                                HostMap::iterator& dlconns,
                                NWMap::iterator& nwconns, uint32_t id,
                                uint32_t nwaddr, uint32_t mask)
{
    if ((nwconns->first & mask) == nwaddr) {
        lock_and_set_agroups(dlconns->first, nwconns->first, &nwconns->second);
    }
}

void
Authenticator::mod_if_has_addr_group(const ConnPtr& conn,
                                     HostMap::iterator& dlconns,
                                     NWMap::iterator& nwconns, uint32_t id)
{
    if (contains_group(*(nwconns->second.addr_groups), id)) {
        lock_and_set_agroups(dlconns->first, nwconns->first, &nwconns->second);
    }
}

void
Authenticator::mod_if_is_switch(GroupInfo& info, uint64_t dpid,
                                uint32_t id)
{
    if (info.id != id) {
        return;
    }

    decrement_ids(info.groups);
    info.groups.clear();
    get_info_groups(&info, get_name(id), Directory::SWITCH_PRINCIPAL);

    if (dpid != 0) {
        map_conns(boost::bind(&Authenticator::mod_if_on_switch, this,
                              _1, _2, _3, _4, dpid),
                  get_unauthenticated_name(), Directory::HOST_PRINCIPAL, EMPTY_GROUP, true);
    }
}

void
Authenticator::mod_if_info_is_principal(GroupInfo& info, uint64_t key,
                                        uint32_t id, Directory::Principal_Type ptype)
{
    if (info.id != id) {
        return;
    }

    decrement_ids(info.groups);
    info.groups.clear();
    get_info_groups(&info, get_name(id), ptype);
}


void
Authenticator::mod_if_info_has_group(GroupInfo& info, uint64_t key, uint32_t id,
                                     Directory::Principal_Type ptype)
{
    if (!contains_group(info.groups, id)) {
        return;
    }

    decrement_ids(info.groups);
    info.groups.clear();
    get_info_groups(&info, get_name(info.id), ptype);
}

void
Authenticator::mod_if_on_switch(const ConnPtr& conn,
                                HostMap::iterator& dlconns,
                                NWMap::iterator& nwconns, uint32_t id,
                                uint64_t dpid)
{
    if ((conn->location & DP_MASK) != dpid) {
        return;
    }

    lock_and_set_hgroups(conn, &nwconns->second);
}

void
Authenticator::mod_if_is_principal(const ConnPtr& conn,
                                   HostMap::iterator& dlconns,
                                   NWMap::iterator& nwconns, uint32_t id,
                                   Directory::Principal_Type ptype)
{
    std::list<user_info>::iterator u;
    switch (ptype) {
    case Directory::LOCATION_PRINCIPAL:
        if (conn->ap != id) {
            return;
        }
        lock_and_set_hgroups(conn, &nwconns->second);
        return;
    case Directory::HOST_PRINCIPAL:
        if (conn->host != id) {
            return;
        }
        lock_and_set_hgroups(conn, &nwconns->second);
        return;
    case Directory::USER_PRINCIPAL:
        if (!contains_user(conn, id, u)) {
            return;
        }
        lock_and_set_ugroups(u, &nwconns->second);
        return;
    default:
        VLOG_ERR(lg, "Cannot mod group membership of unknown ptype %u.", ptype);
        return;
    }
}


void
Authenticator::mod_if_has_group(const ConnPtr& conn,
                                HostMap::iterator& dlconns,
                                NWMap::iterator& nwconns, uint32_t id,
                                Directory::Group_Type gtype)
{
    std::list<user_info>::iterator u;
    switch (gtype) {
    case Directory::SWITCH_PRINCIPAL_GROUP:
    case Directory::LOCATION_PRINCIPAL_GROUP:
    case Directory::HOST_PRINCIPAL_GROUP:
        if (!contains_group(conn->hostgroups, id)) {
            return;
        }
        lock_and_set_hgroups(conn, &nwconns->second);
        return;
    case Directory::USER_PRINCIPAL_GROUP:
        for (u = conn->users.begin(); u != conn->users.end(); ++u) {
            if (contains_group(u->groups, id)) {
                lock_and_set_ugroups(u, &nwconns->second);
            }
        }
        return;
    default:
        VLOG_ERR(lg, "Cannot mod group membership of unknown gtype %u.", gtype);
        return;
    }
}


bool
Authenticator::contains_group(std::vector<uint32_t>& groups, uint32_t id)
{
    for (std::vector<uint32_t>::iterator g = groups.begin();
         g != groups.end(); ++g)
    {
        if (*g == id) {
            return true;
        } else if (*g > id) {
            return false;
        }
    }
    return false;
}

bool
Authenticator::contains_group(std::list<uint32_t>& groups, uint32_t id)
{
    for (std::list<uint32_t>::iterator g = groups.begin();
         g != groups.end(); ++g)
    {
        if (*g == id) {
            return true;
        } else if (*g > id) {
            return false;
        }
    }
    return false;
}

}
}
