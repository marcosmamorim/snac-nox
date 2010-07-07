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
#include <boost/shared_array.hpp>
#include <inttypes.h>

#include "assert.hh"
#include "bindings_storage/bindings_storage.hh"
#include "directory/netinfo_mod_event.hh"
#include "vlog.hh"

#define DP_MASK         0xffffffffffffULL
#define ADDR_TIMEOUT    600

#define EMPTY_PRINCE     ((Directory::Principal_Type)UINT32_MAX)
#define EMPTY_GROUP      ((Directory::Group_Type)UINT32_MAX)

namespace vigil {
namespace applications {

static Vlog_module lg("authenticator");

static const std::string app_name("authenticator");

bool
Authenticator::host_exists(const ethernetaddr& dladdr, uint32_t nwaddr) const
{
    HostMap::const_iterator dlconns(hosts.find(dladdr.hb_long()));
    NWMap::const_iterator nwconns;

    if (dlconns != hosts.end()) {
        if ((nwconns = dlconns->second.nws.find(nwaddr)) != dlconns->second.nws.end()) {
            return !nwconns->second.conns.empty();
        }
    }
    return false;
}

void
Authenticator::get_dlconns(const ethernetaddr& dladdr, const DLEntryCb& cb)
{
    HostMap::iterator dlconns = hosts.find(dladdr.hb_long());
    HostMap::const_iterator dlconns_const = dlconns;

    if (dlconns != hosts.end()) {
        if (dlconns->second.status.locked) {
            dlconns->second.status.waiters.push_back(
                boost::bind(&Authenticator::get_dlconns, this, dladdr, cb));
        } else {
            cb(true, dlconns_const);
        }
        return;
    }
    cb(false, dlconns_const);
}

void
Authenticator::get_nwconns(const ethernetaddr& dladdr, uint32_t nwaddr,
                           const NWEntryCb& cb)
{
    HostMap::iterator dlconns(hosts.find(dladdr.hb_long()));
    NWMap::iterator nwconns;
    NWMap::const_iterator nwconns_const;

    if (dlconns != hosts.end()) {
        if (dlconns->second.status.locked) {
            dlconns->second.status.waiters.push_back(
                boost::bind(&Authenticator::get_nwconns, this, dladdr, nwaddr, cb));
            return;
        }

        if ((nwconns = dlconns->second.nws.find(nwaddr)) != dlconns->second.nws.end()) {
            nwconns_const = nwconns;
            cb(true, nwconns_const);
            return;
        }
    }
    cb(false, nwconns_const);
}

void
Authenticator::get_conn(const datapathid& dpid, uint16_t port,
                        const ethernetaddr& dladdr, uint32_t nwaddr,
                        const ConnEntryCb& cb)
{
    HostMap::iterator dlconns(hosts.find(dladdr.hb_long()));
    NWMap::iterator nwconns;
    ConnList::iterator conn;
    ConnList::const_iterator conn_const;

    if (dlconns != hosts.end()) {
        if (dlconns->second.status.locked) {
            dlconns->second.status.waiters.push_back(
                boost::bind(&Authenticator::get_conn, this,
                            dpid, port, dladdr, nwaddr, cb));
            return;
        }

        if ((nwconns = dlconns->second.nws.find(nwaddr)) != dlconns->second.nws.end()) {
            if (get_conn(dpid.as_host() + (((uint64_t)port) << 48), nwconns->second, conn)) {
                conn_const = conn;
                cb(true, conn_const);
                return;
            }
        }
    }
    cb(false, conn_const);
}

void
Authenticator::new_switch(const datapathid& dpid)
{
    uint64_t dp = dpid.as_host();
    GroupInfoMap::iterator sw = switches.find(dp);
    if (sw != switches.end()) {
        if (sw->second.status.locked) {
            sw->second.status.waiters.push_back(
                boost::bind(&Authenticator::new_switch, this, dpid));
            VLOG_DBG(lg, "Queuing new switch %"PRIx64".", dp);
            return;
        }
        sw->second.status.locked = true;
        decrement_id(sw->second.id);
        decrement_ids(sw->second.groups);
        sw->second.groups.clear();
    } else {
        sw = switches.insert(std::make_pair(dp, SwitchGroupInfo())).first;
        sw->second.status.locked = true;
    }
    get_switch(dpid, boost::bind(&Authenticator::new_switch_name,
                                 this, _1, dpid, &sw->second));
}


void
Authenticator::new_switch_name(const std::string& name,
                               const datapathid& dpid, SwitchGroupInfo *info)
{
    bindings->add_name_for_location(dpid, 0, name, Name::SWITCH);

    LogEntry to_log = LogEntry(app_name, LogEntry::ALERT,
                               "{ss} joined the network.");
    to_log.setName(name, Name::SWITCH, LogEntry::SRC);
    user_log->log(to_log);

    info->id = get_id(name, Directory::SWITCH_PRINCIPAL,
                      EMPTY_GROUP, true, true);
    get_info_groups(info, name, Directory::SWITCH_PRINCIPAL);
}


void
Authenticator::remove_switch(const datapathid& dpid)
{
    GroupInfoMap::iterator sw = switches.find(dpid.as_host());
    if (sw != switches.end()) {
        if (sw->second.status.locked) {
            sw->second.status.waiters.push_back(
                boost::bind(&Authenticator::remove_switch, this, dpid));
            VLOG_DBG(lg, "Queuing rm switch %"PRIx64".", dpid.as_host());
            return;
        }

        LogEntry to_log = LogEntry(app_name, LogEntry::ALERT,
                                   "{ss} left the network.");
        to_log.setName(get_name(sw->second.id), Name::SWITCH, LogEntry::SRC);
        user_log->log(to_log);

        bindings->remove_name_for_location(dpid, 0, "", Name::SWITCH);
        decrement_id(sw->second.id);
        decrement_ids(sw->second.groups);
        switches.erase(sw);
    }
}

void
Authenticator::new_location(const datapathid &dpid, uint16_t port,
                            uint64_t loc, const std::string& port_name)
{
    GroupInfoMap::iterator location = locations.find(loc);
    if (location != locations.end()) {
        if (location->second.status.locked) {
            location->second.status.waiters.push_back(
                boost::bind(&Authenticator::new_location,
                            this, dpid, port, loc, port_name));
            VLOG_DBG(lg, "Queuing new location %"PRIx64".", loc);
            return;
        }
        location->second.status.locked = true;
        decrement_id(location->second.id);
        decrement_ids(location->second.groups);
        location->second.groups.clear();
    } else {
        location = locations.insert(std::make_pair(loc, LocGroupInfo())).first;
        location->second.status.locked = true;
    }
    get_location(dpid, port, port_name,
                 boost::bind(&Authenticator::new_location_name,
                             this, _1, dpid, port, port_name,
                             &location->second));
}


void
Authenticator::new_location_name(const std::string& name,
                                 const datapathid& dpid, uint16_t port,
                                 const std::string& port_name, LocGroupInfo *info)
{
    bindings->add_name_for_location(dpid, port, name, Name::LOCATION);
    bindings->add_name_for_location(dpid, port, port_name, Name::PORT);

    info->id = get_id(name, Directory::LOCATION_PRINCIPAL,
                      EMPTY_GROUP, true, true);
    get_info_groups(info, name, Directory::LOCATION_PRINCIPAL);
}

// remove from bindings here?
void
Authenticator::remove_location(const datapathid& dpid, uint16_t port,
                               uint64_t loc)
{
    GroupInfoMap::iterator location = locations.find(loc);
    if (location != locations.end()) {
        if (location->second.status.locked) {
            location->second.status.waiters.push_back(
                boost::bind(&Authenticator::remove_location, this, dpid, port, loc));
            VLOG_DBG(lg, "Queuing rm location %"PRIx64".", loc);
            return;
        }
        bindings->remove_name_for_location(dpid, port, "", Name::LOCATION);
        bindings->remove_name_for_location(dpid, port, "", Name::PORT);
        decrement_id(location->second.id);
        decrement_ids(location->second.groups);
        locations.erase(location);
    }
}


void
Authenticator::remove_dp_locations(const datapathid& dpid, uint64_t dpint,
                                   const hash_set<uint64_t>& valid_locs,
                                   bool remove_all)
{
    for (GroupInfoMap::iterator loc = locations.begin();
         loc != locations.end();)
    {
        if ((loc->first & DP_MASK) == dpint
            && (remove_all || valid_locs.find(loc->first) == valid_locs.end()))
        {
            if (loc->second.status.locked) {
                loc->second.status.waiters.push_back(
                    boost::bind(&Authenticator::remove_location, this, dpid,
                                (uint16_t)(loc->first >> 48), loc->first));
                VLOG_DBG(lg, "Queuing rm dp location %"PRIx64".", loc->first);
                ++loc;
            } else {
                uint16_t port = (uint16_t)(loc->first >> 48);
                bindings->remove_name_for_location(dpid, port, "", Name::LOCATION);
                bindings->remove_name_for_location(dpid, port, "", Name::PORT);
                decrement_id(loc->second.id);
                decrement_ids(loc->second.groups);
                locations.erase(loc++);
            }
        } else {
            ++loc;
        }
    }
}


void
Authenticator::new_nw_entry(HostMap::iterator& dlconns,
                            NWMap::iterator& nwconns,
                            const ethernetaddr& dladdr,
                            bool unlock)
{
    NWEntry *nwentry = &nwconns->second;
    nwconns->second.status = &(dlconns->second.status);
    if (nwconns->first == 0) {
        dlconns->second.zero = nwentry;
    }
    set_addr_groups(dladdr, nwconns->first, nwentry,
                    boost::bind(&Authenticator::new_nw_entry2, this, nwentry, unlock),
                    true);
}

void
Authenticator::new_nw_entry2(NWEntry *nwentry, bool unlock)
{
    nwentry->timeout = time(NULL) + ADDR_TIMEOUT;
    bool empty = nwentry->status->waiters.empty();
    if (unlock || empty) {
        unlock_status(nwentry->status);
    } else {
        EmptyCb cb = nwentry->status->waiters.front();
        nwentry->status->waiters.pop_front();
        cb();
    }
}

void
Authenticator::set_addr_groups(const ethernetaddr& dladdr, uint32_t nwaddr,
                               NWEntry *nwentry, const EmptyCb& cb, bool incr)
{
    std::list<uint32_t> empty;
    ListCb success = boost::bind(&Authenticator::set_addr_groups2,
                                 this, _1, nwaddr, nwentry, cb, incr);
    EmptyCb fail = boost::bind(&Authenticator::set_addr_groups2,
                               this, empty, nwaddr, nwentry, cb, incr);

    if (!dirmanager->search_dladdr_groups(dladdr, "", true,
                                          boost::bind(&Authenticator::translate_groups,
                                                      this, _1, Directory::DLADDR_GROUP,
                                                      success, incr), fail))
    {
        fail();
    }
}


void
Authenticator::set_addr_groups2(const std::list<uint32_t>& dlgroups,
                                uint32_t nwaddr, NWEntry *nwentry,
                                const EmptyCb& cb, bool incr)
{
    std::list<uint32_t> empty;
    ListCb success = boost::bind(&Authenticator::set_addr_groups3,
                                 this, dlgroups, _1, nwentry, cb);
    EmptyCb fail = boost::bind(&Authenticator::set_addr_groups3,
                               this, dlgroups, empty, nwentry, cb);

    if (!dirmanager->search_nwaddr_groups(nwaddr, "", true,
                                          boost::bind(&Authenticator::translate_groups,
                                                      this, _1, Directory::NWADDR_GROUP,
                                                      success, incr), fail))
    {
        fail();
    }
}


void
Authenticator::set_addr_groups3(const std::list<uint32_t>& dlgroups,
                                const std::list<uint32_t>& nwgroups,
                                NWEntry *nwentry, const EmptyCb& cb)
{
    nwentry->addr_groups.reset(new std::vector<uint32_t>(
                                   dlgroups.size() + nwgroups.size()));
    merge_group_lists(&dlgroups, &nwgroups, NULL, *(nwentry->addr_groups));
    cb();
}


// Add a host Connector to the map.

void
Authenticator::new_dl_entry(HostMap::iterator& dlconns,
                            const ethernetaddr& dladdr, bool unlock)
{
    is_router(dladdr, boost::bind(&Authenticator::new_dl2,
                                  this, _1, &dlconns->second, dladdr, unlock));
}

void
Authenticator::new_dl2(bool router, DLEntry *dlentry,
                       const ethernetaddr& dladdr, bool unlock)
{
    dlentry->router = router;
    is_gateway(dladdr, boost::bind(&Authenticator::new_dl3,
                                   this, _1, dlentry, unlock));
}

void
Authenticator::new_dl3(bool gateway, DLEntry *dlentry, bool unlock)
{
    dlentry->gateway = gateway;
    NWMap::iterator zero = dlentry->nws.find(0);
    if (zero == dlentry->nws.end()) {
        dlentry->zero = NULL;
    } else {
        dlentry->zero = &zero->second;
    }

    // happens in unlock_auth
    if (unlock || dlentry->status.waiters.empty()) {
        unlock_status(&(dlentry->status));
    } else {
        EmptyCb cb = dlentry->status.waiters.front();
        dlentry->status.waiters.pop_front();
        cb();
    }
}


void
Authenticator::get_info_groups(GroupInfo *info, const std::string& name,
                               Directory::Principal_Type ptype)
{
    info->status.locked = true;
    get_groups(name, ptype, boost::bind(&Authenticator::get_info_groups2,
                                        this, _1, info), true);
}

void
Authenticator::get_info_groups2(std::list<uint32_t>& groups, GroupInfo *info)
{
    info->groups.swap(groups);
    unlock_status(&(info->status));
}

void
Authenticator::merge_group_lists(const std::list<uint32_t> *one,
                                 const std::list<uint32_t> *two,
                                 const std::list<uint32_t> *three,
                                 std::vector<uint32_t>& merged)
{
    merged.resize(one->size() + two->size() + (three == NULL ? 0 : three->size()));
    std::list<uint32_t>::const_iterator iter1 = one->begin();
    std::list<uint32_t>::const_iterator iter2 = two->begin();
    std::list<uint32_t>::const_iterator iter3;
    if (three != NULL) {
        iter3 = three->begin();
    }

    uint32_t i = 0;
    while (true) {
        if (three != NULL && iter3 == three->end()) {
            three = NULL;
        }

        if (iter1 == one->end()) {
            if (three == NULL) {
                while (iter2 != two->end()) {
                    merged[i++] = *(iter2++);
                }
                return;
            } else {
                iter1 = iter3;
                one = three;
                three = NULL;
            }
        }

        if (iter2 == two->end()) {
            if (three == NULL) {
                while (iter1 != one->end()) {
                    merged[i++] = *(iter1++);
                }
                return;
            } else {
                iter2 = iter3;
                two = three;
                three = NULL;
            }
        }

        if (three == NULL) {
            if (*iter1 < *iter2) {
                merged[i++] = *(iter1++);
            } else {
                merged[i++] = *(iter2++);
            }
        } else if (*iter1 < *iter2) {
            if (*iter1 < *iter3) {
                merged[i++] = *(iter1++);
            } else {
                merged[i++] = *(iter3++);
            }
        } else if (*iter2 < *iter3) {
            merged[i++] = *(iter2++);
        } else {
            merged[i++] = *(iter3++);
        }
    }
}


void
Authenticator::translate_groups(const std::vector<std::string>& groups,
                                Directory::Group_Type type, const ListCb& cb,
                                bool incr)
{
    std::list<uint32_t> translated;
    for (std::vector<std::string>::const_iterator iter = groups.begin();
         iter != groups.end(); ++iter)
    {
        bool inserted = false;
        uint32_t group = get_id(*iter, EMPTY_PRINCE, type, false, incr);
        for (std::list<uint32_t>::iterator pos = translated.begin();
             pos !=  translated.end(); ++pos)
        {
            if (group < *pos) {
                translated.insert(pos, group);
                inserted = true;
                break;
            } else if (group == *pos) {
                inserted = true;
                break;
            }
        }
        if (!inserted) {
            translated.push_back(group);
        }
    }

    cb(translated);
}

void
Authenticator::get_groups(const std::string& name,
                          Directory::Principal_Type type, const ListCb& cb,
                          bool incr)
{
    std::list<uint32_t> empty;
    EmptyCb fail = boost::bind(cb, empty);
    bool ret = false;
    switch (type) {
    case Directory::SWITCH_PRINCIPAL:
        ret = dirmanager->search_switch_groups(name, "", true,
                                               boost::bind(&Authenticator::translate_groups,
                                                           this, _1,
                                                           Directory::SWITCH_PRINCIPAL_GROUP,
                                                           cb, incr), fail);
        break;
    case Directory::LOCATION_PRINCIPAL:
        ret = dirmanager->search_location_groups(name, "", true,
                                                 boost::bind(&Authenticator::translate_groups,
                                                             this, _1,
                                                             Directory::LOCATION_PRINCIPAL_GROUP,
                                                             cb, incr), fail);
        break;
    case Directory::HOST_PRINCIPAL:
        ret = dirmanager->search_host_groups(name, "", true,
                                             boost::bind(&Authenticator::translate_groups,
                                                         this, _1,
                                                         Directory::HOST_PRINCIPAL_GROUP,
                                                         cb, incr), fail);
        break;
    case Directory::USER_PRINCIPAL:
        ret = dirmanager->search_user_groups(name, "", true,
                                             boost::bind(&Authenticator::translate_groups,
                                                         this, _1,
                                                         Directory::USER_PRINCIPAL_GROUP,
                                                         cb, incr), fail);
        break;
    default:
        VLOG_ERR(lg, "Cannot retrieve groups for unknown principal type %u.", type);
    }

    if (!ret){
        cb(empty);
    }
}

void
Authenticator::set_groups(const ConnPtr& conn,
                          const EmptyCb& cb, bool incr)
{
    EmptyCb cb2 = boost::bind(&Authenticator::set_user_groups, this,
                              conn->users.begin(), cb, incr);
    set_host_groups(conn, cb2, incr);
}


void
Authenticator::set_host_groups(const ConnPtr& conn,
                               const EmptyCb& cb, bool incr)
{
    if (conn->host == UNAUTHENTICATED_ID) {
        set_host_groups(conn, std::list<uint32_t>(), cb, incr);
        return;
    }

    get_groups(get_name(conn->host), Directory::HOST_PRINCIPAL,
               boost::bind(&Authenticator::set_host_groups,
                           this, conn, _1, cb, incr), incr);
}

void
Authenticator::set_host_groups(const ConnPtr& conn,
                               const std::list<uint32_t>& host_groups,
                               const EmptyCb& cb, bool incr)
{
    const std::list<uint32_t> *sgroups;
    const std::list<uint32_t> *lgroups;
    const std::list<uint32_t> *hgroups = &host_groups;

    GroupInfoMap::iterator sw = switches.find(conn->location & DP_MASK);
    if (sw != switches.end()) {
        if (sw->second.status.locked) {
            sw->second.status.waiters.push_back(
                boost::bind(&Authenticator::set_host_groups, this,
                            conn, host_groups, cb, incr));
            VLOG_DBG(lg, "Queuing set host groups for switch %"PRIx64".", sw->first);
            return;
        }
        sgroups = &sw->second.groups;
    } else {
        if (unauth_sw_groups.status.locked) {
            unauth_sw_groups.status.waiters.push_back(
                boost::bind(&Authenticator::set_host_groups, this,
                            conn, host_groups, cb, incr));
            VLOG_DBG(lg, "Queuing set host groups for unauth switch.");
            return;
        }
        sgroups = &unauth_sw_groups.groups;
    }

    GroupInfoMap::iterator location = locations.find(conn->location);
    if (location != locations.end()) {
        if (location->second.status.locked) {
            location->second.status.waiters.push_back(
                boost::bind(&Authenticator::set_host_groups, this,
                            conn, host_groups, cb, incr));
            VLOG_DBG(lg, "Queuing set host groups for location %"PRIx64".", conn->location);
            return;
        }
        conn->ap = location->second.id;
        lgroups = &location->second.groups;
    } else {
        if (unauth_loc_groups.status.locked) {
            unauth_loc_groups.status.waiters.push_back(
                boost::bind(&Authenticator::set_host_groups, this,
                            conn, host_groups, cb, incr));
            VLOG_DBG(lg, "Queuing set host groups for unauth location.");
            return;
        }
        conn->ap = UNAUTHENTICATED_ID;
        lgroups = &unauth_loc_groups.groups;
    }

    if (conn->host == UNAUTHENTICATED_ID) {
        if (unauth_host_groups.status.locked) {
            unauth_host_groups.status.waiters.push_back(
                boost::bind(&Authenticator::set_host_groups, this,
                            conn, host_groups, cb, incr));
            VLOG_DBG(lg, "Queuing set host groups for unauth host.");
            return;
        }
        hgroups = &unauth_host_groups.groups;
        // passed in hgroups already incremented, so this must be nested
        if (incr) {
            increment_ids(*hgroups);
        }
    }

    if (incr) {
        increment_ids(*sgroups);
        increment_id(conn->ap);
        increment_ids(*lgroups);
    }

    merge_group_lists(sgroups, lgroups, hgroups, conn->hostgroups);
    cb();
}

void
Authenticator::set_user_groups(std::list<user_info>::iterator u,
                               const EmptyCb& cb, bool incr)
{
    if (u->user == UNAUTHENTICATED_ID) {
        set_user_groups(u, std::list<uint32_t>(), cb, incr);
        return;
    }

    get_groups(get_name(u->user), Directory::USER_PRINCIPAL,
               boost::bind(&Authenticator::set_user_groups,
                           this, u, _1, cb, incr), incr);
}

void
Authenticator::set_user_groups(std::list<user_info>::iterator u,
                               const std::list<uint32_t>& user_groups,
                               const EmptyCb& cb, bool incr)
{
    if (u->user == UNAUTHENTICATED_ID) {
        if (unauth_user_groups.status.locked) {
            unauth_user_groups.status.waiters.push_back(
                boost::bind(&Authenticator::set_user_groups, this,
                            u, user_groups, cb, incr));
            VLOG_DBG(lg, "Queuing set user groups for unauth user.");
            return;
        }
        if (incr) {
            increment_ids(unauth_user_groups.groups);
        }
        u->groups.assign(unauth_user_groups.groups.begin(),
                         unauth_user_groups.groups.end());
    } else {
        u->groups.assign(user_groups.begin(),
                         user_groups.end());
    }
    cb();
}


void
Authenticator::is_gateway(const ethernetaddr& dladdr, const BoolCb& cb)
{
    if (!dirmanager->is_gateway(dladdr, "", cb,
                                boost::bind(&Authenticator::return_false,
                                            this, cb)))
    {
        cb(false);
    }
}

void
Authenticator::is_router(const ethernetaddr& dladdr, const BoolCb& cb)
{
    if (!dirmanager->is_router(dladdr, "", cb,
                               boost::bind(&Authenticator::return_false,
                                           this, cb)))
    {
        cb(false);
    }
}

void
Authenticator::return_false(const BoolCb& cb)
{
    cb(false);
}

static
bool
is_rm_dp_ap(const ConnPtr& conn,
            const Authenticator::HostMap::const_iterator& dlconns,
            const Authenticator::NWMap::const_iterator& nwconns,
            uint64_t dp, const hash_set<uint64_t>& points, bool remove_all)
{
    if ((conn->location & DP_MASK) == dp
        && (remove_all || points.find(conn->location) == points.end())) {
         return true;
    }
    return false;
}

static
bool
is_ap(const ConnPtr& conn,
      const Authenticator::HostMap::const_iterator& dlconns,
      const Authenticator::NWMap::const_iterator& nwconns,
      uint64_t loc)
{
    return (conn->location == loc);
}

static
bool
is_ip_host(const ConnPtr& conn,
           const Authenticator::HostMap::const_iterator& dlconns,
           const Authenticator::NWMap::const_iterator& nwconns)
{
    return (nwconns->first != 0);
}

Disposition
Authenticator::handle_netinfo_change(const Event& e)
{
    const NetInfo_mod_event& nm = assert_cast<const NetInfo_mod_event&>(e);

    uint64_t dladdr = nm.dladdr.hb_long();
    if (dladdr != 0) {
        mod_dl_attrs(dladdr, nm.is_router, nm.is_gateway);
    }

    return CONTINUE;
}


void
Authenticator::mod_dl_attrs(uint64_t dladdr, bool is_router,
                            bool is_gateway)
{
    HostMap::iterator dlconns = hosts.find(dladdr);
    if (dlconns == hosts.end()) {
        return;
    } else if (dlconns->second.status.locked) {
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::mod_dl_attrs, this, dladdr,
                        is_router, is_gateway));
        VLOG_DBG(lg, "Queuing mod_dl_attrs for dladdr %"PRIx64".",
                 dladdr);
        return;
    }

    if (dlconns->second.router != is_router
        || (!dlconns->second.gateway && is_gateway))
    {
        dlconns->second.router = is_router;
        dlconns->second.gateway = is_gateway;
        remove_nwhosts(dlconns, true, " (change MAC attributes)",
                       boost::bind(is_ip_host, _1, _2, _3));
    } else {
        // in case no longer a gateway
        dlconns->second.gateway = is_gateway;
    }
}


bool
Authenticator::remove_host(const ConnPtr& conn,
                           const HostMap::const_iterator& dlconns,
                           const NWMap::const_iterator& nwconns,
                           const std::string& delname)
{
    uint32_t id = get_id(delname, Directory::HOST_PRINCIPAL,
                         EMPTY_GROUP, true, false);
    return (conn->host == id);
}

// Post leave events for connectors remove(<Connector>) returns true on

void
Authenticator::remove_hosts(bool poison, const std::string& reason,
                            const To_Remove_Fn& remove)
{
    for (HostMap::iterator dlconns = hosts.begin();
         dlconns != hosts.end(); ++dlconns)
    {
        if (dlconns->second.status.locked) {
            dlconns->second.status.waiters.push_back(
                boost::bind(&Authenticator::remove_addr_hosts, this,
                            dlconns->first, poison, reason, remove));
            VLOG_DBG(lg, "Queueing remove_hosts %"PRIx64".",
                     dlconns->first);
        } else {
            remove_nwhosts(dlconns, poison, reason, remove);
        }
    }
}

void
Authenticator::remove_addr_hosts(uint64_t dladdr, bool poison,
                                 const std::string& reason,
                                 const To_Remove_Fn& remove)
{
    HostMap::iterator dlconns = hosts.find(dladdr);
    if (dlconns == hosts.end()) {
        return;
    } else if (dlconns->second.status.locked) {
        dlconns->second.status.waiters.push_back(
            boost::bind(&Authenticator::remove_addr_hosts, this,
                        dladdr, poison, reason, remove));
        VLOG_DBG(lg, "Queuing remove_addr_hosts %"PRIx64".",
                 dladdr);
        return;
    }

    remove_nwhosts(dlconns, poison, reason, remove);
}


void
Authenticator::remove_nwhosts(HostMap::iterator& dlconns,
                              bool poison, const std::string& reason,
                              const To_Remove_Fn& remove)
{
    for (NWMap::iterator nwconns = dlconns->second.nws.begin();
         nwconns != dlconns->second.nws.end(); ++nwconns)
    {
        for (ConnList::iterator conn = nwconns->second.conns.begin();
             conn != nwconns->second.conns.end();)
        {
            if (remove(*conn, dlconns, nwconns)) {
                post_leave(dlconns, nwconns, conn, poison, reason);
            } else {
                ++conn;
            }
        }
    }
}



// Post leave events for all hosts not a enabled port of a dp

void
Authenticator::remove_dp_hosts(uint64_t dpint,
                               const hash_set<uint64_t>& valid_points,
                               bool remove_all,
                               bool poison, const std::string& reason)
{
    remove_hosts(poison, reason,
                 boost::bind(is_rm_dp_ap, _1, _2, _3,
                             dpint, valid_points, remove_all));
}


// Post leave events for all hosts connecting through 'ap'

void
Authenticator::remove_loc_hosts(uint64_t ap, bool poison,
                                const std::string& reason)
{
    remove_hosts(poison, reason, boost::bind(is_ap, _1, _2, _3, ap));
}


// Post leave events for idle hosts
void
Authenticator::remove_expired_hosts()
{
    time_t cur_time(time(NULL));

    for (HostMap::iterator dlconns = hosts.begin();
         dlconns != hosts.end();)
    {
        if (dlconns->second.status.locked) {
            ++dlconns;
            continue;
        }

        hash_set<uint64_t> active_locs;
        for (NWMap::iterator nwconns = dlconns->second.nws.begin();
             nwconns != dlconns->second.nws.end();)
        {
            if (nwconns->first != 0) {
                for (ConnList::iterator conn = nwconns->second.conns.begin();
                     conn != nwconns->second.conns.end();)
                {
                    Connector& c = **conn;
                    if (c.hard_timeout != 0 && c.hard_timeout <= cur_time) {
                        post_leave(dlconns, nwconns, conn, true, " (hard timeout)");
                    } else if (c.last_active + c.inactivity_len <= cur_time) {
                        post_leave(dlconns, nwconns, conn, true, " (inactivity)");
                    } else {
                        active_locs.insert(c.location);
                        ++conn;
                    }
                }
            }
            if (nwconns->first != 0 && nwconns->second.conns.empty()
                && nwconns->second.timeout <= cur_time)
            {
                decrement_ids(*(nwconns->second.addr_groups));
                dlconns->second.nws.erase(nwconns++);
            } else {
                ++nwconns;
            }
        }

        if (dlconns->second.zero != NULL) {
            NWMap::iterator zero = dlconns->second.nws.find(0);
            for (ConnList::iterator conn = zero->second.conns.begin();
                 conn != zero->second.conns.end();)
            {
                Connector& c = **conn;
                if (c.hard_timeout != 0 && c.hard_timeout <= cur_time) {
                    post_leave(dlconns, zero, conn, true, " (hard timeout)");
                } else if (c.last_active + c.inactivity_len <= cur_time
                           && active_locs.find(c.location) == active_locs.end())
                {
                    post_leave(dlconns, zero, conn, true, " (inactivity)");
                } else {
                    ++conn;
                }
            }
            if (zero->second.conns.empty()
                && zero->second.timeout <= cur_time)
            {
                decrement_ids(*(zero->second.addr_groups));
                dlconns->second.nws.erase(zero);
                dlconns->second.zero = NULL;
            }
        }

        if (dlconns->second.nws.empty()) {
            hosts.erase(dlconns++);
        } else {
            ++dlconns;
        }
    }


    for (IDMap::iterator id = ids.begin(); id != ids.end();) {
        if (id->second.refcount == 0 && id->second.expire <= cur_time) {
            NameMap::iterator n = names.find(id->second.name + id->second.suffix);
            if (n != names.end() && n->second == id->first) {
                VLOG_DBG(lg, "Expiring name \'%s\'.", id->second.name.c_str());
                names.erase(n);
            }
            ids.erase(id++);
        } else {
            ++id;
        }
    }

    timeval tv = { expire_timer, 0 };
    post(boost::bind(&Authenticator::remove_expired_hosts, this), tv);
}


#define CHECK_POISON_ERR(error, dp)                                     \
    if (error) {                                                        \
        if (error == EAGAIN) {                                          \
            VLOG_DBG(lg, "Poison location on dp:%"PRIx64" failed with EAGAIN.", \
                     dp.as_host());                                     \
        } else {                                                        \
            VLOG_ERR(lg, "Poison location on dp:%"PRIx64" failed with %d:%s.", \
                     dp.as_host(), error, strerror(error));             \
        }                                                               \
        return;                                                         \
    }

void
Authenticator::poison_ap(const ConnPtr& src,
                         const ethernetaddr& dladdr, uint32_t nwaddr,
                         bool wildcard_nw) const
{
    ofp_match& match = ofm->match;

    memcpy(match.dl_dst, dladdr.octet, ethernetaddr::LEN);
    match.wildcards = htonl(OFPFW_ALL & (~OFPFW_DL_DST));
    if (!wildcard_nw) {
        match.nw_dst = htonl(nwaddr);
        match.wildcards &= htonl(~OFPFW_NW_DST_MASK);
    }

    VLOG_DBG(lg, "Poisoning old primary ap:%llx:%"PRIu16", dl:%"PRIx64", nw:%"PRIx32" wc:%u",
             src->location & DP_MASK, (uint16_t)(src->location >> 48),
             dladdr.hb_long(), nwaddr, wildcard_nw ? 1 : 0);

    datapathid dpid = datapathid::from_host(src->location & DP_MASK);
    int err = send_openflow_command(dpid, &ofm->header, false);
    CHECK_POISON_ERR(err, dpid);

    memcpy(match.dl_src, dladdr.octet, ethernetaddr::LEN);
    match.wildcards = htonl(OFPFW_ALL & (~OFPFW_DL_SRC));
    if (!wildcard_nw) {
        match.nw_src = htonl(nwaddr);
        match.wildcards &= htonl(~OFPFW_NW_SRC_MASK);
    }

    err = send_openflow_command(dpid, &ofm->header, false);
    CHECK_POISON_ERR(err, dpid);
}

#define OUI_MASK 0x3fffff000000ULL
#define OUI      0x002320000000ULL

bool
Authenticator::is_internal_mac(uint64_t hb_dladdr) const
{
    return ((OUI_MASK & hb_dladdr) == OUI);
}

}
}
