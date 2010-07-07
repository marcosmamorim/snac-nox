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
#ifndef AUTHENTICATOR_HH
#define AUTHENTICATOR_HH 1

#include <boost/function.hpp>
#include <ctime>
#include <string>
#include <vector>

#include "auth-event.hh"
#include "component.hh"
#include "directory/directorymanager.hh"
#include "directory/principal_types.hh"
#include "event.hh"
#include "flow.hh"
#include "flow-in.hh"
#include "hash_map.hh"
#include "hash_set.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ethernet.hh"
#include "netinet++/cidr.hh"
#include "openflow/openflow.h"
#include "packet-in.hh"
#include "routing/routing.hh"
#include "topology/topology.hh"
#include "user_event_log/user_event_log.hh"

/*
 * Authenticator keeps track of authenticated hosts in the network as
 * Connectors (defined in flow-in.hh).  On a packet-in event, it finds
 * Connectors for the packet's source and destination hosts, and spawns off a
 * Flow-in event.  Authenticator also throws Host_events and User_events as
 * hosts and users join and leave the network.
 *
 * Host information is kept current by listening for Auth_events.  An
 * authentication Auth_event always authenticates a LOC/DLADDR/ and possibly
 * NWADDR tuple as a sending device in the network.  An Auth_event can further
 * associate that device with host and user names by filling in the
 * corresponding Auth_event attributes (further described in auth-event.hh).
 * This information can be included in the first Auth_event seen for a
 * location, or can be posted in another Auth_event at a later time in which
 * case the location's already-existing Connector record will be updated.
 *
 * Auth_events for the same LOC/DLADDR pair (and different NWADDRs) with
 * 'owns_dl' == true are assumed to be the same host, and thus share a single
 * Connector record.  Conversely, events for that same LOC/DLADDR pair with
 * 'owns_dl' == false are considered to be separate hosts (though in reality
 * they may be on the same device) and point to different Connector records.
 *
 * When a Connector record is first created, a host join event is thrown.
 * Following from the previous paragraph, only one host join event is thrown
 * when multiple NWADDR Auth_events are received for the same LOC/DLADDR pair
 * with 'owns_dl' == true.  Thus no event is thrown when a new IP address is
 * authenticated for the owning host.  Meanwhile, for non-dl-owning hosts, a
 * host join event is thrown when the nwaddr location is first seen in an
 * Auth_event (and the Connector is created).  User join events are posted
 * when a new user authenticates on a host.
 *
 * Deauthentication Auth_events can either remove name bindings from a host or
 * fully deauthenticate a host (again, further described in auth-event.hh).
 * Host leave events are posted when all of a host's NWADDR entries have been
 * deauthenticated.  A non-dl_owning host only has one entry, its
 * LOC/DLADDR/NWADDR tuple, and so it has left the network when an UNKNOWN
 * Auth_event is received for that tuple.  Dl_owning hosts meanwhile have a
 * DLADDR-only location (nwaddr == 0) plus 0 or more NWADDR locations.  Each of
 * the NWADDR locations can be deauthed individually with UNKNOWN Auth_events,
 * however, a 'nwaddr' == 0 deauth event is interpretted as deauthentication
 * of a dladdr interface as a whole, and thus automatically deauthenticates any
 * NWADDR locations on top of the dladdr.  This means that a single UNKNOWN
 * deauth Auth_event for the location with 'nwaddr' == 0 is sufficient to
 * remove a host from the network state (and cause a host leave event to be
 * posted).  Furthermore, non-dl_owning hosts located behind the dl interface
 * are deauthenticated as well.  Host leave events are posted for each of these
 * non-owning hosts and their Connector records are deleted.
 *
 * API Notes:
 * ----------
 * All integers should be passed in host byte order into methods.
 *
 * Connector objects
 * -----------------
 * Connector objects store principal and group names in the form of integer
 * IDs.  ID-to-name mappings can be looked up using 'get_name(id)'.
 *
 * Connector integer fields are all stored in host byte order.
 *
 * Authenticator is now modified to support asynchronous directory calls.
 * Public methods retrieving Connectors thus now use callbacks to avoid
 * returning currently "locked" state.
 *
 * Even though iterators to Authenticator's Connector state are exposed,
 * Connector records shouldn't be modified by callers.  Additionally, iterators
 * are of course succeptible to invalidation between calls, so clients wanting
 * to maintain state must make copies.
 *
 */

namespace vigil {
namespace applications {

// forward declare
class Bindings_Storage;

class Authenticator
    : public container::Component {

public:
    // Reserved principal IDs
    static const uint32_t UNAUTHENTICATED_ID = 0;
    static const uint32_t AUTHENTICATED_ID = 1;
    static const uint32_t UNKNOWN_ID = 2;
    static const uint32_t START_ID = 3;

    // Reserved principal name retrieval methods
    static const std::string& get_authenticated_name();
    static const std::string& get_unauthenticated_name();
    static const std::string& get_unknown_name();

    typedef boost::function<void()> EmptyCb;

    // Status structs used to "lock" datastructures waiting for directory
    // calls to return

    struct UpdateStatus {
        bool locked;
        std::list<EmptyCb> waiters;
    };

    // ConnList paired with an UpdateStatus object.  ConnList isn't valid when
    // status is locked.

    struct NWEntry {
        ConnList conns;
        UpdateStatus *status;
        boost::shared_ptr<std::vector<uint32_t> > addr_groups;
        time_t timeout;
    };

    typedef hash_map<uint32_t, NWEntry> NWMap;

    struct DLEntry {
        UpdateStatus status;
        bool router;
        bool gateway;
        NWMap nws;
        NWEntry *zero;
        DLEntry() : router(false), gateway(false), zero(NULL)
            { status.locked = false; }
    };

    // Data structure holding Connector objects.  Authenticator maintains a
    // single HostMap

    typedef hash_map<uint64_t, DLEntry> HostMap;

    Authenticator(const container::Context*, const xercesc::DOMNode*);
    Authenticator() : Component(0) { }

    static void getInstance(const container::Context*, Authenticator*&);

    void configure(const container::Configuration*);
    void install();

    // Name-to-ID managements fns

    bool rename(const std::string& old_name, const std::string& new_name,
                Directory::Principal_Type, Directory::Group_Type,
                bool is_principal);
    uint32_t get_id(const std::string& name, Directory::Principal_Type,
                    Directory::Group_Type, bool is_principal, bool incr);
    bool get_principal_type(uint32_t id, Directory::Principal_Type& ptype) const;
    bool get_group_type(uint32_t id, Directory::Group_Type& gtype) const;
    void increment_id(uint32_t id);
    void decrement_id(uint32_t id);
    void increment_ids(const std::list<uint32_t>& ids);
    void decrement_ids(const std::list<uint32_t>& ids);
    void decrement_ids(const std::vector<uint32_t>& ids);
    void decrement_conn(const ConnPtr& conn);
    const std::string& get_name(uint32_t id) const;
    void reset_names();

    // When the destination addresses of a packet have not been authenticated,
    // if lookup_unauth_dst == true, static configurations will be looked up,
    // else principal IDs will be set to UNAUTHENTICATED_ID

    void set_lookup_unauth_dst(bool unauth_dst) { lookup_unauth_dst = unauth_dst; }
    void auth_host(const Flow_in_event&);

    // Methods to retrieve Connector information on an authenticated host.
    // nwaddrs and ports should be in host byte order - A network address of 0
    // is equivalent to no network address

    // Callback is called when the segment of the HostMap is not locked.
    // If boolean is true, the entry exists and the iterator is valid, else it
    // does not exist (and the iterator is invalid).

    // If the queried state is unlocked at the time of the get_*conns call, the
    // callback will be called immediately, before the get_*conns call has even
    // returned.  Else it will be called when the state is available.

    typedef boost::function<void(bool, HostMap::const_iterator&)> DLEntryCb;
    typedef boost::function<void(bool, NWMap::const_iterator&)> NWEntryCb;
    typedef boost::function<void(bool, ConnList::const_iterator&)> ConnEntryCb;

    // Hint if host state for the address pair exists.  synchronous so is
    // approximation.
    bool host_exists(const ethernetaddr& dladdr, uint32_t nwaddr) const;

    // Retrieve iterator pointing to segment of HostMap with all Connectors
    // with the given ethernet address.  See note above for further details.
    void get_dlconns(const ethernetaddr& dladdr, const DLEntryCb& cb);

    // Retrieve iterator pointing segment of HostMap with all Connectors with
    // the given ethernet and network addresses.  See note above for further
    // details.
    void get_nwconns(const ethernetaddr& dladdr, uint32_t nwaddr,
                     const NWEntryCb& cb);

    // Retrieve iterator pointing to the Connector with the given location and
    // ethernet and network addresses.  See note above for further details.
    void get_conn(const datapathid& dpid, uint16_t port,
                  const ethernetaddr& dladdr, uint32_t nwaddr,
                  const ConnEntryCb& cb);

    // Methods to set inactivity expiration times of hosts.  nwaddrs and ports
    // should be in host byte order.

    // Set either inactivity or hard timeout to be 'sec' from current time.
    // 'set_inactivity' boolean signals which to set.
    void set_host_timeout(const datapathid& dpid, uint16_t port,
                          const ethernetaddr& dladdr, uint32_t nwaddr,
                          uint32_t sec, bool set_inactivity);

    // Reset time of last activity to current time
    void reset_last_active(const datapathid& dpid, uint16_t port,
                           const ethernetaddr& dladdr, uint32_t nwaddr);

    void add_internal_subnet(const cidr_ipaddr&);
    void clear_internal_subnets() { internal_subnets.clear(); }
    bool remove_internal_subnet(const cidr_ipaddr&);

    // Get the high-level names that would be thrown against the policy by
    // flow with the specified address headers
    void get_names(const datapathid& dp, uint16_t inport,
                   const ethernetaddr& dlsrc, uint32_t nwsrc,
                   const ethernetaddr& dldst, uint32_t nwdst,
                   PyObject *callable);

    void remove_src_location(const ethernetaddr& dladdr);
private:
    struct GroupInfo {
        UpdateStatus status;
        uint32_t id;
        std::list<uint32_t> groups;
    };

    typedef GroupInfo SwitchGroupInfo;
    typedef GroupInfo LocGroupInfo;

    struct IDEntry {
        uint32_t refcount;
        time_t expire;
        std::string name;
        const char *suffix;

        IDEntry(uint32_t r, time_t e, const std::string& n,
                const char *s)
            : refcount(r), expire(e), name(n), suffix(s) { }
        IDEntry() : refcount(0), suffix(NULL) { }
        ~IDEntry() { }
    };

    struct ip_subnet {
        uint32_t nwaddr;
        uint32_t mask;
    };

    std::vector<ip_subnet> internal_subnets;

    typedef hash_map<uint64_t, GroupInfo> GroupInfoMap;
    typedef hash_map<uint32_t, std::list<NWEntry*> > NWLookup;
    typedef hash_map<std::string, uint32_t> NameMap;
    typedef hash_map<uint32_t, IDEntry> IDMap;
    typedef hash_set<std::string> KeySet;

    Bindings_Storage *bindings;
    DirectoryManager *dirmanager;
    Topology *topology;
    Routing_module *routing_mod;
    User_Event_Log *user_log;
    HostMap hosts;
    NWLookup nwhosts;
    GroupInfoMap switches;
    GroupInfoMap locations;
    uint32_t expire_timer;
    uint32_t default_host_timeout;

    GroupInfo unauth_sw_groups;
    GroupInfo unauth_loc_groups;
    GroupInfo unauth_host_groups;
    GroupInfo unauth_user_groups;

    bool auto_auth_hosts;
    bool lookup_unauth_dst;

    NameMap names;
    IDMap ids;
    uint32_t counter;

    directory::SwitchInfo switch_info;
    directory::LocationInfo loc_info;
    directory::HostInfo host_info;
    KeySet switchkey, lockey, dlkey, nwkey;

    boost::shared_array<uint8_t> raw_of;
    ofp_flow_mod *ofm;

    //instead of constructing everytime...
    char buf[1024];

    typedef boost::function<void(Event*)> EventCb;

    bool get_conn(uint64_t, NWEntry&, ConnList::iterator&);
    bool get_conn(uint64_t, uint64_t, uint32_t, HostMap::iterator&,
                  NWMap::iterator&, ConnList::iterator&);

    void unlock_status(UpdateStatus*);
    void post_event(Event*);

    Disposition handle_bootstrap(const Event&);

    Disposition handle_packet_in(const Event&);
    void set_flow_in(Event *, const EventCb&);
    void set_flow_dst(Event *);
    bool get_addr_conns(const ethernetaddr&, uint32_t,
                        HostMap::iterator&, NWMap::iterator&, Event*,
                        const EventCb&);
    void make_primary(const ethernetaddr&, uint32_t, const time_t&,
                      NWEntry&, ConnList::iterator&, bool);
    void remove_internal_hosts(const datapathid&, uint16_t,
                               HostMap::iterator&, NWMap::iterator&);
    bool get_on_path_conn(const datapathid&, uint16_t, NWEntry&,
                          ConnList::iterator&);
    bool set_flow_src_conn(const datapathid&, uint16_t,
                           const ethernetaddr&, const time_t&,
                           const HostMap::iterator&,
                           const NWMap::iterator&, ConnPtr&, ConnPtr&,
                           boost::shared_ptr<std::vector<uint32_t> >&,
                           bool&, bool&, Event*, const EventCb&);
    bool set_flow_dst_conn(const HostMap::iterator&,
                           const NWMap::iterator&, bool, Flow_in_event*,
                           const EventCb&);
    void auth_ev_host(Event *event);
    void auth_bi_host(const Broadcast_in_event&);
    void auth_host2(Packet_in_event *, const ethernetaddr&, uint64_t, uint32_t);
    void auth_host3(const std::string&, Packet_in_event *, const ethernetaddr&,
                    uint32_t, bool);
    void get_temp_conn(ConnPtr*, uint64_t, bool, uint32_t, const EmptyCb&);
    void post_unauth_dst_flow(const std::string&, Flow_in_event*, const EventCb&);

    Disposition handle_datapath_join(const Event&);
    Disposition handle_data_leave(const Event&);
    Disposition handle_port_status(const Event&);
    Disposition handle_link_change(const Event&);

    Disposition handle_auth(const Event&);
    void add_auth(const Auth_event&);
    void add_auth2(const Auth_event&, ConnPtr&);
    void unlock_auth(const Auth_event&, ConnPtr&, bool);
    void unlock_auth2(const Auth_event&);
    void init_conn(ConnPtr&, const Auth_event&);
    void init_complete(ConnPtr&, const Auth_event&);
    void update_conn(ConnPtr&, const Auth_event&, bool);
    void update_complete(ConnPtr&, bool, bool,
                         const Auth_event&);
    void del_auth(const Auth_event&);
    bool contains_user(const ConnPtr&, uint32_t, std::list<user_info>::iterator&);
    void add_user(const ConnPtr&, const datapathid&, uint16_t,
                  const ethernetaddr&, uint32_t);
    void remove_user(const ConnPtr&, std::list<user_info>::iterator&,
                     const datapathid&, uint16_t, const ethernetaddr&,
                     uint32_t, bool, const std::string&, bool);
    void repost_leave(uint64_t, uint32_t, uint64_t, bool,
                      const std::string&, UpdateStatus&);
    void redo_leave(uint64_t, uint32_t, uint64_t, bool,
                    const std::string&);
    bool post_leave(HostMap::iterator&, NWMap::iterator&,
                    ConnList::iterator&, bool, const std::string&);

    typedef boost::function<void(bool)> BoolCb;
    typedef boost::function<void(const std::string&)> StringCb;
    typedef boost::function<void(std::list<uint32_t>&)> ListCb;

    void new_switch(const datapathid&);
    void new_switch_name(const std::string&, const datapathid&, SwitchGroupInfo *);
    void remove_switch(const datapathid&);

    void new_location(const datapathid&, uint16_t, uint64_t, const std::string&);
    void new_location_name(const std::string&, const datapathid&,
                           uint16_t, const std::string&, LocGroupInfo *);
    void remove_location(const datapathid&, uint16_t, uint64_t);
    void remove_dp_locations(const datapathid&, uint64_t,
                             const hash_set<uint64_t>&, bool);
    void new_nw_entry(HostMap::iterator&, NWMap::iterator&, const ethernetaddr&, bool);
    void new_nw_entry2(NWEntry *, bool);
    void set_addr_groups(const ethernetaddr&, uint32_t, NWEntry *, const EmptyCb&, bool);
    void set_addr_groups2(const std::list<uint32_t>&, uint32_t, NWEntry *,
                          const EmptyCb&, bool);
    void set_addr_groups3(const std::list<uint32_t>&, const std::list<uint32_t>&,
                          NWEntry *, const EmptyCb&);
    void new_dl_entry(HostMap::iterator&, const ethernetaddr&, bool);
    void new_dl2(bool, DLEntry *, const ethernetaddr&, bool);
    void new_dl3(bool, DLEntry *, bool);

    void get_info_groups(GroupInfo *, const std::string&, Directory::Principal_Type);
    void get_info_groups2(std::list<uint32_t>&, GroupInfo *);

    void merge_group_lists(const std::list<uint32_t> *,
                           const std::list<uint32_t> *,
                           const std::list<uint32_t> *,
                           std::vector<uint32_t>&);
    void translate_groups(const std::vector<std::string>&,
                          Directory::Group_Type, const ListCb&, bool);
    void get_groups(const std::string&, Directory::Principal_Type,
                    const ListCb&, bool);
    void set_groups(const ConnPtr&, const EmptyCb&, bool);
    void set_host_groups(const ConnPtr&, const EmptyCb&, bool);
    void set_host_groups(const ConnPtr&, const std::list<uint32_t>&,
                         const EmptyCb&, bool);
    void set_user_groups(std::list<user_info>::iterator, const EmptyCb&, bool);
    void set_user_groups(std::list<user_info>::iterator,
                         const std::list<uint32_t>&, const EmptyCb&, bool);

    void get_switch(const datapathid&, const StringCb&);
    void generate_switch_name(const datapathid&, const StringCb&);
    void get_location(const datapathid&, uint16_t, const std::string&,
                      const StringCb&);
    void generate_location_name(const datapathid&, uint16_t, const std::string&,
                                const StringCb&);
    void get_host(const datapathid&, uint16_t, const ethernetaddr&, uint32_t,
                  const StringCb&, bool, uint32_t iteration = 0);
    void generate_host_name(const ethernetaddr&, uint32_t, bool, const StringCb&);
    void get_principal(const std::vector<std::string>&,
                       const StringCb&, const EmptyCb&);
    void return_unknown(const StringCb&);

    void is_gateway(const ethernetaddr&, const BoolCb&);
    void is_router(const ethernetaddr&, const BoolCb&);
    void return_false(const BoolCb&);

    Disposition handle_netinfo_change(const Event&);
    void mod_dl_attrs(uint64_t, bool, bool);

    typedef boost::function<void(const ConnPtr&, HostMap::iterator&,
                                 NWMap::iterator&, uint32_t)> MapConnFn;
    typedef boost::function<void(GroupInfo&, uint64_t, uint32_t)> MapInfoFn;
    Disposition rename_principal(const Event&);
    Disposition delname_location(const Event&);
    void delname_location2(const std::string&, const std::string&,
                           const datapathid&, uint16_t, uint64_t);
    Disposition rename_group(const Event&);
    Disposition modify_group(const Event&);
    void group_change(Directory::Principal_Type ptype, Directory::Group_Type gtype,
                      const std::string& change_name, bool is_principal);
    void map_conns(const MapConnFn&, const std::string&,
                   Directory::Principal_Type, Directory::Group_Type, bool);
    void map_dlconns(uint64_t, const MapConnFn&, const std::string&,
                     Directory::Principal_Type, Directory::Group_Type, bool);
    void map_nwconns(HostMap::iterator&, const MapConnFn&, uint32_t,
                     bool, Directory::Group_Type);
    void map_infos(GroupInfoMap *, const MapInfoFn&, const std::string&,
                   Directory::Principal_Type, Directory::Group_Type, bool);
    void map_info(GroupInfoMap *, uint64_t, const MapInfoFn&,
                  const std::string&, Directory::Principal_Type,
                  Directory::Group_Type, bool);
    void map_info(GroupInfo *, const MapInfoFn&, const std::string&,
                  Directory::Principal_Type, Directory::Group_Type, bool);
    void lock_and_set_agroups(uint64_t, uint32_t nwaddr, NWEntry*);
    void lock_and_set_hgroups(const ConnPtr&, NWEntry*);
    void lock_and_set_ugroups(std::list<user_info>::iterator, NWEntry*);
    void delname_user(const ConnPtr&, HostMap::iterator&, NWMap::iterator&, uint32_t, bool);
    void mod_if_is_dladdr(const ConnPtr&, HostMap::iterator&, NWMap::iterator&,
                          uint32_t, uint64_t);
    void mod_if_is_nwaddr(const ConnPtr&, HostMap::iterator&, NWMap::iterator&,
                          uint32_t, uint32_t, uint32_t);
    void mod_if_has_addr_group(const ConnPtr&, HostMap::iterator&,
                               NWMap::iterator&, uint32_t);
    void mod_if_is_switch(GroupInfo&, uint64_t, uint32_t);
    void mod_if_info_is_principal(GroupInfo&, uint64_t, uint32_t,
                                  Directory::Principal_Type);
    void mod_if_info_has_group(GroupInfo&, uint64_t, uint32_t,
                               Directory::Principal_Type);
    void mod_if_on_switch(const ConnPtr&, HostMap::iterator&, NWMap::iterator&,
                          uint32_t, uint64_t);
    void mod_if_is_principal(const ConnPtr&, HostMap::iterator&,
                             NWMap::iterator&, uint32_t, Directory::Principal_Type);
    void mod_if_has_group(const ConnPtr&, HostMap::iterator&,
                          NWMap::iterator&, uint32_t, Directory::Group_Type);
    bool contains_group(std::vector<uint32_t>&, uint32_t);
    bool contains_group(std::list<uint32_t>&, uint32_t);

    typedef boost::function<bool(const ConnPtr&, const HostMap::const_iterator&,
                                 const NWMap::const_iterator&)> To_Remove_Fn;
    bool remove_host(const ConnPtr&, const HostMap::const_iterator&,
                     const NWMap::const_iterator&, const std::string&);
    void remove_hosts(bool, const std::string&, const To_Remove_Fn& remove);
    void remove_addr_hosts(uint64_t, bool, const std::string&,
                           const To_Remove_Fn&);
    void remove_nwhosts(HostMap::iterator&, bool,
                        const std::string&, const To_Remove_Fn&);
    void remove_dp_hosts(uint64_t, const hash_set<uint64_t>&, bool, bool,
                         const std::string&);
    void remove_loc_hosts(uint64_t, bool, const std::string&);
    void remove_expired_hosts();

    void poison_ap(const ConnPtr&, const ethernetaddr&,
                   uint32_t, bool) const;
    bool is_internal_mac(uint64_t) const;
    bool is_internal_ip(uint32_t) const;

#ifdef TWISTED_ENABLED
    void get_names2(Event *, PyObject*);
    PyObject *get_name_conn_list(Flow_in_event::DestinationList&);
    PyObject *get_name_dict(Connector&);
    PyObject *get_name_list(const std::vector<uint32_t>&);
#endif
};

// Ignores UpdateStatus struct

inline
bool
Authenticator::get_conn(uint64_t loc, NWEntry& nwentry,
                        ConnList::iterator& conn)
{
    for (conn = nwentry.conns.begin();
         conn != nwentry.conns.end(); ++conn)
    {
        if ((*conn)->location == loc) {
            return true;
        }
    }

    return false;
}

inline
bool
Authenticator::get_conn(uint64_t loc, uint64_t dladdr, uint32_t nwaddr,
                        HostMap::iterator& dlconns, NWMap::iterator& nwconns,
                        ConnList::iterator& conn)
{
    if ((dlconns = hosts.find(dladdr)) == hosts.end()) {
        return false;
    }

    if ((nwconns = dlconns->second.nws.find(nwaddr)) == dlconns->second.nws.end()) {
        return false;
    }

    return get_conn(loc, nwconns->second, conn);
}

} // namespace applications
} // namespace vigil

#endif // AUTHENTICATOR_HH
