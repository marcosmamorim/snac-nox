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

#include "cswitchstats.hh"

#include <boost/bind.hpp>
#include <iostream>

#include "packet-in.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "assert.hh"
#include "vlog.hh"

using namespace std;
using namespace vigil;
using namespace vigil::applications;
using namespace vigil::container;

static Vlog_module lg("cswitchstats");

CSwitchStats::CSwitchStats(const Context* c,
                   const xercesc::DOMNode*)
    : Component(c) 
{
}

void
CSwitchStats::install() {

}

void 
CSwitchStats::test_print_averages()
{
    cout << " TOTAL! " << get_global_conn_p_s() << endl;
    timeval tv = { 1, 0 };
    post(boost::bind(&CSwitchStats::test_print_averages, this), tv);
}
void
CSwitchStats::configure(const Configuration*)
{
    register_handler<Datapath_join_event>
        (boost::bind(&CSwitchStats::handle_datapath_join, this, _1));
    register_handler<Datapath_leave_event>
        (boost::bind(&CSwitchStats::handle_data_leave, this, _1));
    register_handler<Packet_in_event>
        (boost::bind(&CSwitchStats::handle_packet_in, this, _1));


    // For testing
    // -- timeval tv = { 1, 0 };
    // -- post(boost::bind(&CSwitchStats::test_print_averages, this), tv);
}

Disposition
CSwitchStats::handle_datapath_join(const Event& e)
{
    const Datapath_join_event& dj = assert_cast<const Datapath_join_event&>(e);
    uint64_t dpint = dj.datapath_id.as_host();

    if(switch_port_map.find(dpint) != switch_port_map.end()){
        VLOG_ERR(lg, "DP join of existing switch %"PRIu64"", dpint);
        for(int i = 0; i < switch_port_map[dpint].size(); ++i){
            tracker_map.erase(switch_port_map[dpint][i]);
        }
        switch_port_map.erase(dpint);
    }

    for (std::vector<Port>::const_iterator iter = dj.ports.begin();
         iter != dj.ports.end(); ++iter) {
        uint64_t loc = dpint + (((uint64_t) iter->port_no) << 48);
        switch_port_map[dpint].push_back(loc);
        tracker_map[loc].reset(5000); // 5 second timeslices
    }

    return CONTINUE;
}

Disposition
CSwitchStats::handle_data_leave(const Event& e)
{
    const Datapath_leave_event& dl = assert_cast<const Datapath_leave_event&>(e);
    uint64_t dpint = dl.datapath_id.as_host();

    if(switch_port_map.find(dpint) == switch_port_map.end()){
        VLOG_ERR(lg, "DP leave of non-existent switch %"PRIu64"", dpint);
        return CONTINUE;
    }

    for(int i = 0; i < switch_port_map[dpint].size(); ++i){
        tracker_map.erase(switch_port_map[dpint][i]);
    }
    switch_port_map.erase(dpint);

    return CONTINUE;
}

Disposition
CSwitchStats::handle_packet_in(const Event& e)
{
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    uint64_t loc = pi.datapath_id.as_host() + (((uint64_t) pi.in_port) << 48);
    if(tracker_map.find(loc) == tracker_map.end()){
        VLOG_ERR(lg, "packet-in from non-existent location %"PRIu64"", loc);
        return CONTINUE;
    }
    
    tracker_map[loc].add_event(1);

    return CONTINUE;
}

float 
CSwitchStats::get_global_conn_p_s(void)
{
    float total = 0.;

    for (hash_map<uint64_t, std::vector<uint64_t> >::iterator iter = switch_port_map.begin();
            iter != switch_port_map.end(); ++iter){
        for (int i = 0; i < iter->second.size(); ++i){
            if (tracker_map.find(iter->second[i]) == tracker_map.end() ) {
                VLOG_ERR(lg, "mapped location %"PRIu64" doesn't exist", iter->second[i]);
                continue;
            }
            if (tracker_map[iter->second[i]].get_history_q_ref().size() > 0){
                total += tracker_map[iter->second[i]].get_history_q_ref().front();
            }
        }
    }

    return total;
}

float 
CSwitchStats::get_switch_conn_p_s(uint64_t dpid)
{
    float total = 0.;

    if (switch_port_map.find(dpid) == switch_port_map.end()){
        VLOG_ERR(lg, "(get_switch_conn_p_s) no ports associated with dpid %"PRIu64, dpid);
        return total;
    }

    for (int i = 0; i < switch_port_map[dpid].size(); ++i){
        if (tracker_map.find(switch_port_map[dpid][i]) == tracker_map.end() ) {
            VLOG_ERR(lg, "mapped location %"PRIu64" doesn't exist", switch_port_map[dpid][i]);
            continue;
        }
        if (tracker_map[switch_port_map[dpid][i]].get_history_q_ref().size() > 0){
            total += tracker_map[switch_port_map[dpid][i]].get_history_q_ref().front();
        }
    }

    return total;
}

float 
CSwitchStats::get_loc_conn_p_s   (uint64_t loc)
{
    if (tracker_map.find(loc) == tracker_map.end()){
        VLOG_ERR(lg, "(get_loc_conn_p_s) loc %"PRIu64" doesn't exist", loc);
        return 0.;
    }

    if (tracker_map[loc].get_history_q_ref().size() > 0){
        return tracker_map[loc].get_history_q_ref().front();
    }
    return 0.;
}

void 
CSwitchStats::getInstance(const container::Context* ctxt, CSwitchStats*& scpa) {
    scpa = dynamic_cast<CSwitchStats*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(CSwitchStats).name())));
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory<CSwitchStats>,
                   CSwitchStats);
