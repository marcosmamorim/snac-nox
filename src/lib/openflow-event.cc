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
// --
// TODO:
//   This should really be moved to a class ...
// --
#include "openflow-event.hh"

#include <map>
#include <netinet/in.h>
#include <boost/bind.hpp>
#include <boost/static_assert.hpp>
#include <inttypes.h>
#include <cstddef>
#include "assert.hh"
#include "buffer.hh"
#include "datapath.hh"
#include "packet-in.hh"
#include "port-status.hh"
#include "datapath-join.hh"
#include "switch-features.hh"
#include "echo-request.hh"
#include "flow-stats-in.hh"
#include "aggregate-stats-in.hh"
#include "desc-stats-in.hh"
#include "table-stats-in.hh"
#include "port-stats-in.hh"
#include "error-event.hh"
#include "flow-removed.hh"
#include "openflow.hh"
#include "vlog.hh"

using namespace vigil;

namespace {

static Vlog_module lg("openflow-event");


Event*
handle_packet_in(datapathid datapath_id,
                 const ofp_packet_in* opi, std::auto_ptr<Buffer> packet)
{
    /* jump past packet ofp_header and get access to packet data
     * */
    packet->pull(offsetof(ofp_packet_in, data));
    lg.dbg("received packet-in event from %s (len:%zu)",
           datapath_id.string().c_str(), packet->size());
    return new Packet_in_event(datapath_id, opi, packet);
}

Event*
handle_flow_removed(datapathid datapath_id,
                    const ofp_flow_removed *ofe, std::auto_ptr<Buffer> buf)
{
    lg.dbg("received flow expired event from %s",
           datapath_id.string().c_str());
    return new Flow_removed_event(datapath_id, ofe, buf);
}

Event*
handle_port_status(datapathid datapath_id,
                   const ofp_port_status *ops, std::auto_ptr<Buffer> buf)
{
    lg.dbg("received port status event from %s",
           datapath_id.string().c_str());
    return new Port_status_event(datapath_id, ops, buf);
}

Event*
handle_features_reply(datapathid datapath_id,
                  const ofp_switch_features *osf, std::auto_ptr<Buffer> buf)
{
    lg.err("received updated features reply event from %s", 
            datapath_id.string().c_str());
    return new Switch_features_event(osf, buf);
}

Event*
handle_stats_aggregate_reply(datapathid datapath_id,
                             const ofp_stats_reply *osr, std::auto_ptr<Buffer> buf)
{
    int len = htons(osr->header.length);

    if ( (len - sizeof(ofp_stats_reply)) != sizeof(ofp_aggregate_stats_reply)){
        lg.err("handle_stats_aggregate_reply has invalid length %d", 
                len);
        return 0;
    }

    return new Aggregate_stats_in_event(datapath_id, osr, buf);
}

Event*
handle_stats_table_reply(datapathid datapath_id,
                         const ofp_stats_reply *osr, std::auto_ptr<Buffer> buf)
{
    int len = htons(osr->header.length);

    if ( (len - sizeof(ofp_stats_reply)) % sizeof(ofp_table_stats)){
        lg.err("handle_stats_table_reply has invalid length %d", 
                len);
        return 0;
    }

    Table_stats_in_event* tsie = new Table_stats_in_event(datapath_id, osr, buf);
    len -= sizeof(ofp_stats_reply);
    ofp_table_stats* ots = (struct ofp_table_stats*)osr->body;
    for (int i = 0; i < len / sizeof(ofp_table_stats); ++i){
        tsie->add_table(
                (int)(ots->table_id),
                ots->name,
                htonl(ots->max_entries),
                htonl(ots->active_count),
                htonll(ots->lookup_count),
                htonll(ots->matched_count));
        ots++;
    }

    return tsie;
}

Event*
handle_stats_port_reply(datapathid datapath_id,
                        const ofp_stats_reply *osr, std::auto_ptr<Buffer> buf)
{
    int len = htons(osr->header.length);

    if ( (len - sizeof(ofp_stats_reply)) % sizeof(ofp_port_stats)){
        lg.err("handle_stats_port_reply has invalid length %d", 
                len);
        return 0;
    }

    Port_stats_in_event* psie = new Port_stats_in_event(datapath_id, osr, buf);
    len -= sizeof(ofp_stats_reply);
    ofp_port_stats* ops = (struct ofp_port_stats*)osr->body;
    for (int i = 0; i < len / sizeof(ofp_port_stats); ++i){
        psie->add_port(ops);
        ops++;
    }

    return psie;
}

Event*
handle_stats_desc_reply(datapathid datapath_id,
                        const ofp_stats_reply *osr, std::auto_ptr<Buffer> buf)
{
    int len = htons(osr->header.length);

    if ( (len - sizeof(ofp_stats_reply)) != sizeof(ofp_desc_stats)){
        lg.err("handle_stats_desc_reply has invalid length %d", 
                len);
        return 0;
    }

    return new Desc_stats_in_event(datapath_id, osr, buf);
}

Event*
handle_stats_flow_reply(datapathid datapath_id,
                        const ofp_stats_reply *osr, std::auto_ptr<Buffer> buf)
{
    int len = htons(osr->header.length);
    len -= (int) sizeof *osr;
    if (len < 0) {
        lg.err("handle_stats_flow_reply has invalid length %d", len);
        return 0;
    }
    return new Flow_stats_in_event(datapath_id, osr, buf);
}

Event*
handle_stats_reply(datapathid datapath_id,
                   const ofp_stats_reply *osr, std::auto_ptr<Buffer> buf)
{
    lg.dbg("received stats reply from %s", 
            datapath_id.string().c_str());

    switch(htons(osr->type)) {
        case OFPST_DESC:
            return handle_stats_desc_reply(datapath_id, osr, buf);
        case OFPST_TABLE:
            return handle_stats_table_reply(datapath_id, osr, buf);
        case OFPST_PORT:
            return handle_stats_port_reply(datapath_id, osr, buf);
        case OFPST_AGGREGATE:
            return handle_stats_aggregate_reply(datapath_id, osr, buf);
        case OFPST_FLOW:
            return handle_stats_flow_reply(datapath_id, osr, buf);
        default:    
            lg.warn("unhandled reply type %d", 
                    htons(osr->type));
            return NULL; 
    }
}

Event*
handle_echo_request(datapathid datapath_id,
                    const ofp_header* oh, std::auto_ptr<Buffer> packet)
{
    packet->pull(sizeof(ofp_header));
    lg.dbg("received echo-request event from %s (len:%zu)",
           datapath_id.string().c_str(), packet->size());
    return new Echo_request_event(datapath_id, oh, packet);
}

Event*
handle_error(datapathid datapath_id,
             const ofp_error_msg *oem, std::auto_ptr<Buffer> packet)
{
    uint16_t type = ntohs(oem->type);
    uint16_t code = ntohs(oem->code);
    lg.err("received Openflow error packet from dpid=%s: "
           "type=%d, code=%d, %zu bytes of data\n",
           datapath_id.string().c_str(), type, code,
           packet->size() - offsetof(ofp_error_msg, data));
    return new Error_event(datapath_id, oem, packet);
}

template <class Packet>
Event*
handle_packet(Event* (*handler)(datapathid datapath_id,
                              const Packet*, std::auto_ptr<Buffer>),
	      datapathid datapath_id,
              const ofp_header* oh, std::auto_ptr<Buffer> packet,
              size_t min_size = sizeof(Packet))
{
    // Attempt to ensure that Packet is a OpenFlow packet format.
    BOOST_STATIC_ASSERT(offsetof(Packet, header.version) == 0);

    if (packet->size() < min_size) {
	lg.dbg("openflow packet too short");
    }

    const Packet* p = reinterpret_cast<const Packet*>(oh);
    return handler(datapath_id, p, packet);
}

} // null namespace

namespace vigil {

Event*
openflow_packet_to_event(datapathid datapath_id, std::auto_ptr<Buffer> p)
{
    if (p->size() < sizeof(struct ofp_header)) {
        lg.warn("openflow packet missing header");
        return NULL;
    }

    const ofp_header* oh = &p->at<ofp_header>(0);
    if (oh->version != OFP_VERSION) {
        lg.warn("bad openflow version %"PRIu8, oh->version);
        return NULL;
    }

   
    switch (oh->type) {
    case OFPT_PACKET_IN:
        return handle_packet(handle_packet_in, datapath_id, oh, p);
    case OFPT_FLOW_REMOVED:
        return handle_packet(handle_flow_removed, datapath_id, oh, p);
    case OFPT_PORT_STATUS:
        return handle_packet(handle_port_status, datapath_id, oh, p);
    case OFPT_FEATURES_REPLY:
        return handle_packet(handle_features_reply, datapath_id, oh, p);
    case OFPT_STATS_REPLY:
        return handle_packet(handle_stats_reply, datapath_id, oh, p);
    case OFPT_ECHO_REQUEST:
        return handle_echo_request(datapath_id, oh, p);
    case OFPT_ECHO_REPLY:
        return NULL;
        // TODO OFPT_CLOSE
    case OFPT_ERROR:
        return handle_packet(handle_error, datapath_id, oh, p);
    default:
        lg.err("unhandled openflow packet type %"PRIu8, oh->type);
        return NULL;
    }
}

} // namespace vigil
