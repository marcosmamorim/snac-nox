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
#ifndef PACKET_IN_HH
#define PACKET_IN_HH 1

#include <memory>
#include <iostream>
#include <boost/shared_ptr.hpp>
#include <arpa/inet.h>
#include "openflow/openflow.h"
#include "buffer.hh"
#include "event.hh"
#include "netinet++/datapathid.hh"
#include "ofp-msg-event.hh"
#include "openflow.hh"

namespace vigil {

struct Packet_in_event
    : public Event,
      public Ofp_msg_event
{
    Packet_in_event(datapathid datapath_id_, uint16_t in_port_,
                    std::auto_ptr<Buffer> buf_, size_t total_len_,
                    uint32_t buffer_id_, uint8_t reason_)
        : Event(static_get_name()), Ofp_msg_event((ofp_header*) NULL, buf_),
          datapath_id(datapath_id_), in_port(in_port_), total_len(total_len_),
          buffer_id(buffer_id_), reason(reason_)
        {}

    Packet_in_event(datapathid datapath_id_, uint16_t in_port_,
                    boost::shared_ptr<Buffer> buf_, size_t total_len_,
                    uint32_t buffer_id_, uint8_t reason_)
        : Event(static_get_name()), Ofp_msg_event((ofp_header*) NULL, buf_),
          datapath_id(datapath_id_), in_port(in_port_), total_len(total_len_),
          buffer_id(buffer_id_), reason(reason_)
        {}

    Packet_in_event(datapathid datapath_id_,
                    const ofp_packet_in *opi, std::auto_ptr<Buffer> buf_)
        : Event(static_get_name()), Ofp_msg_event(&opi->header, buf_),
          datapath_id(datapath_id_),
          in_port(ntohs(opi->in_port)),
          total_len(ntohs(opi->total_len)),
          buffer_id(ntohl(opi->buffer_id)),
          reason(opi->reason)
        {}

    virtual ~Packet_in_event() { }

    const boost::shared_ptr<Buffer>& get_buffer() const { return buf; }

    static const Event_name static_get_name() {
        return "Packet_in_event";
    }

    datapathid datapath_id;
    uint16_t in_port;
    size_t   total_len;
    uint32_t buffer_id;
    uint8_t  reason;

    Packet_in_event(const Packet_in_event&);
    Packet_in_event& operator=(const Packet_in_event&);
};

} // namespace vigil

#endif /* packet-in.hh */
