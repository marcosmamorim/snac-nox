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
#include "bcast-in.hh"

namespace vigil {

Broadcast_in_event::Broadcast_in_event(const Flow& flow_,
                                       const timeval& received_,
                                       const Packet_in_event& pi)
    : Event(static_get_name()), flow(flow_), received(received_),
      datapath_id(pi.datapath_id), buf(pi.buf),
      total_len(pi.total_len), buffer_id(pi.buffer_id), reason(pi.reason)
{ }

}
