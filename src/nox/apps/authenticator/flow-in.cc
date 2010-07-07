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
#include "flow-in.hh"
#include "bcast-in.hh"
#include "vlog.hh"

namespace vigil {

static Vlog_module lg("flow_in");

Flow_in_event::Flow_in_event(const Flow& flow_,
                             const timeval& received_,
                             const Packet_in_event& pi)
    : Event(static_get_name()), flow(flow_), active(true), fn_applied(false),
      received(received_), routed_to(NOT_ROUTED), src_dl_authed(false),
      src_nw_authed(false), dst_dl_authed(false), dst_nw_authed(false),
      datapath_id(pi.datapath_id), buf(pi.buf), total_len(pi.total_len),
      buffer_id(pi.buffer_id), reason(pi.reason)
{ }

Flow_in_event::Flow_in_event(const Broadcast_in_event& bi)
    : Event(static_get_name()), flow(bi.flow), active(true), fn_applied(false),
      received(bi.received), source(bi.source), route_source(bi.route_source),
      routed_to(NOT_ROUTED), src_addr_groups(bi.src_addr_groups),
      dst_addr_groups(bi.dst_addr_groups), src_dl_authed(bi.src_dl_authed),
      src_nw_authed(bi.src_nw_authed), dst_dl_authed(false), dst_nw_authed(false),
      datapath_id(bi.datapath_id), buf(bi.buf), total_len(bi.total_len),
      buffer_id(bi.buffer_id), reason(bi.reason)
{ }

void
Flow_in_event::set_destination_list(const ConnList& conns)
{
    destinations.resize(conns.size());
    DestinationList::iterator iter = destinations.begin();
    ConnList::const_iterator citer = conns.begin();
    for (; citer != conns.end(); ++iter, ++citer) {
        iter->connector = *citer;
        iter->allowed = true;
    }
}

#ifdef TWISTED_ENABLED

template <>
PyObject*
to_python(const user_info& ui)
{
    PyObject *user = PyTuple_New(2);
    if (user == NULL) {
        VLOG_ERR(lg, "Could not create python tuple");
        Py_RETURN_NONE;
    }

    if (PyTuple_SetItem(user, 0, to_python(ui.user)) != 0) {
        VLOG_ERR(lg, "Could not set user tuple item");
    }
    if (PyTuple_SetItem(user, 1, to_python_list(ui.groups)) != 0) {
        VLOG_ERR(lg, "Could not set user tuple item");
    }

    return user;
}

template <>
PyObject*
to_python(const Connector& conn)
{
    PyObject *connector = PyDict_New();
    if (connector == NULL) {
        VLOG_ERR(lg, "Could not create python dict");
        Py_RETURN_NONE;
    }
    pyglue_setdict_string(connector, "location", to_python(conn.location));
    pyglue_setdict_string(connector, "is_internal", to_python(conn.is_internal));
    pyglue_setdict_string(connector, "ap", to_python(conn.ap));
    pyglue_setdict_string(connector, "host", to_python(conn.host));
    pyglue_setdict_string(connector, "hostgroups", to_python_list(conn.hostgroups));
    PyObject *pylist = PyList_New(conn.users.size());
    if (pylist == NULL) {
        Py_INCREF(Py_None);
        pylist = Py_None;
        VLOG_ERR(lg, "Could not create python list");
    } else {
        std::list<user_info>::const_iterator user = conn.users.begin();
        for (uint32_t i = 0; user != conn.users.end(); ++i, ++user) {
            if (PyList_SetItem(pylist, i, to_python(*user)) != 0) {
                VLOG_ERR(lg, "Could not set user list item");
            }
        }
    }
    pyglue_setdict_string(connector, "users", pylist);
    pyglue_setdict_string(connector, "n_bindings", to_python(conn.n_bindings));
    pyglue_setdict_string(connector, "last_active", to_python(conn.last_active));
    pyglue_setdict_string(connector, "hard_timeout", to_python(conn.hard_timeout));
    pyglue_setdict_string(connector, "inactivity_len", to_python(conn.inactivity_len));

    return connector;
}

template <>
PyObject*
to_python(const ConnList& conns)
{
    PyObject *connectors = PyList_New(conns.size());
    if (connectors == NULL) {
        VLOG_ERR(lg, "Could not create python list");
        Py_RETURN_NONE;
    }

    ConnList::const_iterator d(conns.begin());
    for (uint32_t i = 0; d != conns.end(); ++i, ++d) {
        if (PyList_SetItem(connectors, i, to_python(**d)) != 0) {
            VLOG_ERR(lg, "Could not set connector list item");
        }
    }
    return connectors;
}

template <>
PyObject*
to_python(const Flow_in_event::DestinationInfo& dst)
{
    PyObject *destination = PyDict_New();
    if (destination == NULL) {
        VLOG_ERR(lg, "Could not create python dict");
        Py_RETURN_NONE;
    }
    pyglue_setdict_string(destination, "connector", to_python(*(dst.connector)));
    pyglue_setdict_string(destination, "allowed", to_python(dst.allowed));
    pyglue_setdict_string(destination, "waypoints", to_python_list(dst.waypoints));
    pyglue_setdict_string(destination, "rules", to_python_list(dst.rules));

    return destination;
}

template <>
PyObject*
to_python(const Flow_in_event::DestinationList& dsts)
{
    PyObject *destinations = PyList_New(dsts.size());
    if (destinations == NULL) {
        VLOG_ERR(lg, "Could not create python list");
        Py_RETURN_NONE;
    }

    for (uint32_t i = 0; i < dsts.size(); ++i) {
        if (PyList_SetItem(destinations, i, to_python(dsts[i])) != 0) {
            VLOG_ERR(lg, "Could not set destination list item %u.", i);
        }
    }
    return destinations;
}

PyObject*
route_source_to_python(const ConnPtr& src)
{
    if (src == NULL) {
        Py_RETURN_NONE;
    }

    PyObject *ret = to_python(src->location);
    if (ret == NULL) {
        VLOG_ERR(lg, "Could not set src_to_route location");
        Py_RETURN_NONE;
    }
    return ret;
}

PyObject*
route_destinations_to_python(const ConnList& dst)
{
    PyObject *lst = PyList_New(dst.size());
    if (lst == NULL) {
        VLOG_ERR(lg, "Could not create python list");
        Py_RETURN_NONE;
    }

    ConnList::const_iterator d(dst.begin());
    for (uint32_t i = 0; d != dst.end(); ++i, ++d) {
        if (PyList_SetItem(lst, i, to_python((*d)->location)) != 0) {
            VLOG_ERR(lg, "Could not set dst_to_route location");
        }
    }
    return lst;
}


#endif

}
