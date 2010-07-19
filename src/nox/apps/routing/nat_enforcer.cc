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
#include "nat_enforcer.hh"

#include <boost/bind.hpp>
#include <inttypes.h>

#include "assert.hh"
#include "cnode-result.hh"
#include "vlog.hh"

using namespace vigil::applications;
using namespace vigil::container;

namespace vigil {
namespace applications {

static Vlog_module lg("nat_enforcer");

NAT_enforcer::NAT_enforcer(const container::Context* c,
                           const xercesc::DOMNode*)
    : Classifier<Flow_expr, Flow_action>(), Component(c),
      result(&data)
{}

void
NAT_enforcer::getInstance(const container::Context* ctxt,
                          NAT_enforcer*& r)
{
    r = dynamic_cast<NAT_enforcer*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(NAT_enforcer).name())));
}

void
NAT_enforcer::configure(const container::Configuration*)
{}

void
NAT_enforcer::install()
{}

void
NAT_enforcer::get_nat_locations(const Flow *flow,
                                const std::vector<uint32_t> *saddr_groups,
                                const std::vector<uint32_t> *daddr_groups,
                                std::vector<const std::vector<uint64_t>*>& locations)
{
    locations.clear();

    data.flow = flow;
    data.src_addr_groups = saddr_groups;
    data.dst_addr_groups = daddr_groups;

    const Rule<Flow_expr, Flow_action> *match;
    get_rules(result);
    while ((match = result.next()) != NULL) {
        locations.push_back(
            boost::get<std::vector<uint64_t> >(&match->action.arg));
    }
    result.clear();
}

bool
NAT_enforcer::nat_location(uint64_t location, uint64_t& dladdr,
                           std::vector<const std::vector<uint64_t>*>& locations)
{
    for (std::vector<const std::vector<uint64_t>*>::const_iterator iter = locations.begin();
         iter != locations.end(); ++iter)
    {
        const std::vector<uint64_t>& loc = **iter;
        if (location == loc[0]) {
            if (loc.size() > 1) {
                dladdr = loc[1];
            } else {
                dladdr = 0;
            }
            return true;
        }
    }
    return false;
}

} // namespace applications

static
bool
in_groups(const std::vector<uint32_t>& groups, uint32_t val)
{
    for (std::vector<uint32_t>::const_iterator iter = groups.begin();
         iter != groups.end(); ++iter)
    {
        if (val == *iter)
            return true;
        else if (val < *iter)
            return false;
    }

    return false;
}

template<>
bool
get_field<Flow_expr, NAT_data>(uint32_t field, const NAT_data& data,
                               uint32_t idx, uint32_t& value)
{
    uint64_t v;

    // No other supported fields have > 1 value
    if (idx > 0 && (field < Flow_expr::ADDRGROUPSRC
                    || field > Flow_expr::ADDRGROUPDST))
    {
        return false;
    }

    switch (field) {
    case Flow_expr::DLVLAN:
        value = data.flow->dl_vlan;
        return true;
    case Flow_expr::DLVLANPCP:
        value = data.flow->dl_vlan_pcp;
        return true;
    case Flow_expr::DLSRC:
        v = data.flow->dl_src.nb_long();
        value = ((uint32_t) v) ^ (v >> 32);
        return true;
    case Flow_expr::DLDST:
        v = data.flow->dl_dst.nb_long();
        value = ((uint32_t) v) ^ (v >> 32);
        return true;
    case Flow_expr::DLTYPE:
        value = data.flow->dl_type;
        return true;
    case Flow_expr::NWSRC:
        value = data.flow->nw_src;
        return true;
    case Flow_expr::NWDST:
        value = data.flow->nw_dst;
        return true;
    case Flow_expr::NWPROTO:
        value = data.flow->nw_proto;
        return true;
    case Flow_expr::NWTOS:
        value = data.flow->nw_tos;
        return true;
    case Flow_expr::TPSRC:
        value = data.flow->tp_src;
        return true;
    case Flow_expr::TPDST:
        value = data.flow->tp_dst;
        return true;
    case Flow_expr::ADDRGROUPSRC:
        if (data.src_addr_groups == NULL
            || idx >= data.src_addr_groups->size())
        {
            if (idx > 0)
                return false;
            value = 0;
        } else {
            value = data.src_addr_groups->at(idx);
        }
        return true;
    case Flow_expr::ADDRGROUPDST:
        if (data.dst_addr_groups == NULL
            || idx >= data.dst_addr_groups->size())
        {
            if (idx > 0)
                return false;
            value = 0;
        } else {
            value = data.dst_addr_groups->at(idx);
        }
        return true;
    }

    VLOG_ERR(lg, "Classifier was split on field not retrievable from a NAT_data.");

    if (idx > 0) {
        return false;
    }
    // return true so that doesn't try to do ANY and look at all children
    value = 0;
    return true;
}


template<>
bool
matches(const Flow_expr& expr, const NAT_data& data)
{
    const Flow& flow = *(data.flow);

    bool bad_result = false; // equality result signaling failed match
    int32_t t;

    std::vector<Flow_expr::Pred>::const_iterator end = expr.m_preds.end();
    for (std::vector<Flow_expr::Pred>::const_iterator iter = expr.m_preds.begin();
         iter != end; ++iter)
    {
        if (iter->type < 0) {
            t = -1 * iter->type;
            bad_result = true;
        } else {
            t = iter->type;
            // bad_result should already be set
        }

        switch (t) {
        case Flow_expr::DLVLAN:
            if (((uint32_t)(iter->val) == flow.dl_vlan) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::DLVLANPCP:
            if (((uint32_t)(iter->val) == flow.dl_vlan_pcp) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::DLSRC:
            if ((iter->val == flow.dl_src.nb_long()) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::DLDST:
            if ((iter->val == flow.dl_dst.nb_long()) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::DLTYPE:
            if (((uint32_t)(iter->val) == flow.dl_type) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::NWSRC:
            if (((uint32_t)(iter->val) == flow.nw_src) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::NWDST:
            if (((uint32_t)(iter->val) == flow.nw_dst) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::NWPROTO:
            if (((uint32_t)(iter->val) == flow.nw_proto) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::NWTOS:
            if (((uint32_t)(iter->val) == flow.nw_tos) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::TPSRC:
            if (((uint32_t)(iter->val) == flow.tp_src) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::TPDST:
            if (((uint32_t)(iter->val) == flow.tp_dst) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::ADDRGROUPSRC:
            if (data.src_addr_groups == NULL) {
                if (!bad_result) {
                    return false;
                }
            } else if (in_groups(*(data.src_addr_groups), iter->val) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::ADDRGROUPDST:
            if (data.dst_addr_groups == NULL) {
                if (!bad_result) {
                    return false;
                }
            } else if (in_groups(*(data.dst_addr_groups), iter->val) == bad_result) {
                return false;
            }
            break;
        case Flow_expr::SUBNETSRC:
            if ((((uint32_t)(iter->val >> 32) & flow.nw_src)
                 == (uint32_t)iter->val) == bad_result)
            {
                return false;
            }
            break;
        case Flow_expr::SUBNETDST:
            if ((((uint32_t)(iter->val >> 32) & flow.nw_dst)
                 == (uint32_t)iter->val) == bad_result)
            {
                return false;
            }
            break;
        default:
            VLOG_ERR(lg, "Rule defined on field not retrievable from a NAT_data.");
            return false;
        }
    }

    return true;
}

} // namespace vigil

REGISTER_COMPONENT(Simple_component_factory<NAT_enforcer>,
                   NAT_enforcer);
