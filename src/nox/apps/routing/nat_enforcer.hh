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
#ifndef NAT_ENFORCER_HH
#define NAT_ENFORCER_HH 1

#include <xercesc/dom/DOM.hpp>

#include "authenticator/flow_util.hh"
#include "classifier.hh"
#include "component.hh"
#include "flow.hh"

namespace vigil {
namespace applications {

struct NAT_data {
    const Flow *flow;
    const std::vector<uint32_t> *src_addr_groups;
    const std::vector<uint32_t> *dst_addr_groups;
};

class NAT_enforcer
    : public Classifier<Flow_expr, Flow_action>, public container::Component
{

public:
    NAT_enforcer(const container::Context*, const xercesc::DOMNode*);

    static void getInstance(const container::Context*, NAT_enforcer*&);

    void configure(const container::Configuration*);
    void install();

    void get_nat_locations(const Flow *flow,
                           const std::vector<uint32_t> *saddr_groups,
                           const std::vector<uint32_t> *daddr_groups,
                           std::vector<const std::vector<uint64_t>*>& locations);

    static
    bool nat_location(uint64_t location, uint64_t& dladdr,
                      std::vector<const std::vector<uint64_t>*>& locations);

private:
    NAT_data data;
    Cnode_result<Flow_expr, Flow_action, NAT_data> result;
}; // class NAT_enforcer

} // namespace applications

template<>
bool
get_field<Flow_expr, applications::NAT_data>(uint32_t,
                                             const applications::NAT_data&,
                                             uint32_t, uint32_t&);
template<>
bool matches(const Flow_expr&, const applications::NAT_data&);

} // namespace vigil

#endif // NAT_ENFORCER_HH
