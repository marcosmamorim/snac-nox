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
#ifndef BCAST_RESOLVE_HH
#define BCAST_RESOLVE_HH 1

#include "authenticator/authenticator.hh"
#include "component.hh"

namespace vigil {
namespace applications {

class Bcast_resolve
    : public container::Component {

public:
    Bcast_resolve(const container::Context*,
                  const xercesc::DOMNode*);

    static void getInstance(const container::Context*, Bcast_resolve*&);

    void configure(const container::Configuration*);
    void install();

    ~Bcast_resolve();

private:
    Authenticator *auth;

    Disposition handle_bcast_in(const Event&);
    bool get_mac(uint32_t, uint64_t&);

}; // class bcast_resolve

} // namespace applications
} // namespace vigil

#endif
