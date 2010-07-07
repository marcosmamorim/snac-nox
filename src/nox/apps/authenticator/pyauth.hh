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
#ifndef CONTROLLER_PYHOSTGLUE_HH
#define CONTROLLER_PYHOSTGLUE_HH 1

#include <Python.h>

#include "authenticator.hh"
#include "component.hh"

/*
 * Proxy authenticator "component" used to set authenticator's python functions
 * and permit access to the authenticator's "updated_group" method.
 */

namespace vigil {
namespace applications {

class PyAuthenticator {
public:
    PyAuthenticator(PyObject*);

    void configure(PyObject*);

    uint32_t get_principal_id(const std::string& name,
                              Directory::Principal_Type, bool incr);
    uint32_t get_group_id(const std::string& name,
                          Directory::Group_Type, bool incr);
    void decrement_id(uint32_t);
    std::string get_name(uint32_t id) const;
    void reset_names();

    void set_lookup_unauth_dst(bool unauth_dst);

    void set_host_timeout(const datapathid&, uint16_t,
                          const ethernetaddr&, uint32_t, uint32_t, bool);
    void reset_last_active(const datapathid&, uint16_t,
                           const ethernetaddr&, uint32_t);

    void add_internal_subnet(const cidr_ipaddr&);
    void clear_internal_subnets();
    bool remove_internal_subnet(const cidr_ipaddr&);

    void get_names(const datapathid& dp, uint16_t inport,
                   const ethernetaddr& dlsrc, uint32_t nwsrc,
                   const ethernetaddr& dldst, uint32_t nwdst,
                   PyObject *callable);

private:
    Authenticator* authenticator;
    container::Component* c;
};

}
}

#endif
