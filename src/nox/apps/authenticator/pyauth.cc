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
#include "pyauth.hh"

#include "swigpyrun.h"
#include "pyrt/pycontext.hh"

namespace vigil {
namespace applications {

PyAuthenticator::PyAuthenticator(PyObject* ctxt)
    : authenticator(0)
{
    if (!SWIG_Python_GetSwigThis(ctxt) || !SWIG_Python_GetSwigThis(ctxt)->ptr) {
        throw std::runtime_error("Unable to access Python context.");
    }

    c = ((PyContext*)SWIG_Python_GetSwigThis(ctxt)->ptr)->c;
}

void
PyAuthenticator::configure(PyObject* configuration) {
    c->resolve(authenticator);
}

uint32_t
PyAuthenticator::get_principal_id(const std::string& name,
                                  Directory::Principal_Type ptype, bool incr)
{
    return authenticator->get_id(name, ptype, (Directory::Group_Type)0,
                                 true, incr);
}

uint32_t
PyAuthenticator::get_group_id(const std::string& name,
                              Directory::Group_Type gtype, bool incr)

{
    return authenticator->get_id(name, (Directory::Principal_Type)0,
                                 gtype, false, incr);
}

void
PyAuthenticator::decrement_id(uint32_t id)
{
    authenticator->decrement_id(id);
}

std::string
PyAuthenticator::get_name(uint32_t id) const
{
    return authenticator->get_name(id);
}

void
PyAuthenticator::reset_names()
{
    authenticator->reset_names();
}

void
PyAuthenticator::set_lookup_unauth_dst(bool unauth_dst)
{
    authenticator->set_lookup_unauth_dst(unauth_dst);
}

void
PyAuthenticator::set_host_timeout(const datapathid& dp, uint16_t port,
                                  const ethernetaddr& dladdr, uint32_t nwaddr, uint32_t sec,
                                  bool set_inactivity)
{
    authenticator->set_host_timeout(dp, port, dladdr, nwaddr, sec, set_inactivity);
}

void
PyAuthenticator::reset_last_active(const datapathid& dp, uint16_t port,
                                   const ethernetaddr& dladdr, uint32_t nwaddr)
{
    authenticator->reset_last_active(dp, port, dladdr, nwaddr);
}

void
PyAuthenticator::add_internal_subnet(const cidr_ipaddr& cidr)
{
    authenticator->add_internal_subnet(cidr);
}

void
PyAuthenticator::clear_internal_subnets()
{
    authenticator->clear_internal_subnets();
}

bool
PyAuthenticator::remove_internal_subnet(const cidr_ipaddr& cidr)
{
    return authenticator->remove_internal_subnet(cidr);
}

void
PyAuthenticator::get_names(const datapathid& dp, uint16_t inport,
                           const ethernetaddr& dlsrc, uint32_t nwsrc,
                           const ethernetaddr& dldst, uint32_t nwdst,
                           PyObject *callable)
{
    authenticator->get_names(dp, inport, dlsrc, nwsrc, dldst, nwdst, callable);
}

}
}

