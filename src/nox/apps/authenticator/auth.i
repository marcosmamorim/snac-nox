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
%module "nox.apps.authenticator.pyauth"

%{
#include "aggregate-stats-in.hh"
#include "bootstrap-complete.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "desc-stats-in.hh"
#include "echo-request.hh"
#include "flow-removed.hh"
#include "flow-mod-event.hh"
#include "port-stats-in.hh"
#include "table-stats-in.hh"
#include "port-status.hh"
#include "pyrt/pycontext.hh"
#include "pyrt/pyevent.hh"
#include "pyrt/pyglue.hh"

#include "authenticator.hh"
#include "auth-event.hh"
#include "host-event.hh"
#include "pyauth.hh"
#include "user-event.hh"

using namespace vigil;
using namespace vigil::applications;
%}

%import "netinet/netinet.i"
%import "../pyrt/event.i"
%import "../directory/directory.i"

%include "common-defs.i"
%include "std_string.i"
%include "std_list.i"
%include "pyauth.hh"

/*
 * Exposes Auth_event, Host_event, User_event, and Authenticator to Python
 */

struct Host_event
    : public Event
{
    enum Action {
        JOIN,
        LEAVE
    };

    Host_event(Action, datapathid, uint16_t,
               ethernetaddr, uint32_t, const std::string&);

    Host_event();

    Action        action;
    datapathid    datapath_id;
    uint16_t      port;
    ethernetaddr  dladdr;
    uint32_t      nwaddr;      // set to zero if no IP needed to define host
    std::string   name;

    static const std::string static_get_name();

%pythoncode
%{
    def __str__(self):
        action_map = {0:'JOIN',1:'LEAVE'}
        return 'Host_event '+action_map[self.action]+\
               ' [dpid: '+str(self.datapath_id)+' , port: ' + str(self.port) +\
               ' , dl: ' + str(self.dladdr) +' , nw: ' + hex(self.nwaddr) +\
               ' , name: ' + str(self.name) + ']'
%}

%extend {
    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const Host_event& he = dynamic_cast<const Host_event&>(e);

        pyglue_setattr_string(proxy, "action", to_python((uint32_t)(he.action)));
        pyglue_setattr_string(proxy, "datapath_id", to_python(he.datapath_id));
        pyglue_setattr_string(proxy, "port", to_python(he.port));
        pyglue_setattr_string(proxy, "dladdr", to_python(he.dladdr));
        pyglue_setattr_string(proxy, "nwaddr", to_python(he.nwaddr));
        pyglue_setattr_string(proxy, "name", to_python(he.name));

        ((Event*)SWIG_Python_GetSwigThis(proxy)->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        if (!SWIG_Python_GetSwigThis(ctxt) || !SWIG_Python_GetSwigThis(ctxt)->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)SWIG_Python_GetSwigThis(ctxt)->ptr;
        pyctxt->register_event_converter<Host_event>
            (&Host_event_fill_python_event);
    }
}

};


struct User_event
    : public Event
{
    enum Action {
        JOIN,
        LEAVE
    };

    User_event(Action, const std::string&, datapathid,
               uint16_t, ethernetaddr, uint32_t);

    User_event();

    Action        action;
    std::string   username;
    datapathid    datapath_id;
    uint16_t      port;
    ethernetaddr  dladdr;
    uint32_t      nwaddr;      // set to zero if no IP needed to define user

    static const std::string static_get_name();

%pythoncode
%{
    def __str__(self):
        action_map = {0:'JOIN',1:'LEAVE'}
        return 'User_event '+action_map[self.action]+' [uname: '+str(self.username)+\
               ' [dpid: '+str(self.datapath_id)+' , port: ' + str(self.port) +\
               ' , dl: ' + str(self.dladdr) +' , nw: ' + hex(self.nwaddr) + ']'
%}

%extend {
    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const User_event& he = dynamic_cast<const User_event&>(e);

        pyglue_setattr_string(proxy, "action", to_python((uint32_t)(he.action)));
        pyglue_setattr_string(proxy, "username", to_python(he.username));
        pyglue_setattr_string(proxy, "datapath_id", to_python(he.datapath_id));
        pyglue_setattr_string(proxy, "port", to_python(he.port));
        pyglue_setattr_string(proxy, "dladdr", to_python(he.dladdr));
        pyglue_setattr_string(proxy, "nwaddr", to_python(he.nwaddr));

        ((Event*)SWIG_Python_GetSwigThis(proxy)->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        if (!SWIG_Python_GetSwigThis(ctxt) || !SWIG_Python_GetSwigThis(ctxt)->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)SWIG_Python_GetSwigThis(ctxt)->ptr;
        pyctxt->register_event_converter<User_event>
            (&User_event_fill_python_event);
    }
}

};


struct Auth_event
    : public Event
{
    enum Action {
        AUTHENTICATE,
        DEAUTHENTICATE,
    };

    Auth_event(Action, datapathid, uint16_t, ethernetaddr, uint32_t, bool,
               const std::string&, const std::string&, uint32_t, uint32_t);

    Auth_event();

    Action        action;
    datapathid    datapath_id;
    uint16_t      port;
    ethernetaddr  dladdr;
    uint32_t      nwaddr;       // set to zero if no IP to auth
    bool          owns_dl;
    std::string   hostname;
    std::string   username;
    uint32_t      inactivity_timeout;
    uint32_t      hard_timeout;

    static const std::string static_get_name();

%pythoncode
%{
    def __str__(self):
        action_map = {0:'AUTHENTICATE',1:'DEAUTHENTICATE'}
        return 'Auth_event '+action_map[self.action]+\
               ' , dpid: '+str(self.datapath_id) + ' , port: ' + str(self.port) +\
               ' , dl: ' + str(self.dladdr) + ' , nw: ' + hex(self.nwaddr) +\
               ' , owns_dl: ' + str(self.owns_dl) +\
               ' , hname: ' + str(self.hostname) +\
               ' , uname: ' + str(self.username) +\
               ' , inactivity_timeout: ' + str(self.inactivity_timeout) +\
               ' , hard_timeout: ' + str(self.hard_timeout) + ']'
%}

%extend {

    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const Auth_event& ae = dynamic_cast<const Auth_event&>(e);

        pyglue_setattr_string(proxy, "action", to_python((uint32_t)(ae.action)));
        pyglue_setattr_string(proxy, "datapath_id", to_python(ae.datapath_id));
        pyglue_setattr_string(proxy, "port", to_python(ae.port));
        pyglue_setattr_string(proxy, "dladdr", to_python(ae.dladdr));
        pyglue_setattr_string(proxy, "nwaddr", to_python(ae.nwaddr));
        pyglue_setattr_string(proxy, "owns_dl", to_python(ae.owns_dl));
        pyglue_setattr_string(proxy, "hostname", to_python(ae.hostname));
        pyglue_setattr_string(proxy, "username", to_python(ae.username));
        pyglue_setattr_string(proxy, "inactivity_timeout", to_python(ae.inactivity_timeout));
        pyglue_setattr_string(proxy, "hard_timeout", to_python(ae.hard_timeout));

        ((Event*)SWIG_Python_GetSwigThis(proxy)->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        if (!SWIG_Python_GetSwigThis(ctxt) || !SWIG_Python_GetSwigThis(ctxt)->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)SWIG_Python_GetSwigThis(ctxt)->ptr;
        pyctxt->register_event_converter<Auth_event>
            (&Auth_event_fill_python_event);
    }
}

};


class Authenticator {
public:

    static const uint32_t UNAUTHENTICATED_ID;
    static const uint32_t AUTHENTICATED_ID;
    static const uint32_t UNKNOWN_ID;
    static const std::string& get_unauthenticated_name();
    static const std::string& get_authenticated_name();
    static const std::string& get_unknown_name();

};

%pythoncode
%{
    from nox.lib.core import Component

    class PyAuth(Component):
        def __init__(self, ctxt):
            Component.__init__(self, ctxt)
            self.authenticator = PyAuthenticator(ctxt)
        
        def configure(self, configuration):
            self.authenticator.configure(configuration)
            Host_event.register_event_converter(self.ctxt)
            User_event.register_event_converter(self.ctxt)
            Auth_event.register_event_converter(self.ctxt)

        def getInterface(self):
            return str(PyAuth)

        def get_principal_id(self, name, t, incr):
            return self.authenticator.get_principal_id(name, t, incr)

        def get_group_id(self, name, t, incr):
            return self.authenticator.get_group_id(name, t, incr)

        def decrement_id(self, id):
            return self.authenticator.decrement_id(id)

        def get_name(self, id):
            return self.authenticator.get_name(id)

        def reset_names(self):
            self.authenticator.reset_names()

        def set_lookup_unauth_dst(self, unauth_dst):
            self.authenticator.set_lookup_unauth_dst(unauth_dst)

        def set_host_timeout(self, dp, port, dladdr, nwaddr, sec, set_inactivity):
            self.authenticator.set_host_timeout(dp, port, dladdr, nwaddr, sec, set_inactivity)

        def reset_last_active(self, dp, port, dladdr, nwaddr):
            self.authenticator.reset_last_active(dp, port, dladdr, nwaddr)

        def add_internal_subnet(self, cidr):
            self.authenticator.add_internal_subnet(cidr)

        def remove_internal_subnet(self):
            self.authenticator.remove_internal_subnet(cidr)

        def clear_internal_subnets(self):
            self.authenticator.clear_internal_subnets()
            
        def get_names(self, dp, inport, dlsrc, nwsrc, dldst, nwdst, callable):
            self.authenticator.get_names(dp, inport, dlsrc, nwsrc, dldst,
                                         nwdst, callable)

    def getFactory():
        class Factory:
            def instance(self, context):
                return PyAuth(context)

        return Factory()
%}
