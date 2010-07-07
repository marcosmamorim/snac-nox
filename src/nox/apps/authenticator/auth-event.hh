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
#ifndef AUTH_EVENT_HH
#define AUTH_EVENT_HH 1

#include <boost/noncopyable.hpp>
#include <list>
#include <stdint.h>
#include <string>
#include <vector>

#include "event.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"

/*
 * Authentication event.
 *
 * Signals authentication/deauthentication of a location in the network
 * identified by a switch/port pair, a link layer address, and optionally a
 * network layer address to send traffic.  The event can additionally associate
 * the device with a host and/or user name (that can be used for policy
 * enforcement). The 'owns_dl' member should be set to 'true' when the entity
 * owns the dladdr interface.  A host for example would not own the interface
 * if it was behind a router.  An 'owns_dl' == false event must include a
 * non-zero network layer address.
 *
 * In reference to the Authenticator component, an "AUTHENTICATE" event
 * authenticates the location, additionally associating it with the host and/or
 * user names in the event.  The Authenticator defines three special name
 * constants Auth_events can use to signal certain semantics for the host
 * and/or user name for a location:
 *
 * UNKNOWN (Authenticator::get_unknown_name()) - Used when the event poster
 * doesn't know the name associated with the location.  If the location is
 * already associated with a name for this field, use that name.  If it's not
 * associated with a name, the name defaults to UNAUTHENTICATED (see next
 * special name).
 *
 * UNAUTHENTICATED (Authenticator::get_unauthenticated_name()) - Used when the
 * location has not authenticated a name for this field.  Common use case is
 * when the location should be able to send traffic even though it has not
 * authenticated as a specific principal.  It will be presented to the policy
 * as an "unauthenticated" principal.
 *
 * AUTHENTICATED (get_authenticated_name()) - Used when the location has
 * sufficiently authenticated as a principal, but not a specific principal.
 * Basically, a general "authenticated" principal name.
 *
 *
 * A "DEAUTHENTICATE" event meanwhile will unbind from the location the host
 * and/or user names specified in the event, with the option of
 * deauthenticating the entire location.  For deauthenticate events, the name
 * constants have the following semantics:
 *
 * UNKNOWN - Leave this name value (whatever it may be) as is, i.e. do not
 * deauthenticate it.  See below for special behavior when both names are set
 * to this value.
 *
 * UNAUTHENTICATED - Whatever this name value is, deauthenticate it.  If the
 * event's username is set to this, deauthenticate all users on the location.
 *
 * AUTHENTICATED - Treated as any other name (whose behavior described next).
 *
 * Other name values signal the name that should be deauthenticated from the
 * location and replaced with UNAUTHENTICATED.
 *
 * To completely deauthenticate a location, both the hostname and username in
 * the event should be set to UNKNOWN (signaling that no particular binding
 * should be removed, but rather the entire location should be).
 *
 *
 * All integer values are stored in host byte order, and should be passed in as
 * such.
 */

namespace vigil {

struct Auth_event
    : public Event,
      boost::noncopyable
{
    enum Action {
        AUTHENTICATE,
        DEAUTHENTICATE,
    };

    Auth_event(Action, datapathid, uint16_t,
               ethernetaddr, uint32_t, bool,
               const std::string&, const std::string&,
               uint32_t, uint32_t);

    Auth_event(const Auth_event& ae)
        : Event(static_get_name()), action(ae.action),
          datapath_id(ae.datapath_id), port(ae.port), dladdr(ae.dladdr),
          nwaddr(ae.nwaddr), owns_dl(ae.owns_dl), hostname(ae.hostname),
          username(ae.username), inactivity_timeout(ae.inactivity_timeout),
          hard_timeout(ae.hard_timeout), to_post(ae.to_post) { }

    // -- only for use within python
    Auth_event() : Event(static_get_name()) { }

    static const Event_name static_get_name() {
        return "Auth_event";
    }

    Action        action;
    datapathid    datapath_id;
    uint16_t      port;
    ethernetaddr  dladdr;
    uint32_t      nwaddr;       // set to zero if no IP to auth
    bool          owns_dl;
    std::string   hostname;
    std::string   username;
    uint32_t      inactivity_timeout;
    uint32_t      hard_timeout; // inactivity and hard timeouts, set to zero to
                                // use default and no timeout respectively.
    Event         *to_post;
};

} // namespace vigil

#endif /* auth-event.hh */
