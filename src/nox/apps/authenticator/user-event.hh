#ifndef USER_EVENT_HH
#define USER_EVENT_HH 1

#include <boost/noncopyable.hpp>
#include <stdint.h>
#include <string>

#include "event.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"

/*
 * User join/leave event.
 *
 * Advertises a user as having joined or left a location the network.  The
 * location is defined by a switch/port pair, a link layer address, and
 * optionally a network layer address.
 *
 * All integer values are stored in host byte order, and should be passed in as
 * such.
 */

namespace vigil {

struct User_event
    : public Event,
      boost::noncopyable
{
    enum Action {
        JOIN,
        LEAVE
    };

    User_event(Action, const std::string&, datapathid,
               uint16_t, ethernetaddr, uint32_t);

    // -- only for use within python
    User_event() : Event(static_get_name()) { }

    static const Event_name static_get_name() {
        return "User_event";
    }

    Action        action;
    std::string   username;
    datapathid    datapath_id;
    uint16_t      port;
    ethernetaddr  dladdr;
    uint32_t      nwaddr;   // set to zero if no IP needed to define location
};

} // namespace vigil

#endif /* user-event.hh */
