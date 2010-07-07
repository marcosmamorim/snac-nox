#include "user-event.hh"

namespace vigil {

User_event::User_event(Action a, const std::string& uname, datapathid dp,
                       uint16_t pt, ethernetaddr dl, uint32_t nw)
    : Event(static_get_name()), action(a), username(uname),
      datapath_id(dp), port(pt), dladdr(dl), nwaddr(nw)
{ }

}
