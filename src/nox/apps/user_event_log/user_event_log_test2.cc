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
#include <list>
#include <sys/time.h>
#include "hash_map.hh"

#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>

#include "component.hh"
#include "vlog.hh"
#include "user_event_log/user_event_log.hh" 
#include "bindings_storage/bindings_storage.hh"
using namespace std;
using namespace vigil;
using namespace vigil::container;
using namespace vigil::applications;
using namespace boost;


namespace vigil {
namespace applications { 

static Vlog_module lg("user-event-log-test");



class UserEventLogTest2
    : public Component
{
public:

    UserEventLogTest2(const container::Context* c,
                      const xercesc::DOMNode* xml) 
        : Component(c), counter(0) {
    }

    void configure(const Configuration*) {
        resolve(uel);
        resolve(b_store);
    }

    void install() {
        b_store->store_binding_state(datapathid::from_host(1),1,1,1, 
            "discovered;dan", Name::USER, false);
        b_store->add_name_for_location(datapathid::from_host(1),1,
                              "discovered;the #1 and #2 worst ap\\location name; ever", Name::LOCATION); 
 
        b_store->add_name_for_location(datapathid::from_host(1),0,
                          "discovered;switch #1", Name::SWITCH); 
        // this is a hack for simplicity.  we assume that NDB writes will
        // complete in 2 seconds, which should be quite safe 
        timeval tv = { 2, 0 };
        post(boost::bind(&UserEventLogTest2::timer_callback, this), tv);
    }

    void timer_callback() {
      char buf[128]; 
      snprintf(buf,128,"message #%d  source info: {su}, {sh}, {sl}", counter);
      string s(buf);

      ethernetaddr src_dladdr(1); 
      ethernetaddr dst_dladdr(9);
      LogEntry lentry("UserEventLogTest2",LogEntry::INFO, s); 
      lentry.addMacKey(src_dladdr,LogEntry::SRC); 
      lentry.addMacKey(dst_dladdr,LogEntry::DST);
      uel->log(lentry); 
      timeval tv = { 5, 0 };
      post(boost::bind(&UserEventLogTest2::timer_callback, this), tv);
      ++counter; 
    }

private:
   
    int counter; 
    User_Event_Log *uel;
    Bindings_Storage* b_store;
};




REGISTER_COMPONENT(container::Simple_component_factory<UserEventLogTest2>, 
                   UserEventLogTest2);

}
} 

