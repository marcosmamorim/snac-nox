#include <boost/bind.hpp>
#include <xercesc/dom/DOM.hpp>

#include "component.hh"
#include "datapath-leave.hh"
#include "packet-in.hh"

using namespace vigil;
using namespace vigil::container;

namespace {

class Noop
    : public Component 
{
public:
    Noop(const Context* c,
         const xercesc::DOMNode*) 
        : Component(c) { }

    void configure(const Configuration*) {
        
    }

    Disposition noop_handler(const Event& e)
    {
        return CONTINUE;
    }
    
    Disposition noop_leave_handler(const Event& e)
    {
        ::exit(0);
    }

    void install()
    {
        register_handler<Datapath_leave_event>
            (boost::bind(&Noop::noop_leave_handler, this, _1));
        register_handler<Packet_in_event>
            (boost::bind(&Noop::noop_handler, this, _1));
    }
};

REGISTER_COMPONENT(container::Simple_component_factory<Noop>, Noop);

} // unnamed namespace
