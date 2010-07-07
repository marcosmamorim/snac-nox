#include <boost/bind.hpp>
#include <xercesc/dom/DOM.hpp>

#include "component.hh"
#include "datapath-leave.hh"

using namespace vigil;
using namespace vigil::container;

namespace {

class Exit
    : public Component 
{
public:
    Exit(const Context* c,
         const xercesc::DOMNode*) 
        : Component(c) { }

    void configure(const Configuration*) {
        
    }

    Disposition exit_handler(const Event& e)
    {
        return CONTINUE;
    }
    
    Disposition exit_leave_handler(const Event& e)
    {
        ::exit(0);
    }

    void install()
    {
        register_handler<Datapath_leave_event>
            (boost::bind(&Exit::exit_leave_handler, this, _1));
    }
};

REGISTER_COMPONENT(container::Simple_component_factory<Exit>, Exit);

} // unnamed namespace
