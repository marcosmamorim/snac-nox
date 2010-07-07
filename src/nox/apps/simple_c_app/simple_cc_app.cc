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
#include "component.hh"
#include "config.h"

#include <xercesc/dom/DOM.hpp>

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"

#else
#include "vlog.hh"
#endif

using namespace std;
using namespace vigil;
using namespace vigil::container;

namespace {

#ifdef LOG4CXX_ENABLED
static log4cxx::LoggerPtr lg(log4cxx::Logger::getLogger
                             ("nox.apps.simple-cc-component"));
#else
static Vlog_module lg("simple-cc-component");
#endif

class SimpleCCApp
    : public Component {
public:
    SimpleCCApp(const Context* c, const xercesc::DOMNode*)
        : Component(c) {
    }

    void configure(const Configuration*) {
        // Parse the configuration, register event handlers, and
        // resolve any dependencies.
#ifdef LOG4CXX_ENABLED
        LOG4CXX_DEBUG(lg, "Configure called");
        LOG4CXX_DEBUG(lg, boost::format("Formatting is %1% as %2%+%2%") 
                      % "easy" % 1);
#else
        lg.dbg(" Configure called ");
#endif
    }

    void install() {
        // Start the component. For example, if any threads require
        // starting, do it now.
#ifdef LOG4CXX_ENABLED
        LOG4CXX_DEBUG(lg, "Install called");
#else
        lg.dbg(" Install called ");
#endif
    }

private:

};

REGISTER_COMPONENT(container::Simple_component_factory<SimpleCCApp>,
                   SimpleCCApp);

} // unnamed namespace
