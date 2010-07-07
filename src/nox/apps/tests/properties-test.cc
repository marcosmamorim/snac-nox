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
#include <boost/bind.hpp>
#include <boost/test/unit_test.hpp>

#include "configuration/properties.hh"
#include "storage/transactional-storage.hh"
#include "tests.hh"
#include "vlog.hh"

using namespace vigil;
using namespace vigil::applications::configuration;
using namespace vigil::applications::storage;
using namespace std;
using namespace boost::unit_test;

namespace {

Vlog_module lg("properties-test");

class Properties_test_case
    : public testing::Test_component
{
public:
    Properties_test_case(const container::Context* c,
                         const xercesc::DOMNode* xml) 
        : Test_component(c) {
    }

    void configure(const container::Configuration*) {
        resolve(storage);
    }

    void install() {

    }

    void invalid();

    void run_test();

private:
    Async_transactional_storage* storage;
};

void Properties_test_case::run_test() {
    {
        Properties::Default_value_map defaults;
        std::vector<Property> v2;
        v2.push_back(Property("should_be_overriden"));
        defaults["key_1"] = v2;

        Properties p(storage, "TESTING", defaults);
        p.begin();
        
        Property_list_ptr l = p.get_value("key_1");
        l->clear();
        l->push_back(Property("value_a"));
        l->push_back(Property("value_b"));
        
        l->clear();
        l->push_back(Property("value_c"));
        l->push_back(Property("value_d"));
        
        l = p.get_value("key_2");
        l->clear();
        l->push_back(Property("value_X"));
        l->push_back(Property("value_Y"));
        l->push_back(Property("value_Z"));

        BOOST_REQUIRE(p.commit() == true);

        // Reuse the same properties for another update
        // transaction. Note how the begin() actually refreshes the
        // values from the database as well.

        p.begin();

        l = p.get_value("key_2");
        l->clear();
        l->push_back(Property("value_X"));
        l->push_back(Property("value_Y"));
        l->push_back(Property("value_Z"));

        BOOST_REQUIRE(p.commit() == true);
    }

    {
        Properties::Default_value_map defaults;
        std::vector<Property> v1;
        v1.push_back(Property("default"));
        defaults["default_key"] = v1;

        std::vector<Property> v2;
        v2.push_back(Property("should_be_overriden"));
        defaults["key_1"] = v2;

        Properties p(storage, "TESTING", defaults);
        p.load();

        Property_list_ptr l1 = p.get_value("key_1");
        Property_list_ptr l2 = p.get_value("key_2");
        BOOST_REQUIRE(l1->size() == 2);
        BOOST_REQUIRE(l2->size() == 3);

        BOOST_REQUIRE(boost::get<string>((*l1)[0].get_value()) == "value_c");
        BOOST_REQUIRE(boost::get<string>((*l1)[1].get_value()) == "value_d");

        BOOST_REQUIRE(boost::get<string>((*l2)[0].get_value()) == "value_X");
        BOOST_REQUIRE(boost::get<string>((*l2)[1].get_value()) == "value_Y");
        BOOST_REQUIRE(boost::get<string>((*l2)[2].get_value()) == "value_Z");

        Property_list_ptr l3 = p.get_value("default_key");
        BOOST_REQUIRE(l3->size() == 1);

        BOOST_REQUIRE(boost::get<string>((*l3)[0].get_value()) == "default");

        p.begin();

        Property_list_ptr l = p.get_value("key_2");
        (*l)[0].set_value("value_Xm");
        (*l)[1].set_value("value_Ym");
        (*l)[2].set_value("value_Zm");

        l->pop_back();
        l->push_back(Property("value_Z"));

        BOOST_REQUIRE(p.commit() == true);
    }
}

} /* unnamed namespace */

BOOST_AUTO_COMPONENT_TEST_CASE(Properties_test, Properties_test_case);
