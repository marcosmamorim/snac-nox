# Copyright 2008 (C) Nicira, Inc.
#
# This file is part of NOX.
#
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
from nox.apps.tests import unittest
from nox.apps.storage import Storage
from nox.apps.storage import TransactionalStorage, TransactionalConnection
from nox.apps.configuration.properties import Properties

import logging
log = logging.getLogger('properties_test')

SECTION = 'property_test_section'

class DeleteSection():
    def __init__(self, storage, section):
        self.storage = storage
        self.section = section

    def begin(self, r):
        result, self.connection = r
        return self.connection.begin(TransactionalConnection.EXCLUSIVE)

    def get(self, r):
        return self.connection.get('PROPERTIES', { 'SECTION' : self.section })

    def get_next(self, r):
        result, self.cursor = r
        return self.cursor.get_next()

    def delete_rows(self, r):
        result, row = r
        if result[0] == Storage.NO_MORE_ROWS:
            return

        def get_next(r):
            return self.cursor.get_next().\
                addCallback(self.delete_rows)

        return self.connection.remove('PROPERTIES', row).\
            addCallback(get_next)
                
    def cursor_close(self, r):
        return self.cursor.close()

    def commit(self, r):
        return self.connection.commit()

    def rollback(self, failure):
        return self.connection.rollback().\
            addCallback(lambda x: failure)

    def __call__(self):
        return self.storage.get_connection().\
            addCallback(self.begin).\
            addCallback(self.get).\
            addCallback(self.get_next).\
            addCallback(self.delete_rows).\
            addCallback(self.cursor_close).\
            addCallback(self.commit).\
            addErrback(self.rollback)

class PropertiesTestCase(unittest.NoxTestCase):

    def getInterface(self):
        return str(PropertiesTestCase)

    def setUp(self):
        self.storage = self.ctxt.resolve(str(TransactionalStorage))
        return DeleteSection(self.storage, SECTION)()

    def tearDown(self):
        pass

    def report(self, failure):
        log.error("Error detected")
        log.error(str(failure))
        return failure

    def store_and_load(self):
        def store():
            defaults = { 'key_1' : [ 'should_be_overriden' ] }

            p = Properties(self.storage, SECTION, defaults)

            assert(isinstance(p, dict))
        
            def set_item_1(result):
                p['key_1'] = [u'value_a', 'value_b']
            
            def modify_item_1(result):
                p['key_1'] = ['value_c', 'value_d']
                p['key_1'][0] = 'value_0'

            def set_item_2(result):
                p['key_2'] = ['value_X', 'value_Y', u'value_Z']

            def get_item_1(result):
                a = p['key_1']

            def commit(result):
                return p.commit()

            return p.begin().\
                addCallback(set_item_1).\
                addCallback(modify_item_1).\
                addCallback(set_item_2).\
                addCallback(get_item_1).\
                addCallback(commit)

        def load(ignore):
            defaults = { 'key_1' : [ 'should_be_overriden' ],
                         'default' : [ 'default'] }

            p = Properties(self.storage, SECTION, defaults)

            def verify_contents(r):
                assert(len(p['key_1']) == 2)
                assert(len(p['key_2']) == 3)
                assert(len(p['default']) == 1)

                assert(p['key_1'][0] == 'value_0')
                assert(p['key_1'][1] == 'value_d')

                assert(p['key_2'][0] == 'value_X')
                assert(p['key_2'][1] == 'value_Y')
                assert(p['key_2'][2] == u'value_Z')

                assert(p['default'][0] == 'default')

            def begin(r):
                return p.begin()

            def modify_contents(r):
                p['key_2'][0] = 'value_X'
                p['key_2'][1] = 'value_Y'
                p['key_2'][2] = u'value_Z'
                p['key_2'].reverse()
                p['key_2'].sort()
                p['key_2'].remove(u'value_Z')

                assert(p['key_2'][0] == 'value_X')
                assert(p['key_2'][1] == 'value_Y')

                p['key_2'].insert(2, u'value_Z')
                p['key_2'].sort()

                assert(p['key_2'][0] == 'value_X')
                assert(p['key_2'][1] == 'value_Y')
                assert(p['key_2'][2] == u'value_Z')

                assert(len(p['key_2']) == 3)

                # Test the iterators
                keys = p.keys()
                assert(len(keys) == 3)
                assert('key_1' in keys)
                assert('key_2' in keys)
                assert(len(p['key_1']) == 2)
                    
            def commit(result):
                return p.commit()

            return p.load().\
                addCallback(verify_contents).\
                addCallback(begin).\
                addCallback(modify_contents).\
                addCallback(commit)

        return store().\
            addCallback(load).\
            addErrback(self.report)            

    def lock_test(self):
        props = Properties(self.storage, 'test')
        d = props.load()
        d.addCallback(lambda x : props.begin())
        return d

def suite(ctxt):
    pyunit = __import__('unittest')

    suite = pyunit.TestSuite()
    suite.addTest(PropertiesTestCase("store_and_load", ctxt))
    #the following test hangs
    #suite.addTest(PropertiesTestCase("lock_test", ctxt))
    return suite
