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
from nox.apps.tests.pyunittests.storage_test_base import StorageTestBase

pyunit = __import__('unittest')

class StorageTestCase(StorageTestBase):     

    def getInterface(self):
        return str(StorageTestCase)

    def setUp(self):
        try:
            from nox.apps.storage import Storage
            self.impl = self.ctxt.resolve(str(Storage))
        except Exception, e:
            print e
            assert(0)
 
    def tearDown(self):
        pass

def suite(ctxt):
    suite = pyunit.TestSuite()
    suite.addTest(StorageTestCase("testAddthenDrop", ctxt))
    suite.addTest(StorageTestCase("testAddthenPut", ctxt))
    suite.addTest(StorageTestCase("testAddthenPutWrongTable", ctxt))
    suite.addTest(StorageTestCase("testAddthenPutthenGet", ctxt))
    suite.addTest(StorageTestCase("testAddthenPutthenGetNextUsingIndex", ctxt))
    suite.addTest(StorageTestCase("testAddthenPutthenGetNextAll", ctxt))
    suite.addTest(StorageTestCase("testAddthenPutthenGetDoubleIndexCheck", ctxt))
    suite.addTest(StorageTestCase("testMultiIndex", ctxt))
    suite.addTest(StorageTestCase("testMultiIndexModify", ctxt))
    suite.addTest(StorageTestCase("testRemoveMultipleRows", ctxt))
    suite.addTest(StorageTestCase("testGetRemoveSequence", ctxt))
    suite.addTest(StorageTestCase("testCreateSchemaCheck", ctxt))
    return suite
