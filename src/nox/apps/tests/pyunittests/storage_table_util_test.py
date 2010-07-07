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

import logging
from nox.apps.tests import unittest
from nox.apps.storage import Storage, StorageException, TransactionalStorage
from nox.apps.storage.StorageTableUtil import *
from twisted.internet import defer

pyunit = __import__('unittest')

lg = logging.getLogger('storage_table_util_test')

def _compare_recs(r1, r2):
    return r1.strcol == r2.strcol \
           and r1.intcol == r2.intcol \
           and r1.floatcol == r2.floatcol

class StuTestRecord(StorageRecord):
    _columns = { 'strcol'   : str,   'intcol'   : int, 'floatcol' : float }
    __slots__ = _columns.keys()

    def __init__(self, strcol, intcol, floatcol):
        self.strcol = strcol
        self.intcol = intcol
        self.floatcol = floatcol

class StuTestTable(StorageTable):
    _table_name = 'storage_table_util_test'
    _table_indices = (
        ('str_idx',       ("strcol",)),
        ('int_float_idx', ("intcol", "floatcol")),
    )

    def __init__(self, storage, cache_contents=False):
        StorageTable.__init__(self, storage, self._table_name,
                StuTestRecord, self._table_indices, cache_contents)

class StorageTableUtilTestCase(unittest.NoxTestCase):

    def __init__(self, methodName, ctxt):
        unittest.NoxTestCase.__init__(self, methodName, ctxt)
        self.conn = None
        self.test_complete_deferred = None

    def configure(self, configuration):
        pass

    def install(self):
        self.storage = self.resolve(str(TransactionalStorage))
        self.test_complete_deferred = defer.Deferred()

    def getInterface(self):
        return str(StorageTableUtilTestCase)

    def setUp(self):
        def _conn_ok(res):
            result, self.conn = res
            self.failUnless(result[0] == Storage.SUCCESS,
                    'Could not connect to transactional storage')
            return self._dropTestTable()
        def _conn_err(failure):
            self.fail("can't get a connection to storage")
        d = self.storage.get_connection()
        d.addCallbacks(_conn_ok, _conn_err)
        return d

    def tearDown(self, res=None):
        if self.test_complete_deferred != None:
            self.test_complete_deferred.addCallback(self.tearDown)
        return self._dropTestTable()

    def _createTestTable(self, cached=False):
        def _create_ok(res):
            self.failUnless(res[0] == Storage.SUCCESS,
                    'Could not create test table')
            return table
        def _create_err(failure):
            self.fail("Failed to ensure table exists: '%s'"%failure)
        table = StuTestTable(self.storage, cache_contents=cached)
        d = table.ensure_table_exists()
        d.addCallbacks(_create_ok, _create_err)
        return d

    def _dropTestTable(self):
        if self.conn is not None:
            def _drop_ok(res):
                self.failUnless(res[0] == Storage.SUCCESS)
                lg.debug("Dropped test table")
            def _drop_err(failure):
                if failure.value.code == Storage.NONEXISTING_TABLE:
                    lg.debug("No existing test table to drop")
                else:
                    return failure
            d = self.conn.drop_table(StuTestTable._table_name)
            d.addErrback(_drop_err)
        else:
            d = defer.Deferred()
            d.callback((0,r''))
        return d

    def testEnsureTableExistsCached(self):
        return self.testEnsureTableExists(cached=True)

    def testEnsureTableExists(self, cached=False):
        def _already_created_ok(res):
            self.failUnless(res[0] == Storage.SUCCESS)
        def _already_created_err(failure):
            self.fail("Failed to ensure existing table exists: '%s'"%failure)
        def _ensure_ok(res):
            self.failUnless(res[0] == Storage.SUCCESS)
            d = table.ensure_table_exists()
            d.addCallbacks(_already_created_ok, _already_created_err)
        def _ensure_err(failure):
            self.fail("Failed to ensure table exists: '%s'"%failure)
        table = StuTestTable(self.storage, cache_contents=cached)
        d = table.ensure_table_exists()
        d.addCallbacks(_ensure_ok, _ensure_err)
        return d

    def testPutRecordCached(self):
        return self.testPutRecord(cached=True)

    def testPutRecord(self, cached=False):
        rec = StuTestRecord("col1", 1, 1.1)
        def _get_table(table):
            d = table.put_record(rec)
            d.addCallback(_put_ok, table)
            d.addErrback(_put_err)
            return d
        def _put_ok(res, table):
            self.failUnless(_compare_recs(res, rec), "Put record didn't match")
            d = table.get_all_recs_for_query({})
            d.addCallback(_get_ok)
            return d
        def _get_ok(recs):
            self.failUnless(len(recs) == 1, 'Incorrect rec count after put')
            r = recs[0]
            self.failUnless(_compare_recs(r, rec),
                            'Record does not match what we put')
        def _put_err(failure):
            self.fail("Failed to put record: '%s'"%failure)
        d = self._createTestTable(cached=cached)
        d.addCallback(_get_table)
        return d

    def testPutNoDupCached(self):
        return self.testPutNoDup(cached=True)

    def testPutNoDup(self, cached=False):
        rec = StuTestRecord("col1", 1, 1.1)
        def _get_table(table):
            d = table.put_record_no_dup(rec, ('str_idx','int_float_idx'))
            d.addCallback(_put_ok, table)
            d.addErrback(_put_err)
            return d
        def _put_ok(res, table):
            self.failUnless(_compare_recs(res, rec), "Put record didn't match")
            d = table.get_all_recs_for_query({})
            d.addCallback(_get_ok, table)
            return d
        def _put_err(failure):
            self.fail("Failed to put record: '%s'"%failure)
        def _get_ok(recs, table):
            self.failUnless(len(recs) == 1, 'Incorrect rec count after put')
            r = recs[0]
            self.failUnless(_compare_recs(r, rec),
                             'Record does not match what we put')
            #put was fine, put the same thing to fail
            d = table.put_record_no_dup(rec, ('str_idx','int_float_idx'))
            d.addCallbacks(_put_dup_ok, _put_dup_err)
            return d
        def _put_dup_ok(res):
            self.fail("We were able to put a duplicate record")
        def _put_dup_err(failure):
            result = failure.value
            self.failUnless(type(result) == tuple,
                "Expected tuple with value[0]==%d; got %s" 
                %(Storage.INVALID_ROW_OR_QUERY, type(result)))
            self.failUnless(result[0] == Storage.INVALID_ROW_OR_QUERY, 
                    "Put dup returned %d (expected %d)"
                    %(result[0], Storage.INVALID_ROW_OR_QUERY))
        d = self._createTestTable(cached=cached)
        d.addCallback(_get_table)
        return d

    def testPutAllCached(self):
        return self.testPutAll(cached=True)

    def testPutAll(self, cached=False):
        recs = ( StuTestRecord("col1", 1, 1.1),
                 StuTestRecord("col1", 2, 1.1),
                 StuTestRecord("col1", 3, 1.1) )
        def _get_table(table):
            d = table.put_all_records(recs)
            d.addCallback(_put_ok, table)
            d.addErrback(_put_err)
            return d
        def _put_ok(res, table):
            for i in range(len(recs)):
                self.failUnless(_compare_recs(res[i], recs[i]),
                                'Put return does not match what we put')
            d = table.get_all_recs_for_query({})
            d.addCallback(_get_ok, table)
            return d
        def _put_err(failure):
            self.fail("Failed to put records: '%s'"%failure)
        def _get_ok(get_recs, table):
            self.failUnless(len(get_recs) == len(recs),
                    'Wrong record count after put_all')
            get_recs.sort(cmp=lambda x,y: int(x.intcol - y.intcol))
            for i in range(len(recs)):
                self.failUnless(_compare_recs(get_recs[i], recs[i]),
                                 'Record does not match what we put')
        d = self._createTestTable(cached=cached)
        d.addCallback(_get_table)
        return d

    def testPutAllNoDup(self, cached=False):
        recs1 = ( StuTestRecord("col1", 1, 1.1),
                  StuTestRecord("col2", 2, 1.1),
                  StuTestRecord("col3", 3, 1.1) )
        recs2 = ( StuTestRecord("col4", 1, 1.1),
                  StuTestRecord("col1", 2, 1.1),
                  StuTestRecord("col5", 3, 1.1) )
        def _get_table(table):
            d = table.put_all_records(recs1)
            d.addCallback(_put_ok, table)
            d.addErrback(_put_err)
            return d
        def _put_ok(put_recs, table):
            self.failUnless(len(put_recs) == len(recs1),
                    'Wrong record count for put result')
            for i in range(len(recs1)):
                self.failUnless(_compare_recs(put_recs[i], recs1[i]),
                        'Record does not match what we put')
            d = table.get_all_recs_for_query({})
            d.addCallback(_get_ok, table)
            return d
        def _put_err(failure):
            self.fail("Failed to put records: '%s'"%failure)
        def _get_ok(get_recs, table):
            self.failUnless(len(get_recs) == len(recs1),
                    'Wrong record count after put_all')
            get_recs.sort(cmp=lambda x,y: int(x.intcol - y.intcol))
            for i in range(len(recs1)):
                self.failUnless(_compare_recs(get_recs[i], recs1[i]),
                                 'Record does not match what we put')
            lg.debug("-----------putting dups------------")
            d = table.put_all_records_no_dup(recs2, ('str_idx',))
            d.addCallback(_putdup_ok)
            d.addErrback(_putdup_err, table)
            return d
        def _putdup_ok(res):
            self.fail("Succeeded putting duplicate records")
        def _putdup_err(failure, table):
            d = table.get_all_recs_for_query({})
            d.addCallback(_get2_ok, table)
            return d
        def _get2_ok(get_recs, table):
            #should still only have rows from initial put
            self.failUnless(len(get_recs) == len(recs1),
                    'Wrong record count after putting dups')
            get_recs.sort(cmp=lambda x,y: int(x.intcol - y.intcol))
            for i in range(len(recs1)):
                self.failUnless(_compare_recs(get_recs[i], recs1[i]),
                                 'Failed put did not rollback correctly')
            return 
        d = self._createTestTable(cached=cached)
        d.addCallback(_get_table)
        return d

    def testPutAllNoDupCached(self, cached=False):
        return self.testPutAll(cached=True)

    def testGetAllCached(self):
        return self.testGetAll(cached=True)

    def testGetAll(self, cached=False):
        recs = ( StuTestRecord("col1", 1, 1.1),
                 StuTestRecord("col1", 2, 1.1),
                 StuTestRecord("col1", 3, 1.1) )
        def _get_table(table):
            d = table.put_all_records(recs)
            d.addCallback(_put_ok, table)
            d.addErrback(_put_err)
            return d
        def _put_ok(put_recs, table):
            for i in range(len(recs)):
                self.failUnless(_compare_recs(put_recs[i], recs[i]),
                        'Records do not match what we put')
            d = table.get_all_recs_for_query({'intcol':2, 'floatcol':1.1})
            d.addCallback(_get_1_ok, table)
            return d
        def _put_err(failure):
            self.fail("Failed to put records: '%s'"%failure)
        def _get_1_ok(get_recs, table):
            self.failUnless(len(get_recs) == 1, 
                    'Incorrect number of records returned in get_all')
            d = table.get_all_recs_for_query({'strcol':'col1'})
            d.addCallback(_get_2_ok, table)
            return d
        def _get_2_ok(get_recs, table):
            self.failUnless(len(get_recs) == 3, 
                    'Incorrect number of records returned in get_all')
        d = self._createTestTable(cached=cached)
        d.addCallback(_get_table)
        return d

    def testRemoveAllCached(self):
        return self.testRemoveAll(cached=True)

    def testRemoveAll(self, cached=False):
        recs = ( StuTestRecord("col1", 1, 1.1),
                 StuTestRecord("col2", 2, 2.2),
                 StuTestRecord("col3", 3, 3.3) )
        def _get_table(table):
            d = table.put_all_records(recs)
            d.addCallback(_put_ok, table)
            d.addErrback(_put_err)
            return d
        def _put_ok(put_recs, table):
            for i in range(len(recs)):
                self.failUnless(_compare_recs(put_recs[i], recs[i]),
                        'Records do not match what we put')
            d = table.remove_all_rows_for_query({'STRCOL':'col2'})
            d.addCallback(_remove_1_ok, table)
            return d
        def _put_err(failure):
            self.fail("Failed to put records: '%s'"%failure)
        def _remove_1_ok(removed_recs, table):
            self.failUnless(len(removed_recs) == 1, 
                    'Incorrect number of records (%d) returned in remove_all'
                    %len(removed_recs))
            d = table.get_all_recs_for_query({})
            d.addCallback(_get_1_ok, table)
            return d
        def _get_1_ok(get_recs, table):
            self.failUnless(len(get_recs) == 2, 
                    'Incorrect number of records left in remove_all')
            d = table.remove_all_rows_for_query({})
            d.addCallback(_remove_2_ok, table)
            return d
        def _remove_2_ok(removed_recs, table):
            self.failUnless(len(removed_recs) == 2, 
                    'Incorrect number of records returned in remove_all')
            d = table.get_all_recs_for_query({})
            d.addCallback(_get_2_ok, table)
            return d
        def _get_2_ok(get_recs, table):
            self.failUnless(len(get_recs) == 0, 
                    'Incorrect number of records left in remove_all')
        d = self._createTestTable(cached=cached)
        d.addCallback(_get_table)
        return d

    def testSearchUnindexed(self):
        recs = (
            StuTestRecord("col1", 1, 1.1),
            StuTestRecord("col2", 2, 2.2),
            StuTestRecord("col2a", 2, 2.23),
            StuTestRecord("col3", 3, 3.3),
            StuTestRecord("col3a", 3, 3.3),
        )
        def _get_table(table):
            d = table.put_all_records(recs)
            d.addCallback(_put_ok, table)
            return d
        def _put_ok(put_recs, table):
            d = table.get_all_recs_for_unindexed_query({'intcol':2}, {})
            d.addCallback(_get_1, table)
            return d
        def _get_1(recs, table):
            self.failUnless(len(recs) == 2,
                    'Incorrect number of records (%d) returned in get_1'
                    %len(recs))
            d = table.get_all_recs_for_unindexed_query(
                    {'intcol':3, 'floatcol':3.3, 'strcol':'col3'}, {})
            d.addCallback(_get_2_ok, table)
            return d
        def _get_2_ok(recs, table):
            self.failUnless(len(recs) == 1,
                    'Incorrect number of records (%d) returned in get_2'
                    %len(recs))
            d = table.get_all_recs_for_unindexed_query(
                    {}, {'strcol' : 'col.*'})
            d.addCallback(_get_3_ok, table)
            return d
        def _get_3_ok(recs, table):
            self.failUnless(len(recs) == 5,
                    'Incorrect number of records (%d) returned in get_3'
                    %len(recs))
            d = table.get_all_recs_for_unindexed_query(
                    {'intcol':2}, {'strcol' : '.*ol2.*'})
            d.addCallback(_get_4_ok, table)
            return d
        def _get_4_ok(recs, table):
            self.failUnless(len(recs) == 2,
                    'Incorrect number of records (%d) returned in get_4'
                    %len(recs))
            d = table.get_all_recs_for_unindexed_query(
                    {'intcol':2}, {'strcol' : '.*ol2$'})
            d.addCallback(_get_5_ok, table)
            return d
        def _get_5_ok(recs, table):
            self.failUnless(len(recs) == 1,
                    'Incorrect number of records (%d) returned in get_4'
                    %len(recs))
            d = table.get_all_recs_for_unindexed_query(
                    {'intcol':3, 'floatcol':3.3},
                    {'strcol' : 'col\\da'})
            d.addCallback(_get_6_ok, table)
            return d
        def _get_6_ok(recs, table):
            self.failUnless(len(recs) == 1,
                    'Incorrect number of records (%d) returned in get_4'
                    %len(recs))
        d = self._createTestTable()
        d.addCallback(_get_table)
        return d

    def testModifyCached(self):
        return self.testModify(cached=True)

    def testModify(self, cached=False):
        recs = ( StuTestRecord("col1", 1, 1.1),
                 StuTestRecord("col1", 2, 2.1),
                 StuTestRecord("col1", 3, 3.1) )
        def _get_table(table):
            d = table.put_all_records(recs)
            d.addCallback(_put_ok, table)
            d.addErrback(_put_err)
            return d
        def _put_ok(res, table):
            for i in range(len(recs)):
                self.failUnless(_compare_recs(res[i], recs[i]),
                                'Put return does not match what we put')
            res[0].intcol = 50
            d = table.modify_record(res[0])
            d.addCallback(_modify_ok, table)
            return d
        def _modify_ok(res, table):
            expected = StuTestRecord("col1", 50, 1.1)
            self.failUnless(_compare_recs(res, expected),
                    "Modify return does not match expected")
            d = table.get_all_recs_for_query({})
            d.addCallback(_get_ok, table)
            return d
        def _put_err(failure):
            self.fail("Failed to put records: '%s'"%failure)
        def _get_ok(get_recs, table):
            expected = StuTestRecord("col1", 50, 1.1)
            self.failUnless(len(get_recs) == len(recs),
                    'Wrong record count after put_all')
            get_recs.sort(cmp=lambda x,y: int(x.intcol - y.intcol))
            self.failUnless(_compare_recs(get_recs[0], recs[1]),
                             'Record1 does not match what we put')
            self.failUnless(_compare_recs(get_recs[1], recs[2]),
                             'Record3 does not match what we put')
            self.failUnless(_compare_recs(get_recs[2], expected),
                             'Record2 does not match what we modified')
        d = self._createTestTable(cached=cached)
        d.addCallback(_get_table)
        return d


def suite(ctxt):
    suite = pyunit.TestSuite()
    suite.addTest(StorageTableUtilTestCase("testEnsureTableExists", ctxt))
    suite.addTest(StorageTableUtilTestCase("testPutRecord", ctxt))
    suite.addTest(StorageTableUtilTestCase("testPutNoDup", ctxt))
    suite.addTest(StorageTableUtilTestCase("testPutAll", ctxt))
    suite.addTest(StorageTableUtilTestCase("testPutAllNoDup", ctxt))
    suite.addTest(StorageTableUtilTestCase("testGetAll", ctxt))
    suite.addTest(StorageTableUtilTestCase("testRemoveAll", ctxt))
    suite.addTest(StorageTableUtilTestCase("testModify", ctxt))

    suite.addTest(StorageTableUtilTestCase("testEnsureTableExistsCached",ctxt))
    suite.addTest(StorageTableUtilTestCase("testPutRecordCached", ctxt))
    suite.addTest(StorageTableUtilTestCase("testPutNoDupCached", ctxt))
    suite.addTest(StorageTableUtilTestCase("testPutAllCached", ctxt))
    suite.addTest(StorageTableUtilTestCase("testGetAllCached", ctxt))
    suite.addTest(StorageTableUtilTestCase("testRemoveAllCached", ctxt))
    suite.addTest(StorageTableUtilTestCase("testModifyCached", ctxt))

    suite.addTest(StorageTableUtilTestCase("testSearchUnindexed", ctxt))
    return suite
