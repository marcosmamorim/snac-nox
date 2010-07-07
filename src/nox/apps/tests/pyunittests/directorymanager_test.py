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
from nox.apps.directory.directorymanager import *
from nox.apps.directory.discovered_directory import discovered_directory
from nox.apps.directory.pydirmanager import Directory as cDirectory
from nox.apps.storage import StorageTableUtil
from nox.lib.directory import *
from twisted.internet import defer

NO_SUPPORT = Directory.NO_SUPPORT
READ_ONLY_SUPPORT = Directory.READ_ONLY_SUPPORT
READ_WRITE_SUPPORT = Directory.READ_WRITE_SUPPORT

pyunit = __import__('unittest')

lg = logging.getLogger('directorymanager_test')

class DummyDirectory(Directory):
    """A very hacked up Directory for testing"""
    def __init__(self, name, type="DummyDirectory", global_groups=False,
            all_principal_support=None, all_group_support=None,
            supported_auth_types=(), enabled_auth_types=(),
            simple_auth_result=AuthResult.INVALID_CREDENTIALS,
            topology_supported=NO_SUPPORT, 
            switches_supported=NO_SUPPORT, switches_enabled=NO_SUPPORT,
            switch_groups_supported=NO_SUPPORT,
            locations_supported=NO_SUPPORT, locations_enabled=NO_SUPPORT,
            loc_groups_supported=NO_SUPPORT,
            hosts_supported=NO_SUPPORT, hosts_enabled=NO_SUPPORT,
            host_groups_supported=NO_SUPPORT,
            users_supported=NO_SUPPORT, users_enabled=NO_SUPPORT,
            user_groups_supported=NO_SUPPORT,
            dladdr_groups_supported=NO_SUPPORT,
            dladdr_groups_enabled=NO_SUPPORT,
            nwaddr_groups_supported=NO_SUPPORT,
            nwaddr_groups_enabled=NO_SUPPORT,
            ):
        self.name = name
        self.type = type
        setattr(self, 'get_type', lambda:self.type)
        setattr(self, 'get_instance', self._get_instance)

        setattr(self, 'supported_auth_types', lambda:supported_auth_types)
        setattr(self, 'get_enabled_auth_types', lambda:enabled_auth_types)
        setattr(self, 'simple_auth', lambda name, pw:
                defer.succeed(AuthResult(simple_auth_result, name)))

        setattr(self, 'topology_properties_supported',
                lambda:topology_supported)

        setattr(self, 'supports_global_groups', lambda:global_groups)

        setattr(self, 'switches_supported', 
                lambda:all_principal_support or switches_supported)
        setattr(self, 'switch_groups_supported',
                lambda:all_group_support or switch_groups_supported)
        setattr(self, 'locations_supported',
                lambda:all_principal_support or locations_supported)
        setattr(self, 'location_groups_supported',
                lambda:all_group_support or loc_groups_supported)
        setattr(self, 'hosts_supported',
                lambda:all_principal_support or hosts_supported)
        setattr(self, 'host_groups_supported',
                lambda:all_group_support or host_groups_supported)
        setattr(self, 'users_supported',
                lambda:all_principal_support or users_supported)
        setattr(self, 'user_groups_supported',
                lambda:all_group_support or user_groups_supported)
        setattr(self, 'nwaddr_groups_supported',
                lambda:all_group_support or nwaddr_groups_supported)
        setattr(self, 'dladdr_groups_supported',
                lambda:all_group_support or dladdr_groups_supported)

        setattr(self, 'get_group', self._deferred_with_info)
        setattr(self, 'del_group', self._deferred_with_info)
        setattr(self, 'add_group_members', self._deferred_membership)
        setattr(self, 'del_group_members', self._deferred_membership)

        self.name = name
        Directory.__init__(self)

    def validate_mangling(self, name):
        if self.supports_global_groups():
            if not is_mangled_name(name):
                raise Exception("Unmangled name in call to  directory "
                        "with global groups")
        else:
            if is_mangled_name(name):
                raise Exception("Mangled name in call to directory without "
                        "global groups")

    def get_group_membership(self, *args, **kwargs):
        lg.debug("get_group_membership called for %s: %s %s" %(self.name,
                args, kwargs))
        d = defer.Deferred()
        ret = set([self.name])
        if 'local_groups' in kwargs:
            ret = ret | set(kwargs['local_groups'])
        d.callback(tuple(ret))
        return d

    def add_group(self, group_type, info_obj, dir_name=""):
        lg.debug("deferred_add_group called for %s: %s %s %s" %(self.name,
                info_obj.name, info_obj.member_names, info_obj.subgroup_names))
        if is_mangled_name(info_obj.name):
            raise Exception("Mangled name in call to add_group")
        for name in info_obj.member_names:
            self.validate_mangling(name)
        for name in info_obj.subgroup_names:
            self.validate_mangling(name)
        d = defer.Deferred()
        d.callback(info_obj)
        return d

    def get_group_parents(self, *args, **kwargs):
        lg.debug("deferred_with_list called for %s: %s %s" %(self.name,
                args, kwargs))
        d = defer.Deferred()
        d.callback([self.name,])
        return d

    def _get_instance(self, name, config_id):
        lg.debug("get_instance called with %s:%s:%s"
                %(self.name, name, config_id))
        self.cname = name
        return defer.succeed(self)

    def _deferred_membership(self, grouptype, groupname, members, subgroups,
            dir_name=""):
        lg.debug("deferred_membersip called for %s: groupname:%s members:%s "\
                 "subgroups:%s" %(self.name, groupname, members, subgroups))
        if is_mangled_name(groupname):
            raise Exception("Mangled name in group membership call")
        for name in members:
            self.validate_mangling(name)
        for name in subgroups:
            self.validate_mangling(name)
        return defer.succeed((members, subgroups))

    def _deferred_with_info(self, *args, **kwargs):
        lg.debug("deferred_with_info called for %s: %s %s" %(self.name,
                args, kwargs))
        d = defer.Deferred()
        p = PrincipalInfo()
        p.member_names = []
        p.subgroup_names = []
        p.name = self.name
        d.callback(p)
        return d


class DirectorymanagerTestCase(unittest.NoxTestCase):

    def __init__(self, methodName, ctxt):
        unittest.NoxTestCase.__init__(self, methodName, ctxt)

    def configure(self, configuration):
        pass

    def install(self):
        self.dm = self.resolve(str(directorymanager))

    def getInterface(self):
        return str(DirectorymanagerTestCase)

    def setUp(self):
        self.old_instances = self.dm.directory_instances
        self.old_instances_by_name = self.dm.instances_by_name
        self._set_directories([])
        d = StorageTableUtil.drop_tables(self.dm.storage,
                (ConfiguredDirectoryTable._table_name,))
        d.addCallback(self.dm.init_cdb_tables)
        return d

    def tearDown(self, res=None):
        self.dm.directory_instances = self.old_instances
        self.dm.instances_by_name = self.old_instances_by_name
        d = StorageTableUtil.drop_tables(self.dm.storage,
                (ConfiguredDirectoryTable._table_name,))
        d.addCallback(self.dm.init_cdb_tables)
        return d

    def _set_directories(self, instances):
        self.dm.directory_instances = []
        self.dm.instances_by_name = {}
        i = 0
        for instance in instances:
            di = DirectoryInstanceDecorator(instance, instance.name, 0, i)
            i += 1
            self.dm.directory_instances.append(di)
            self.dm.instances_by_name[instance.name] = di

    def _err(self, res):
        lg.error("error in test %s" %res)
        res.printTraceback()
        import traceback
        traceback.print_exc()
        #code.interact(local=locals()) #XXX
        return res

    def testDirectoryManagement(self):
        # we must fake the discovered directory for redorder tests
        self.discovered_dir = discovered_directory() 
        testDir1 = ConfiguredDirectoryRecord('test_dir1',
                        'dirType1', search_order=1, config_id=1)
        testDir2 = ConfiguredDirectoryRecord('test_dir2',
                        'dirType2', search_order=2, config_id=2)
        testDir3 = ConfiguredDirectoryRecord('test_dir3',
                        'dirType1', search_order=0, config_id=3)
        testDir4 = ConfiguredDirectoryRecord('test_dir4',
                        'dirType2', search_order=1, config_id=4)
        dirComp1 = DummyDirectory("test_dir_if1")
        dirComp1.get_type = lambda : "dirType1"
        self.dm.register_directory_component(dirComp1)
        dirComp2 = DummyDirectory("test_dir_if2")
        dirComp2.get_type = lambda : "dirType2"
        def _test_dm(res=None, state='entry'):
            lg.debug("testDirectoryManagement:------- %s : %s ---------"
                    %(state, str(res)))
            if state == 'entry':
                self.failUnless(self.dm.get_configured_directories() == [],
                        "Unexpected configured directory")
                self.failUnless(len(self.dm.get_configured_directories()) == 0,
                        "Unexpected configured directory count")
                self.failUnless(len(self.dm.get_directory_instances()) == 0,
                        "Unexpected directory instance count")
                d = self.dm.add_configured_directory(testDir1.name,
                        testDir1.type, testDir1.search_order,
                        testDir1.config_id)
                d.addCallback(_test_dm, 'added_test_dir1')
            elif state == 'added_test_dir1':
                self.failUnless(len(res) == 1 and res[0].name == testDir1.name,
                        "Unexpected return from add_test_dir1")
                try:
                    d = self.dm.add_configured_directory(testDir1.name,
                            testDir1.type, testDir1.search_order,
                            testDir1.config_id)
                except Exception, e:
                    #temporarily add dirComp2 so we can register
                    self.dm.directory_components['dirType2'] = dirComp2
                    d = self.dm.add_configured_directory(testDir2.name,
                            testDir2.type, testDir2.search_order,
                            testDir2.config_id)
                    d.addCallback(_test_dm, 'added_test_dir2')
                else:
                    self.fail("Did not get exception with dup configured "
                            "directory test_dir1")
            elif state == 'added_test_dir2':
                self.failUnless(len(res) == 2,
                        "Unexpected return len from add_test_dir2")
                dirs = self.dm.get_configured_directories(sorted=True)
                self.failUnless(res[1].name == testDir2.name, 
                        "Unexpected return from add_test_dir2")
                del self.dm.directory_components['dirType2']
                d = self.dm.add_configured_directory(testDir3.name,
                        testDir3.type, testDir3.search_order,
                        testDir3.config_id)
                d.addCallback(_test_dm, 'added_test_dir3')
            elif state == 'added_test_dir3':
                self.failUnless(len(res) == 3,
                        "Unexpected return len from add_test_dir3")
                dirs = self.dm.get_configured_directories(sorted=True)
                self.failUnless(res[0].name == testDir3.name, 
                        "Unexpected return order (0) from add_test_dir3")
                self.failUnless(res[1].name == testDir1.name, 
                        "Unexpected return order (1) from add_test_dir3")
                self.failUnless(res[2].name == testDir2.name, 
                        "Unexpected return order (2) from add_test_dir3")
                #temporarily add dirComp2 so we can register
                self.dm.directory_components['dirType2'] = dirComp2
                d = self.dm.add_configured_directory(testDir4.name,
                        testDir4.type, testDir4.search_order,
                        testDir4.config_id)
                d.addCallback(_test_dm, 'added_test_dir4')
            elif state == 'added_test_dir4':
                self.failUnless(len(res) == 4,
                        "Unexpected return len from add_test_dir4")
                del self.dm.directory_components['dirType2']
                dirs = self.dm.get_configured_directories(sorted=True)
                self.failUnless(res[0].name == testDir3.name, 
                        "Unexpected return order (0) from add_test_dir4")
                self.failUnless(res[1].name == testDir4.name, 
                        "Unexpected return order (1) from add_test_dir4")
                self.failUnless(res[2].name == testDir1.name, 
                        "Unexpected return order (2) from add_test_dir4")
                self.failUnless(res[3].name == testDir2.name, 
                        "Unexpected return order (3) from add_test_dir4")
                self.failUnless(self.dm.get_search_order() == [
                    testDir3.name, testDir4.name, testDir1.name,
                    testDir2.name],
                    "Unexpected search order from add_test_dir4")
                new_order = [testDir1.name, testDir2.name, testDir4.name,
                            testDir3.name]
                self.dm.add_directory_instance(self.discovered_dir, 
                    self.dm.discovered_dir.name, config_id=0, order=sys.maxint)
                d = self.dm.set_search_order(new_order)
                d.addCallback(_test_dm, 'reordered')
            elif state == 'reordered':
                self.failUnless(self.dm.get_search_order() == [testDir1.name,
                        testDir2.name, testDir4.name, testDir3.name,
                        self.dm.discovered_dir.name],
                        "Unexpected search order after reorder")
                d = self.dm.set_search_order([testDir3.name,
                        testDir4.name, testDir1.name, testDir2.name])
                d.addCallback(_test_dm, 'reordered back')
            elif state == 'reordered back':
                del self.dm.instances_by_name[self.dm.discovered_dir.name]
                self.dm.directory_instances.pop()
                self.failUnless(self.dm.get_search_order() == [
                    testDir3.name, testDir4.name, testDir1.name,
                    testDir2.name],
                    "Unexpected search order after resetting order")
                d = self.dm.rename_configured_directory(testDir4.name,
                        'test4_newname')
                d.addCallback(_test_dm, 'renamed_test_dir4')
            elif state == 'renamed_test_dir4':
                expected = sorted([testDir1.name, testDir2.name,
                        testDir3.name, 'test4_newname'])
                self.failUnless(sorted(self.dm.get_search_order()) ==
                        expected, "Unexpected search_order after rename")
                self.failUnless(sorted([cd.name for cd in
                        self.dm.get_configured_directories()]) ==
                        expected, "Unexpected conf dirs after rename")
                d = self.dm.del_configured_directory('test4_newname')
                d.addCallback(_test_dm, 'removed_test_dir4')
            elif state == 'removed_test_dir4':
                self.failUnless(res.name == 'test4_newname',
                        "Unexpected return after removing testdir4")
                self.failUnless(len(self.dm.get_configured_directories()) == 3,
                        "Incorrect directory count after removing testdir4")
                d = self.dm.register_directory_component(dirComp1)
                d.addCallback(_test_dm, 'dirComp1_registered')
            elif state == 'dirComp1_registered':
                instances = self.dm.directory_instances
                self.failUnless(instances[0]._name == testDir3.name, 
                        "Unexpected instance 0 after registering dirComp1")
                self.failUnless(instances[0]._name == testDir3.name, 
                        "Unexpected instance 0 after registering dirComp1")
                d = self.dm.del_configured_directory(testDir3.name)
                d.addCallback(_test_dm, 'removed_test_dir3')
            elif state == 'removed_test_dir3':
                self.failUnless(res.name == testDir3.name,
                        "Unexpected return after removing testdir3")
                self.failUnless(len(self.dm.directory_instances) == 2,
                        "Incorrect directory count after removing testdir3")
                d = self.dm.add_configured_directory(testDir3.name,
                        testDir3.type, testDir3.search_order,
                        testDir3.config_id)
                d.addCallback(_test_dm, 'readded_test_dir3')
            elif state == 'readded_test_dir3':
                self.failUnless(len(self.dm.directory_instances) == 3,
                        "Incorrect directory count after readding testdir3")
                return
            else:
                raise Exception("Invalid state: %s" %state)
            return d
        d = _test_dm()
        d.addErrback(self._err)
        return d

    def testGroups(self, group_type=cDirectory.SWITCH_PRINCIPAL_GROUP):
        dd_nothing = DummyDirectory("dd_nothing")
        dd_groups1 = DummyDirectory("dd_groups1", global_groups=False,
                all_principal_support=READ_WRITE_SUPPORT,
                all_group_support=READ_WRITE_SUPPORT)
        dd_groups2 = DummyDirectory("dd_groups2", global_groups=False,
                all_principal_support=READ_WRITE_SUPPORT,
                all_group_support=READ_WRITE_SUPPORT)
        dd_global= DummyDirectory("dd_global", global_groups=True,
                all_principal_support=READ_WRITE_SUPPORT,
                all_group_support=READ_WRITE_SUPPORT)
        self._set_directories((dd_nothing, dd_groups1, dd_groups2, dd_global))
        def _test_grp(res=None, state='entry'):
            lg.debug("testGroups:--- %s --------------------" %state)
            lg.debug("res: %s" %str(res))
            if state == 'entry':
                d = self.dm.get_group_membership(group_type, 'locname')
                d.addCallback(_test_grp, 'searched_all')
            elif state == 'searched_all':
                expected = ['dd_groups1;dd_groups1', 'dd_groups2;dd_groups2',
                        'dd_global;dd_global']
                self.failUnless(sorted(res) == sorted(expected),
                        "search_all searched wrong directories")
                d = self.dm.get_group_membership(group_type,
                        'dd_groups1;locname')
                d.addCallback(_test_grp, 'searched_dd_groups1')
            elif state == 'searched_dd_groups1':
                expected = ['dd_groups1;dd_groups1', 'dd_global;dd_global']
                self.failUnless(sorted(res) == sorted(expected),
                        "get_group_membership searched wrong directories")
                d = self.dm.get_group_membership(group_type,
                        'dd_groups2;locname', include_global=False)
                d.addCallback(_test_grp, 'searched_dd_groups2_no_global')
            elif state == 'searched_dd_groups2_no_global':
                expected = ['dd_groups2;dd_groups2']
                self.failUnless(sorted(res) == sorted(expected),
                        "get_group_membership searched wrong directories")
                d = self.dm.get_group_membership(group_type)
                d.addCallback(_test_grp, 'searched_with_none')
            elif state == 'searched_with_none':
                expected = ['dd_groups1;dd_groups1', 'dd_groups2;dd_groups2',
                        'dd_global;dd_global']
                self.failUnless(sorted(res) == sorted(expected),
                        "search_with_none searched wrong directories")
                d = self.dm.get_group(group_type, 'a')
                d.addCallback(_test_grp, 'get_first')
            elif state == 'get_first':
                self.failUnless(res.name == 'dd_groups1;dd_groups1',
                        "get_first searched wrong directories")
                d = self.dm.get_group(group_type, 'dd_groups2;a')
                d.addCallback(_test_grp, 'get_in_groups2')
            elif state == 'get_in_groups2':
                self.failUnless(res.name == 'dd_groups2;dd_groups2',
                        "get_in_groups2 searched wrong directories")
                d = self.dm.get_group(group_type, 'a', dir_name='dd_global')
                d.addCallback(_test_grp, 'get_in_global')
            elif state == 'get_in_global':
                self.failUnless(res.name == 'dd_global;dd_global',
                        "get_in_global searched wrong directories")
                d = self.dm.add_group(group_type, GroupInfo('gi'),
                        'dd_groups1')
                d.addCallback(_test_grp, 'add_to_first')
            elif state == 'add_to_first':
                self.failUnless(res.name == 'dd_groups1;gi', "add_to_first "\
                        "returned wrong name")
                d = self.dm.add_group(group_type, GroupInfo('dd_groups2;gi'))
                d = self.dm.add_group(group_type, GroupInfo('dd_groups2;gi',
                        member_names=['dd_groups2;m1','m2'],
                        subgroup_names=['sg1', 'dd_groups2;sg2']))
                d.addCallback(_test_grp, 'add_to_group2')
            elif state == 'add_to_group2':
                self.failUnless(res.name == 'dd_groups2;gi', "add_to_group2 "\
                        "returned wrong name")
                self.failUnless(sorted(res.member_names) == 
                        sorted(['dd_groups2;m1', 'dd_groups2;m2']),
                        "add_to_group2 didn't propery demangle names")
                self.failUnless(sorted(res.subgroup_names) == 
                        sorted(['dd_groups2;sg1', 'dd_groups2;sg2']),
                        "add_to_group2 didn't propery demangle subgroups")
                d = self.dm.add_group(group_type, GroupInfo('dd_global;gi',
                        member_names=['dd_groups2;m1','m2'],
                        subgroup_names=['sg1', 'dd_group1;sg2']))
                d.addCallback(_test_grp, 'add_to_global')
            elif state == 'add_to_global':
                self.failUnless(res.name == 'dd_global;gi', "add_to_global "\
                        "returned wrong name")
                self.failUnless(sorted(res.member_names) == 
                        sorted(['dd_groups2;m1', 'dd_global;m2']),
                        "add_to_global didn't propery mangle names")
                self.failUnless(sorted(res.subgroup_names) == 
                        sorted(['dd_global;sg1', 'dd_group1;sg2']),
                        "add_to_global didn't propery mangle subgroups")
                d = self.dm.add_group(group_type, GroupInfo('gi'),
                        dir_name='dd_global')
                d.addCallback(_test_grp, 'add_to_global_sep')
            elif state == 'add_to_global_sep':
                self.failUnless(res.name == 'dd_global;gi',
                        "add_to_global_sep returned wrong name")
                d = self.dm.del_group(group_type, 'a')
                d.addCallback(_test_grp, 'del_first')
            elif state == 'del_first':
                self.failUnless(res.name == 'dd_groups1;dd_groups1',
                        "del_first called wrong directory")
                d = self.dm.del_group(group_type, 'dd_groups2;a')
                d.addCallback(_test_grp, 'del_in_groups2')
            elif state == 'del_in_groups2':
                self.failUnless(res.name == 'dd_groups2;dd_groups2',
                        "del_in_groups2 called wrong directory")
                d = self.dm.del_group(group_type, 'a', dir_name='dd_global')
                d.addCallback(_test_grp, 'del_in_global')
            elif state == 'del_in_global':
                self.failUnless(res.name == 'dd_global;dd_global',
                        "del_in_global called wrong directory")
                d = self.dm.add_group_members(group_type, 'dd_groups1;grp',
                        ['dd_groups1;m1','m2'],
                        ['sg1','dd_groups1;sg2'])
                d.addCallback(_test_grp, 'add_members_to_first')
            elif state == 'add_members_to_first':
                self.failUnless(sorted(res[0]) == ['dd_groups1;m1',
                        'dd_groups1;m2'],
                        "add_members_to_first didn't demangle group members")
                self.failUnless(sorted(res[1]) == ['dd_groups1;sg1',
                        'dd_groups1;sg2'],
                        "add_members_to_first didn't demangle group subgroups")
                d = self.dm.add_group_members(group_type, 'dd_global;grp',
                        ['dd_groups1;m1','dd_global;m2'],
                        ['sg1','dd_groups1;sg2'])
                d.addCallback(_test_grp, 'add_members_to_global')
            elif state == 'add_members_to_global':
                self.failUnless(sorted(res[0]) == 
                        sorted(['dd_groups1;m1','dd_global;m2']),
                        "add_members_to_global didn't mangle members")
                self.failUnless(sorted(res[1]) ==
                        sorted(['dd_global;sg1','dd_groups1;sg2']),
                        "add_members_to_global didn't demangle subgroups")
                d = self.dm.del_group_members(group_type, 'dd_groups1;grp',
                        ['dd_groups1;m1','m2'],
                        ['sg1','dd_groups1;sg2'])
                d.addCallback(_test_grp, 'del_members_to_first')
            elif state == 'del_members_to_first':
                self.failUnless(sorted(res[0]) == ['dd_groups1;m1',
                        'dd_groups1;m2'],
                        "del_members_to_first didn't demangle group members")
                self.failUnless(sorted(res[1]) == ['dd_groups1;sg1',
                        'dd_groups1;sg2'],
                        "del_members_to_first didn't demangle group subgroups")
                d = self.dm.del_group_members(group_type, 'dd_global;grp',
                        ['dd_groups1;m1','dd_global;m2'],
                        ['sg1','dd_groups1;sg2'])
                d.addCallback(_test_grp, 'del_members_to_global')
            elif state == 'del_members_to_global':
                self.failUnless(sorted(res[0]) == 
                        sorted(['dd_groups1;m1','dd_global;m2']),
                        "del_members_to_global didn't mangle members")
                self.failUnless(sorted(res[1]) ==
                        sorted(['dd_global;sg1','dd_groups1;sg2']),
                        "del_members_to_global didn't demangle subgroups")
                d = self.dm.get_group_parents(group_type, 'dd_global;grp')
                d.addCallback(_test_grp, 'get_parents_of_global')
            elif state == 'get_parents_of_global':
                self.failUnless(res == ['dd_global;dd_global'],
                        "get_parents_of_global called wrong directory")
                d = self.dm.get_group_parents(group_type, 'dd_groups1;grp')
                d.addCallback(_test_grp, 'get_parents_of_local')
            elif state == 'get_parents_of_local':
                expected = ['dd_global;dd_global', 'dd_groups1;dd_groups1']
                self.failUnless(sorted(res) == sorted(expected),
                        "get_parents_of_local called wrong directory")
                return
            else:
                raise Exception("Invalid state: %s" %state)
            return d
        d = _test_grp()
        d.addErrback(self._err)
        return d

    def testAuthentication(self):
        dd_nothing = DummyDirectory("dd_nothing")
        dd_invalid1 = DummyDirectory("dd_invalid1",
                supported_auth_types=(Directory.AUTH_SIMPLE,),
                enabled_auth_types=(Directory.AUTH_SIMPLE,),
                simple_auth_result=AuthResult.INVALID_CREDENTIALS)
        dd_success1 = DummyDirectory("dd_success1",
                supported_auth_types=(Directory.AUTH_SIMPLE,),
                enabled_auth_types=(Directory.AUTH_SIMPLE,),
                simple_auth_result=AuthResult.SUCCESS)
        dd_success2 = DummyDirectory("dd_success2",
                supported_auth_types=(Directory.AUTH_SIMPLE,),
                enabled_auth_types=(Directory.AUTH_SIMPLE,),
                simple_auth_result=AuthResult.SUCCESS)
        dd_exception = DummyDirectory("dd_exception",
                supported_auth_types=(Directory.AUTH_SIMPLE,),
                enabled_auth_types=(Directory.AUTH_SIMPLE,),
                simple_auth_result=AuthResult.SUCCESS)
        setattr(dd_exception, 'simple_auth', lambda name, pw:
                defer.fail(Failure("Simulated failure")))
        def _test_auth(res=None, state='entry'):
            lg.debug("testAuthentication:--- %s --------------------" %state)
            lg.debug("res: %s" %str(res))
            if state == 'entry':
                d = self.dm.simple_auth('name', 'pass')
                d.addCallback(_test_auth, 'succeeded_no_dirs')
                d.addErrback(_test_auth, 'failed_no_dirs')
            elif state == 'succeeded_no_dirs':
                self.fail("Authentication didn't fail with no directories")
            elif state == 'failed_no_dirs':
                self._set_directories((dd_nothing,))
                d = self.dm.simple_auth('name', 'pass')
                d.addCallback(_test_auth, 'succeeded_nothing_supports')
                d.addErrback(_test_auth, 'failed_nothing_supports')
            elif state == 'succeeded_nothing_supports':
                self.fail("Authentication didn't fail with no directories "\
                          "supporting auth")
            elif state == 'failed_nothing_supports':
                self._set_directories((dd_nothing, dd_invalid1, dd_success1,
                        dd_success2))
                d = self.dm.simple_auth('name', 'pass')
                d.addCallback(_test_auth, 'tried_auth1')
            elif state == 'tried_auth1':
                self.failUnless(res.status == AuthResult.SUCCESS,
                        "Invalid status returned from tried_auth1")
                self.failUnless(res.username == 'dd_success1;name',
                        "Invalid username returned from tried_auth1")
                self._set_directories((dd_nothing, dd_invalid1,
                        dd_exception, dd_success1, dd_success2))
                d = self.dm.simple_auth('name', 'pass')
                d.addCallback(_test_auth, 'succeeded_after_failure')
            elif state == 'succeeded_after_failure':
                self.failUnless(res.status == AuthResult.SUCCESS,
                        "Invalid status returned from succeeded_after_failure")
                self.failUnless(res.username == 'dd_success1;name',
                        "Invalid username returned from "\
                        "succeeded_after_failure")
                d = self.dm.simple_auth('name', 'pass', 'dd_success2')
                d.addCallback(_test_auth, 'specific_success')
            elif state == 'specific_success':
                self.failUnless(res.status == AuthResult.SUCCESS,
                        "Invalid status returned from specific_success")
                d = self.dm.simple_auth('name', 'pass', 'dd_invalid1')
                d.addCallback(_test_auth, 'specific_failure')
            elif state == 'specific_failure':
                self.failUnless(res.status == AuthResult.INVALID_CREDENTIALS,
                        "Invalid status returned from specific_failure")
                self._set_directories((dd_nothing, dd_exception, dd_invalid1))
                d = self.dm.simple_auth('name', 'pass')
                d.addCallback(_test_auth, 'failed_after_failure')
            elif state == 'failed_after_failure':
                self.failUnless(res.status == AuthResult.INVALID_CREDENTIALS,
                        "Invalid status returned from failed_after_failure")
                self.failUnless(res.username == 'name',
                        "Invalid username returned from failed_after_failure")
                self._set_directories((dd_nothing, dd_exception))
                d = self.dm.simple_auth('name', 'pass')
                d.addCallback(_test_auth, 'nothing_after_failure_cb')
                d.addErrback(_test_auth, 'nothing_after_failure_eb')
            elif state == 'nothing_after_failure_cb':
                self.fail("Authentication didn't fail with only directories "\
                          "returning exceptions")
            elif state == 'nothing_after_failure_eb':
                return
            else:
                raise Exception("Invalid state: %s" %state)
            return d
        d = _test_auth()
        d.addErrback(self._err)
        return d

    def testPrincipals(self):
        # TODO
        pass

def suite(ctxt):
    suite = pyunit.TestSuite()
    suite.addTest(DirectorymanagerTestCase("testDirectoryManagement", ctxt))
    suite.addTest(DirectorymanagerTestCase("testAuthentication", ctxt))
    suite.addTest(DirectorymanagerTestCase("testPrincipals", ctxt))
    suite.addTest(DirectorymanagerTestCase("testGroups", ctxt))

    return suite
