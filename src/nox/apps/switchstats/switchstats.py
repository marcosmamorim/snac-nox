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
from nox.lib.core import *
import nox.lib.openflow as openflow
from nox.lib.packet.packet_utils  import mac_to_str
from itertools import chain

from nox.lib.netinet.netinet import datapathid
from nox.apps.switchstats.pycswitchstats import pycswitchstats
from nox.apps.bindings_storage.pybindings_storage import pybindings_storage,Name
from nox.apps.directory.pynetinfo_mod_event import NetInfo_mod_event 
from nox.apps.directory.directorymanager import directorymanager
from nox.apps.directory.directorymanager import get_default_loc_name
from twisted.python import log

from nox.lib.directory import Directory
from nox.lib.directory import LocationInfo 

# Default values for the periodicity of polling for each class of
# statistic

DEFAULT_POLL_TABLE_PERIOD     = 30
DEFAULT_POLL_PORT_PERIOD      = 30
DEFAULT_POLL_AGGREGATE_PERIOD = 30

lg = logging.getLogger('switchstats')

class switchstats(Component):
    """Track switch statistics during runtime"""

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.dp_stats = {} 

        self.dp_poll_period = {}
        self.dp_table_stats = {}
        self.dp_desc_stats = {}
        self.dp_port_stats  = {}


    def port_timer(self, dp):
        if dp in self.dp_stats:
            self.ctxt.send_port_stats_request(dp)
            self.post_callback(self.dp_poll_period[dp]['port'] + 1, lambda :  self.port_timer(dp))

    def table_timer(self, dp):
        if dp in self.dp_stats:
            self.ctxt.send_table_stats_request(dp)
            self.post_callback(self.dp_poll_period[dp]['table'], lambda : self.table_timer(dp))
       
    def dp_join(self, dp, stats):

        dpid_obj = datapathid.from_host(dp)
        stats['dpid']     = dp 
        self.dp_stats[dp] = stats
        
        # convert all port hw_addrs to ASCII
        # and register all port names with bindings storage
   
        port_list = self.dp_stats[dp]['ports']
        for i in range(0,len(port_list)):
          new_mac = mac_to_str(port_list[i]['hw_addr']).replace(':','-')
          port_list[i]['hw_addr'] = new_mac 

        # polling intervals for switch statistics
        self.dp_poll_period[dp] = {} 
        self.dp_poll_period[dp]['table'] = DEFAULT_POLL_TABLE_PERIOD
        self.dp_poll_period[dp]['port']  = DEFAULT_POLL_PORT_PERIOD
        self.dp_poll_period[dp]['aggr']  = DEFAULT_POLL_AGGREGATE_PERIOD

        # Switch descriptions do not change while connected, so just send once
        self.ctxt.send_desc_stats_request(dp)
           
        # stagger timers by one second
        self.post_callback(self.dp_poll_period[dp]['table'], 
                              lambda : self.table_timer(dp))
        self.post_callback(self.dp_poll_period[dp]['port'] + 1, 
                              lambda : self.port_timer(dp))

        return CONTINUE
                
                    
    def dp_leave(self, dp): 
        dpid_obj = datapathid.from_host(dp)

        if self.dp_stats.has_key(dp):
            del self.dp_stats[dp]  
        else:    
            log.err('Unknown datapath leave', system='switchstats')

        if self.dp_poll_period.has_key(dp):
            del self.dp_poll_period[dp]  
        if self.dp_table_stats.has_key(dp):
            del self.dp_table_stats[dp]  
        if self.dp_desc_stats.has_key(dp):
            del self.dp_desc_stats[dp]  
        if self.dp_port_stats.has_key(dp):
            del self.dp_port_stats[dp]  

        return CONTINUE


    def map_name_to_portno(self, dpid, name):
        for port in self.dp_stats[dpid]['ports']:
            if port['name'] == name:
                return port['port_no']
        return None        
            
    def table_stats_in_handler(self, dpid, tables):
        if dpid not in self.dp_table_stats:
            self.dp_table_stats[dpid] = []

        # The list 'tables' has multiple table, each dentified
        # by a unique non-null name. Need to cross-reference and
        # overwrite only the appropriate table info.
        self.dp_table_stats[dpid] = dict(chain(
                    ((m['name'],m) for m in self.dp_table_stats[dpid]),
                    ((m['name'],m) for m in tables))).values()

    def desc_stats_in_handler(self, dpid, desc):
        self.dp_desc_stats[dpid] = desc

    def port_stats_in_handler(self, dpid, ports):
        if dpid not in self.dp_port_stats:
            self.dp_port_stats[dpid] = {}

        for port in ports:
            if port['port_no'] in self.dp_port_stats[dpid]:
                port['delta_bytes'] = port['tx_bytes'] - \
                            self.dp_port_stats[dpid][port['port_no']]['tx_bytes']
            else:    
                port['delta_bytes'] = 0 
            self.dp_port_stats[dpid][port['port_no']] = port

    def port_status_handler(self, dpid, reason, port):
        intdp = int(dpid)
        if intdp not in self.dp_stats:
            log.err('port status from unknown datapath', system='switchstats')
            return
        # copy over existing port status
        for i in range(0, len(self.dp_stats[intdp]['ports'])):
            oldport  = self.dp_stats[intdp]['ports'][i]
            if oldport['name'] == port['name']:
                port['hw_addr'] = mac_to_str(port['hw_addr']).replace(':','-')
                self.dp_stats[intdp]['ports'][i] = port

    def get_switch_conn_p_s_heavy_hitters(self):
        hitters = []
        for dp in self.dp_stats:
            hitters.append((dp, self.cswitchstats.get_switch_conn_p_s(dp)))
        return hitters

    def get_switch_port_error_heavy_hitters(self): 
        error_list = []
        for dpid in self.dp_port_stats:
            ports = self.dp_port_stats[dpid].values()
            for port in ports:
                error_list.append((dpid, port['port_no'], port['rx_errors'] + port['tx_errors']))
        return error_list    

    def get_switch_port_bandwidth_hitters(self): 
        error_list = []
        for dpid in self.dp_port_stats:
            ports = self.dp_port_stats[dpid].values()
            for port in ports:
                error_list.append((dpid, port['port_no'], 
                  (port['delta_bytes']) / DEFAULT_POLL_PORT_PERIOD))
        return error_list    
            
    def get_global_conn_p_s(self):
        return self.cswitchstats.get_global_conn_p_s()

    def get_switch_conn_p_s(self, dpid):
        return self.cswitchstats.get_switch_conn_p_s(datapathid.from_host(dpid))

    def install(self):
        self.cswitchstats     = self.resolve(pycswitchstats)
        self.bindings_storage = self.resolve(pybindings_storage)

        self.dm = self.resolve(directorymanager)
        
        self.register_for_datapath_join (self.dp_join)
        self.register_for_datapath_leave(self.dp_leave)

        self.register_for_table_stats_in(self.table_stats_in_handler)

        self.register_for_desc_stats_in(self.desc_stats_in_handler)

        self.register_for_port_stats_in(self.port_stats_in_handler)
        self.register_for_port_status(self.port_status_handler)

    def getInterface(self):
        return str(switchstats)


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return switchstats(ctxt)

    return Factory()
