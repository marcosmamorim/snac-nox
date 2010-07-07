# -*- coding: utf8 -*-
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

from nox.lib.core import *
from twisted.python.failure import Failure
from nox.apps.coreui.authui import UISection, UIResource, Capabilities
from nox.apps.coreui.coreui import *
from nox.apps.coreui.webservice import *
from nox.apps.user_event_log.pyuser_event_log import pyuser_event_log, \
    LogLevel, format_map, LogEntry
from nox.apps.bindings_storage.pybindings_storage import pybindings_storage,\
    Name
from nox.apps.coreui.webservice import json_parse_message_body
from nox.lib.netinet.netinet import *
from nox.apps.coreui.web_arg_utils import *
import simplejson
import types
import copy
import re

# matches each instance of a format string, to be used with
# fmt_pattern.findall(log_message) to get a list of all format
# strings used in a log message
fmt_pattern = re.compile('{[a-z]*}') 

lg = logging.getLogger("networkeventsws")

# makes sure a path component is a currently valid logid value
class WSPathValidLogID(WSPathComponent): 
  def __init__(self, uel):
    WSPathComponent.__init__(self)
    self.uel = uel 

  def __str__(self):
    return "<logid>"

  def extract(self, pc, data): 
    if pc == None:
      return WSPathExtractResult(error="End of requested URI")
    try: 
      max_logid = self.uel.get_max_logid()
      logid = long(pc) 
      if logid > 0 and logid <= max_logid: 
        return WSPathExtractResult(value=pc)
    except:
      pass
    e = "Invalid LogID value '" + pc + "'. Must be number 0 < n <= " \
                                        + str(max_logid)
    return WSPathExtractResult(error=e)

def string_for_name_type(type, is_plural): 
  s = ""
  if type == Name.USER: s = "user"
  elif type == Name.HOST: s = "host"
  elif type == Name.LOCATION: s = "location"
  elif type == Name.SWITCH: s = "switch"
  elif type == Name.USER_GROUP: s = "user group"
  elif type == Name.HOST_GROUP: s = "host group"
  elif type == Name.LOCATION_GROUP: s = "location group"
  elif type == Name.SWITCH_GROUP: s = "switch group"

  if is_plural: 
    if type == Name.SWITCH: 
      s += "es"
    else:
      s += "s" 
  
  return s


def get_name_str(type, names): 
  for_use = [] 
  for n in names:
    if(n[1] == type):
        for_use.append(n[0])

    # this is a hack to let apps log a switch name 
    # even if they only know the dpid
    if(n[1] == Name.LOCATION and type == Name.SWITCH): 
        arr = n[0].split("#") 
        if len(arr) == 3: 
          for_use.append(arr[1])

  if len(for_use) == 0:
    for_use.append("<unknown>") 

  s = string_for_name_type(type, len(for_use) > 1)
  
  n = ""
  for i in range(len(for_use)): 
      n += for_use[i]
      if i < len(for_use) - 1:
        n += ","

  return " {" + s + "|" + n + "}"

     
def fill_in_msg(msg, src_names, dst_names):
  fmts_used = fmt_pattern.findall(msg)
  fmts_used = map(lambda s: s[1:-1],fmts_used) # remove braces

  for fmt in fmts_used: 
    if fmt not in format_map: 
      lg.error("invalid format string '%s' in message '%s'" % (fmt,msg))
      continue

    name_type,dir = format_map[fmt] 
    if dir == LogEntry.SRC:
      name_list = src_names
    else:
      name_list = dst_names
    msg = msg.replace("{"+fmt+"}", get_name_str(name_type, name_list)) 
  return msg

def make_entry(logid, ts, app, level, msg, src_names, dst_names):
  return { "logid" : logid, 
            "timestamp" : ts, 
            "app" : app, 
            "level" : level, 
            "msg" : fill_in_msg(msg,src_names,dst_names) }  

def err(failure, request, fn_name, msg):
  lg.error('%s: %s' % (fn_name, str(failure)))
  return internalError(request, msg)

# get all log entries associated with a 'name' (ie a host or user)
# uses get_logids_for_name() and then uses process_list_op
class process_name_op: 

  def __init__(self,name,name_type,uel,b_store,req,filter): 
    self.uel = uel
    self.req = req
    self.b_store = b_store
    self.filter = filter
    self.uel.get_logids_for_name(name,name_type,self.callback)

  def callback(self,logids):
    try:
      p = process_list_op(logids,self.uel,self.b_store, 
                          self.req,self.filter)
    except Exception, e:
      err(Failure(), self.req, "process_name_op",
          "Could not retrieve log messages.")

# class to get all log entries and writes them
# in JSON to a request object.
# the dict 'filter' describes how these results 
# can be filtered before being returned (see below)
class process_list_op: 

  def __init__(self,logids,uel,b_store,req,filter):
    self.request = req
    self.got = 0
    self.items = []
    self.all_spawned = False
    self.b_store = b_store
    self.name_to_dpid = {} 
    self.name_to_port = {} 
    self.unique_dpids = {} 
    self.filter = filter 
    
    max = uel.get_max_logid()
    if max == 0: 
      self.done() 
      return 
      
    # if nothing was provided, return ALL entries
    if logids is None: 
        min = uel.get_min_logid()
        logids = range(min,max+1)
   
    self.needs = 0
    for id in logids:
      if id > 0 and id <= max and id > filter["after"]:
        self.needs += 1
        uel.get_log_entry(id,self.log_callback) 
    # needed for common case when we call self.done() from self.log_callback()
    self.all_spawned = True
      
    if self.needs == self.got : 
      self.done() # nothing actually spawned, or everything already done
     
  def done(self): 
    try :
      ret_list = sort_and_filter_results(self.filter,self.items)

      self.request.write(simplejson.dumps({ 
                  "identifier" : "logid",
                  "items" : ret_list
                  } ))
    except Exception, e:
      err(Failure(), self.request, "process_list_op",
          "Could not retrieve message IDs.")
      return

    self.request.finish()

  def log_callback(self, logid, ts, app, level, msg, src_names, dst_names):
    try:
      self.got += 1
      if level != LogLevel.INVALID and level <= self.filter["max_level"]: 
        self.items.append(make_entry(logid,ts,app,level,msg,src_names,dst_names))
      if self.all_spawned and self.needs == self.got:
        self.done() 
    except Exception, e:
      err(Failure(), self.request, "process_list_op",
          "Could not look up message IDs.")

class networkeventsws(Component): 
  """ Web service for network events (aka user_event_log)"""

  def __init__(self,ctx):
    Component.__init__(self,ctx)
    
  def getInterface(self):
    return str(networkeventsws)

  
  def handle_add(self,request,data):
    try:
      content = json_parse_message_body(request)
      if content == None:
        content = {} 
      app = "via-netevent-webservice"
      if "app" in content: 
        app = str(content["app"])
      msg = "default webservice message"
      if "msg" in content: 
        msg = str(content["msg"])
      self.uel.log(app,LogEntry.INFO, msg) 
    except Exception, e:
      err(Failure(), request, "handle_add",
          "Could not add log message")
    request.write(simplejson.dumps("success"))
    request.finish()
    return NOT_DONE_YET

  def handle_remove(self,request,data):
    try:
      msg = ""
      def cb():
        try:
          request.write(simplejson.dumps("success:" + msg))
          request.finish()
        except Exception, e:
          err(Failure(), request, "handle_remove",
              "Could not remove log messages.")
    
      if(request.args.has_key("max_logid")): 
        max_logid = int(request.args["max_logid"][0])
        msg = "cleared entries with logid <= " + str(max_logid)
        self.uel.remove(max_logid,cb)
      else : 
        msg = "cleared all entries" 
        self.uel.clear(cb)
    except Exception, e:
      err(Failure(), request, "handle_remove",
          "Could not remove log messages.")
    return NOT_DONE_YET

  def handle_get_entry(self, request, data):
    try:
      logid = int(data["<logid>"]) 
      g = process_list_op((logid,), self.uel, self.b_store, request) 
    except Exception, e:
      err(Failure(), request, "handle_get_entry",
          "Could not retrieve log message.")
    return NOT_DONE_YET

  def handle_get_all(self,request,data):
    # FILTERS
    #'after' let's you filter all results
    # less than or equal to the specified logid.  
    try : 
      filter_arr = get_default_filter_arr("logid")
      filter_arr.extend([("after",0), ("max_level",LogLevel.INFO)])
      filter = parse_mandatory_args(request,filter_arr)
      # handles all requests that are filtering based on a particular 
      # principal name (e.g., host=sepl_directory;bob ) 
      type_map = { "host" : Name.HOST, "user" : Name.USER, 
                 "location" : Name.LOCATION, "switch" : Name.SWITCH } 
      for name, type in type_map.iteritems(): 
        if(request.args.has_key(name)):
          p = process_name_op(request.args[name][0],type,
                  self.uel,self.b_store,request,filter)
          return NOT_DONE_YET

      # otherwise, we just query directory for logids
      # we query either for a single logid or for all
      logid_list = None  # default to query for all 
      if(request.args.has_key("logid")): 
        logid = int(request.args["logid"][0])
        max = self.uel.get_max_logid()
        if logid >= 1 and logid <= max: 
          logid_list = (logid)   
        else: 
          logid_list = () 
    
      p = process_list_op(logid_list,self.uel,self.b_store,request,filter)
    except Exception, e: 
      err(Failure(), request, "handle_get_all",
          "Could not retrieve log messages.")

    return NOT_DONE_YET

  def install(self):
    self.uel = self.resolve(pyuser_event_log) 
    self.b_store = self.resolve(pybindings_storage) 

    ws = self.resolve(webservice)
    v1 = ws.get_version("1") 
    
    # returns a JSON object: 
    #
    # { 'identifier' : 'logid' , items : [ .... ] } 
    #
    # Query Params:
    # * supports standard 'start' 'count' for pagination
    # * supports 'sort_descending' and 
    get_all_path = ( WSPathStaticString("networkevents"),)  
    v1.register_request(self.handle_get_all, "GET", get_all_path, 
                    """Get a set of messages from the network events log""")

# NOT REGISTERED BECAUSE DOESN'T CURRENTLY SET UP FILTER WHICH process_list_op
# ASSUMES EXISTS
#    get_entry_path = ( WSPathStaticString("networkevent"),
#                  WSPathValidLogID(self.uel))  
#    v1.register_request(self.handle_get_entry, "GET", get_entry_path, 
#                    """Get a single message from the network events log""")
    
    remove_path = (  WSPathStaticString("networkevents"), 
                      WSPathStaticString("remove"))  
    v1.register_request(self.handle_remove, "PUT", remove_path, 
                    """Permanently remove all (or just some) network event log entries""")

    add_path = (  WSPathStaticString("networkevents"), 
                      WSPathStaticString("add"))  
    v1.register_request(self.handle_add, "PUT", add_path, 
                    """Add a simple network event log message""")



def getFactory():
  class Factory:
    def instance(self,ctx):
      return networkeventsws(ctx)
  return Factory() 


