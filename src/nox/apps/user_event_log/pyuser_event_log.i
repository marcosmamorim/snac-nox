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
%module "nox.apps.user_event_log"


%{
#include "user_event_log_proxy.hh"
#include "pyrt/pycontext.hh"
#include "bindings_storage/bindings_storage.hh" 
using namespace vigil;
using namespace vigil::applications;
%}

%import "netinet/netinet.i"

%include "common-defs.i"
%include "std_string.i"
%include "user_event_log_proxy.hh"
%include "../bindings_storage/bs_datastructures.i" 

struct LogEntry { 

    enum Level { INVALID = 0, CRITICAL, ALERT, INFO }; 
    enum Direction { SRC = 0, DST } ; 

    LogEntry(const string &_app, Level _level, const string &_msg);  
    void setName(const string &name, Name::Type name_type,Direction dir); 
    void setNameByLocation(const datapathid &dpid, uint16_t port, Direction dir); 
    void addLocationKey(const datapathid &dpid, uint16_t port,Direction dir);  
    void addMacKey(const ethernetaddr &dladdr, Direction dir); 
    void addIPKey(uint32_t nwaddr, Direction dir);  
}; 


%pythoncode
%{
  from nox.lib.core import Component
  from nox.apps.bindings_storage.pybindings_storage import Name

  # TODO: remove these, and use swigged values instead
  # from LogEntry class
  class LogLevel: 
    INVALID = 0    
    CRITICAL = 1
    ALERT = 2 
    INFO = 3 

  # this dictionary defines all valid format strings, mapping
  # them to a tuple indicating the associated name_type and direction 
  format_map = { 
            "su" : (Name.USER,LogEntry.SRC),  
            "du" : (Name.USER,LogEntry.DST),  
            "sh" : (Name.HOST,LogEntry.SRC),  
            "dh" : (Name.HOST,LogEntry.DST),  
            "sl" : (Name.LOCATION,LogEntry.SRC),  
            "dl" : (Name.LOCATION,LogEntry.DST),  
            "ss" : (Name.SWITCH,LogEntry.SRC),  
            "ds" : (Name.SWITCH,LogEntry.DST),  
            "sug" : (Name.USER_GROUP,LogEntry.SRC),   
            "dug" : (Name.USER_GROUP,LogEntry.DST),  
            "shg" : (Name.HOST_GROUP,LogEntry.SRC),   
            "dhg" : (Name.HOST_GROUP,LogEntry.DST),  
            "slg" : (Name.LOCATION_GROUP,LogEntry.SRC),   
            "dlg" : (Name.LOCATION_GROUP,LogEntry.DST),  
            "ssg" : (Name.SWITCH_GROUP,LogEntry.SRC),   
            "dsg" : (Name.SWITCH_GROUP,LogEntry.DST) 
  } 

  class pyuser_event_log(Component):
      """
      Python interface for the User_Event_Log 
      """  
      def __init__(self, ctxt):
          self.proxy = user_event_log_proxy(ctxt)

      def configure(self, configuration):
          self.proxy.configure(configuration)

      def getInterface(self):
          return str(pyuser_event_log)

      def log_simple(self, app_name, level,msg):  
          self.proxy.log_simple(app_name,int(level),msg)
      
      def log_entry(self, entry):  
          self.proxy.log(entry)
      
      # convenience function for logging in one line
      # when using keys.  
      # With respect to add*Key(), this function expects one or
      # two dict arguments indicating a source key and a
      # destination key.  Variable names are:
      # src_location, dst_location, src_mac, dst_mac, src_ip, dst_ip:
      # *_location must be a tuple containing a datapathid and a port
      # *_mac must be an etheraddr
      # *_ip must be an int 
      # if you specify more than one src_* paramter, or more than
      # one dst_* parameter, the result of the function is undefined.
      # With respect to setName() functionality, this can take any of
      # the following parameters (su,du,sh,dh,sl,dl).  Each should be
      # a list of strings.  For example, to associated two source users
      # with this log message, have su = ("bob","sarah")
      # This method also special-cases the scenario when there is only
      # one name, allowing you to pass in just the string instead of
      # a tuple with one item
      # Note: Group names can only be set explicitly.  No bindings 
      # storage query returns a group name

      def log(self, app_name, level, msg, **dict):  
         
          e = LogEntry(app_name,level,msg)
          if "src_location" in dict and len(dict["src_location"]) == 2: 
            t = dict["src_location"] 
            e.addLocationKey(t[0],t[1],LogEntry.SRC)
          if "dst_location" in dict and len(dict["dst_location"]) == 2: 
            t = dict["dst_location"] 
            e.addLocationKey(t[0],t[1],LogEntry.DST)
          if "src_mac" in dict : 
            e.addMacKey(dict["src_mac"],LogEntry.SRC)
          if "dst_mac" in dict : 
            e.addMacKey(dict["dst_mac"],LogEntry.DST)
          if "src_ip" in dict : 
            e.addIPKey(dict["src_ip"],LogEntry.SRC)
          if "dst_ip" in dict : 
            e.addIPKey(dict["dst_ip"],LogEntry.DST)
        
          # for each key-value pair in the keyword args dict,
          # test if it is a format string and, and if so
          # add the corresponding names to the log entry
          for fmt,values in dict.iteritems(): 
            if fmt in format_map :
              name_type,dir = format_map[fmt]
              if type(values) == type(""): 
                values = (values,) 
              for p in values: 
                e.setName(p,name_type,dir)
    
          if "set_src_loc" in dict:
            t = dict["set_src_loc"] # expects (dpid,port) tuple
            e.setNameByLocation(t[0],t[1],LogEntry.SRC)
          
          if "set_dst_loc" in dict:
            t = dict["set_dst_loc"] # expects (dpid,port) tuple
            e.setNameByLocation(t[0],t[1],LogEntry.DST) 

          self.proxy.log(e)

      def get_log_entry(self,logid, cb):
          self.proxy.get_log_entry(logid,cb) 

      def get_max_logid(self):
          return self.proxy.get_max_logid()
      
      def get_min_logid(self):
          return self.proxy.get_min_logid()
    
      def set_max_num_entries(self,num): 
          self.proxy.set_max_num_entries(num)

      def get_logids_for_name(self,name,name_type,cb): 
          self.proxy.get_logids_for_name(name,name_type,cb) 

      def clear(self,cb):
          self.proxy.clear(cb)

      def remove(self,max_logid,cb):
          self.proxy.remove(max_logid,cb)

  def getFactory():
        class Factory():
            def instance(self, context):
                return pyuser_event_log(context)

        return Factory()
%}
