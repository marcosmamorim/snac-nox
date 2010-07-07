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
#ifndef BINDINGS_STORAGE_HH
#define BINDINGS_STORAGE_HH 1

#include "component.hh"
#include "netinet++/ethernetaddr.hh"
#include "storage/storage.hh"
#include "storage/storage_util.hh"
#include "event.hh" 
#include "directory/directory.hh" 
#include <string>
#include <list> 
#include "serial_op_queue.hh" 

#ifdef TWISTED_ENABLED

#include <Python.h> 
#include "pyrt/pyglue.hh"

#endif

namespace vigil {
namespace applications {

using namespace std;
using namespace storage;
using namespace container;
      
// the NetEntity data structure represents a single "network entity",
// which is a (dpid,port,dladdr,nwaddr) tuple.  
struct NetEntity { 
  NetEntity() : port(0),dladdr((uint64_t)0),nwaddr(0) {
    dpid = datapathid::from_host(0); 
  } 
  NetEntity(const datapathid &d, uint16_t p,const ethernetaddr &m, uint32_t i): 
    dpid(d), port(p), dladdr(m), nwaddr(i) {} 
  NetEntity(const storage::Row &row) {
        int64_t dp_i = Storage_Util::get_col_as_type<int64_t>(row,"dpid"); 
        dpid = datapathid::from_host((uint64_t)dp_i); 
        port = (uint16_t)Storage_Util::get_col_as_type<int64_t>(row,"port"); 
        dladdr = ethernetaddr((uint64_t)
                    Storage_Util::get_col_as_type<int64_t>(row,"dladdr"));
        nwaddr = (uint32_t)Storage_Util::get_col_as_type<int64_t>(row,"nwaddr");  }
  datapathid dpid;
  uint16_t port;
  ethernetaddr dladdr; 
  uint32_t nwaddr;
  void fillQuery(storage::Query &query) const { 
    query["dpid"] = (int64_t)dpid.as_host();
    query["port"] = (int64_t) port;
    query["dladdr"] = (int64_t) dladdr.hb_long();
    query["nwaddr"] = (int64_t) nwaddr;
  }
  bool operator==(const NetEntity &other) const {
    return (dpid == other.dpid && port == other.port && 
            dladdr == other.dladdr && nwaddr == other.nwaddr); 
  } 
}; 


struct Link { 
  Link(const datapathid &d1, uint16_t p1, const datapathid &d2, uint16_t p2):
      dpid1(d1), dpid2(d2), port1(p1), port2(p2) {} 
  datapathid dpid1,dpid2; 
  uint16_t port1,port2; 
  bool operator==(const Link &o) const {
    return (dpid1 == o.dpid1 && port1 == o.port1 && 
            dpid2 == o.dpid2 && port2 == o.port2); 
  }
  bool matches(const datapathid & _dpid){
      return dpid1 == _dpid || dpid2 == _dpid; 
  } 
  bool matches(const datapathid & _dpid, uint16_t _port){
      return (dpid1 == _dpid && port1 == _port) ||
             (dpid2 == _dpid && port2 == _port); 
  }
  void fillQuery(storage::Query &q) {
    q["dpid1"] = (int64_t)dpid1.as_host();
    q["port1"] = (int64_t)port1;
    q["dpid2"] = (int64_t)dpid2.as_host();
    q["port2"] = (int64_t)port2;
  } 
};

struct Location {
  enum Port { NO_PORT = -1 };
  Location(const datapathid &d, uint16_t p) : dpid(d), port(p) {} 
  datapathid dpid;
  uint16_t port; 
  bool operator==(const Location &o) const {
    return (dpid == o.dpid && port == o.port);  
  }
  // just for sorting to eliminate duplicate
  bool operator<(const Location &o) const {
    uint64_t did = dpid.as_host(); 
    uint64_t oid = o.dpid.as_host(); 
    return (did == oid) ? (port < o.port) : (did < oid) ;  
  }
}; 

struct Name {
  enum Type { NONE = 0, LOCATION, HOST, USER, SWITCH, PORT, LOC_TUPLE, 
              LOCATION_GROUP, HOST_GROUP, USER_GROUP, SWITCH_GROUP }; 
  Name(const string &n, Type t) : name(n), name_type(t) {} 
  string name;
  Type name_type; 
  bool operator==(const Name &o) const {
    return (name == o.name && name_type == o.name_type);  
  }
  // just for sorting to eliminate duplicates
  bool operator<(const Name &o) const {
    return (name == o.name) ? (name_type < o.name_type) : (name < o.name) ;  
  }
}; 



typedef std::list< Name > NameList;
typedef std::list< NetEntity > EntityList;
typedef std::list< Location > LocationList; 
typedef boost::function<void(const NameList &)> Get_names_callback;  
typedef boost::function<void(const EntityList &)> Get_entities_callback;  
typedef boost::function<void()> Clear_callback;  
typedef boost::function<void(const list<Link> &)> Get_links_callback; 
typedef boost::function<void(const LocationList &)> Get_locations_callback; 

// Internal State Machine helpers

// Any operation that modifies the contents of a table should occur
// serially, so they should use Serial_Ops.  


enum AddBindingState { AB_NEEDS_ID, AB_NEEDS_ID_INSERT, 
                      AB_NEEDS_NAME_INSERT, AB_FINISHED, AB_NONE }; 

struct Add_Binding_Op  { 
  Add_Binding_Op(NetEntity e, string n, Name::Type t, 
          bool er, uint32_t iid) :  entity(e), name(n), 
          name_type(t), cur_state(AB_NEEDS_ID), ip_in_db(iid), id(0), 
          existing_record(er) { } 
  NetEntity entity; 
  string name;
  Name::Type name_type; 
  AddBindingState cur_state; 
  uint32_t ip_in_db;
  int64_t id;
  bool existing_record; 
} ; 
typedef boost::shared_ptr<Add_Binding_Op> Add_Binding_Op_ptr; 

enum GetNamesState { GN_FIND_IDS, GN_FIND_NAMES, GN_FIND_LOCNAMES, 
                            GN_DO_CALLBACK, GN_NONE }; 

struct Get_Names_Op {
  Get_Names_Op(Get_names_callback cb) : callback(cb), 
                  cur_state(GN_FIND_IDS), loc_type(Name::LOCATION) {} 
  Get_names_callback callback; 
  storage::Query query; 
  NameList names_found; // names found so far
  list<int64_t> ids_to_fetch; // list of IDs that need name lookups 
  LocationList locs_to_lookup; // list of locations to do name lookups on
  GetNamesState cur_state;
  Name::Type loc_type; // should locations be returns as just the location name
                      // or as location-name;switch-name;portname tuples?
}; 
typedef boost::shared_ptr<Get_Names_Op> Get_Names_Op_ptr; 

struct Get_All_Names_Op {
  Get_All_Names_Op(Get_names_callback cb, Name::Type type) : 
      callback(cb), name_type(type) {} 
  Get_names_callback callback; 
  Name::Type name_type; 
  NameList names_found; // names found so far
}; 
typedef boost::shared_ptr<Get_All_Names_Op> Get_All_Names_Op_ptr; 

enum GetEntitiesState {GE_FIND_IDS, GE_FIND_ENTITIES, GE_DO_CALLBACK, GE_NONE}; 

struct Get_Entities_Op {
  Get_Entities_Op(string n, Name::Type t, Get_entities_callback cb)
    : name(n), name_type(t), callback(cb), cur_state(GE_FIND_IDS)  {} 
  string name;
  Name::Type name_type; 
  Get_entities_callback callback;   
  EntityList entities; 
  list<int64_t> ids_to_fetch; // list of IDs that need entity lookups  
  GetEntitiesState cur_state;
}; 
typedef boost::shared_ptr<Get_Entities_Op> Get_Entities_Op_ptr; 

struct Get_Entities_By_Loc_Op {
  Get_Entities_By_Loc_Op(Get_entities_callback cb): callback(cb)  {} 
  Get_entities_callback callback;   
  EntityList entities; 
  LocationList locs_to_fetch; // (dpid,port) pairs that need entity lookups  
}; 
typedef boost::shared_ptr<Get_Entities_By_Loc_Op> Get_Entities_By_Loc_Op_ptr; 


enum RemoveState { RM_FIND_ID, RM_REMOVE_NAME_ROWS, RM_REMOVE_ID_ROWS, 
                      RM_FINISHED, RM_NONE} ; 
enum RemoveType { RM_NAME_ONLY, RM_IP_ONLY, RM_ALL} ; 

struct Remove_Op  { 
  Remove_Op(NetEntity e, string n, Name::Type t, RemoveType rt):
      entity(e), name(n), name_type(t), 
      cur_state(RM_FIND_ID), id(0), rm_type(rt)  {} 
  NetEntity entity; 
  string name; 
  Name::Type name_type; 
  RemoveState cur_state; 
  int64_t id;  
  RemoveType rm_type; 
};  
typedef boost::shared_ptr<Remove_Op> Remove_Op_ptr; 


enum GetLinksState { GL_FETCH_ALL, GL_FILTER_AND_CALLBACK, GL_NONE }; 
enum GetLinksType { GL_ALL, GL_DP , GL_DP_Port }; 

struct Get_Links_Op { 
  Get_Links_Op (GetLinksType t, const Get_links_callback &cb) : 
    cur_state(GL_FETCH_ALL), callback(cb), type(t) {} 
  list<Link> links; 
  GetLinksState cur_state;
  Get_links_callback callback; 
  GetLinksType type;
  datapathid filter_dpid;
  uint16_t filter_port; 
}; 
typedef boost::shared_ptr<Get_Links_Op> Get_Links_Op_ptr; 

struct Get_LocNames_Op { 
  Get_LocNames_Op (const Get_names_callback &cb,const storage::Query &q,
                  Name::Type t) : callback(cb), query(q), type(t) {} 
  NameList loc_names;
  Get_names_callback callback; 
  storage::Query query; // query specifying the dpid and port 
  Name::Type type; // type of location being looked for 
}; 
typedef boost::shared_ptr<Get_LocNames_Op> Get_LocNames_Op_ptr; 


struct Get_Loc_By_Name_Op { 
  Get_Loc_By_Name_Op (const Get_locations_callback &cb) : callback(cb) {} 
  LocationList locations; 
  Get_locations_callback callback; 
}; 
typedef boost::shared_ptr<Get_Loc_By_Name_Op> Get_Loc_By_Name_Op_ptr; 


// main class
//
// Bindings_Storage mirrors the Authenticator's internal data structures
// within the NDB.  This serves two goals:  1) this data can be archived to
// reconstruct network state at a later point in time, and 2) other 
// components can query the current binding state via Bindings_Storage
// interfaces.  
//
// To manage names, the component has NDB tables:
//
// the "id table": 
//
// | id (int), dpid (int), port (int), dladdr (int), nwaddr (int) | 
//
// ID values are NOT unique in the table, rather they correspond to
// a single "record" in the policy code, which itself may have mutiple
// different IP addresses.  Each row, however, will be unique.  
//
// the "name table":
//
// | id (int), name (string), name_type (int) | 
//
// ID values in the name table refer to an ID from the id-table, 
// binding that ID to a particular name (name_type is one of the values
// specified by the Name::Type enum).  No values in this table
// are unique, and there may be duplicate rows if the same bindings are
// added multiple times. 
//
// All operations that add or remove name binding state are serialized by
// Bindings_Storage, so that no such operations run in parallel, though
// this serialization is hidden from the caller.  Thus, if two subsequent 
// calls both add binding state, the modifications to NDB state from the 
// first complete before the NDB modifications specified by the second 
// call begin.  Likewise, if the component receives an add and then a remove,
// it will complete all NDB operations for the add before processing the
// remove.  Calls to lookup NDB state are not serialized, so if an add is
// followed quickly by a get, the get result may not include data from the
// add.  
//
// TODO: document the bindings_location and bindings_link tables.
//


class Bindings_Storage : public Component {

public:

      // NDB table names
      static const string ID_TABLE_NAME;
      static const string NAME_TABLE_NAME;
      static const string LINK_TABLE_NAME;
      static const string LOCATION_TABLE_NAME;

      Bindings_Storage(const container::Context* c,const xercesc::DOMNode*); 

      void configure(const container::Configuration*);
      void install(); 

     static void getInstance(const container::Context* ctxt,
         Bindings_Storage*& h);

     // does a lookup for all names of a particular type (e.g., USER,
     // HOST, LOCATION, SWITCH).  This represents all names that have
     // currently active bindings.  Obviously, if you are on a large
     // network, the callback may be called with a very large list, so
     // use this sparingly.  
     void get_all_names(Name::Type name_type, const Get_names_callback &cb); 

     // adds a binding between the network data and a high-level USER or
     // HOST name.  if ip_in_db is non-zero, this data should be added 
     // to an existing record, which can be found using 
     // (dpid,port,mac,ip_in_db) as a lookup key.  
     // NDB operations for this call are serialized. 
     void store_binding_state(const datapathid &dpid, 
          uint16_t port, const ethernetaddr &mac, 
          uint32_t ip, const string &name, Name::Type name_type, 
          bool existing_record, uint32_t ip_in_db = 0); 
     
     // same as above, but doesn't take a name or name type
     // sometimes policy just wants to bind network ids together
     // NDB operations for this call are serialized. 
     void store_binding_state(const datapathid &dpid, 
          uint16_t port, const ethernetaddr &mac, 
          uint32_t ip, bool existing_record, uint32_t ip_in_db = 0); 
    
     // does a lookup based on a network identifier and finds all USER
     // or HOST names associated with it.  Because this call hits the NDB, 
     // results are returned via a callback 
     void get_names_by_ap(const datapathid &dpid, uint16_t port, 
                          const Get_names_callback &cb); 
     void get_names_by_mac(const ethernetaddr &mac, 
                          const Get_names_callback &cb); 
     void get_names_by_ip(uint32_t ip, const Get_names_callback &cb);
     void get_names(const datapathid &dpid, uint16_t port, 
          const ethernetaddr &mac, uint32_t ip, const Get_names_callback &cb);
     // similar to above calls, but passes query on directly to NDB
     void get_names(const storage::Query &query, Name::Type loc_type,
         const Get_names_callback &cb);

     // does a lookup based on a principal name and fills in a caller 
     // provided list of NetEntity objects
     // Valid principal types are (USER,HOST,LOCATION,PORT).  
     void get_entities_by_name(string name, Name::Type name_type, 
                                      const Get_entities_callback &ge_cb); 

     // removes the binding state mapping the supplied USER/HOST name 
     // to the machine with these network identifiers.  
     // NDB operations for this call are serialized. 
     void remove_binding_state(const datapathid& dpid, uint16_t port, 
         const ethernetaddr &mac, uint32_t ip, 
         string name, Name::Type name_type); 

    // remove bindings for the following machine.  If 'remove_all' is true, 
    // this finds an id based on the provided (dpid,port,mac,ip) and then 
    // removes all id-table and name-table entries associated with that id. 
    // If remove_all is false, this only removes the corresponding row in 
    // the id-table, and no name-table entries.  
    // NDB operations for this call are serialized. 
    // This call only removes USER or HOST bindings
    void remove_machine(const datapathid &dpid, uint16_t port, 
          const ethernetaddr &mac, uint32_t ip, bool remove_all);
    
    // removes all USER/HOST name binding state stored by the component
    void clear(Clear_callback cb); 

    // Link functions: the following functions deal only with 
    // bindings, which do not actually have names

    void add_link(const datapathid &dpid1, uint16_t port1, 
                  const datapathid &dpid2, uint16_t port2);

    void remove_link(const datapathid &dpid1, uint16_t port1, 
                  const datapathid &dpid2, uint16_t port2);

    void get_all_links(const Get_links_callback &cb); 
    void get_links(const datapathid dpid,const Get_links_callback &cb); 
    void get_links(const datapathid dpid,uint16_t port, 
                          Get_links_callback &cb); 

    // removes all link binding state stored by the component
    void clear_links(Clear_callback cb);  

    // location/switch functions
    
    // add a switch/location as indicated by name_type
    // If name_type is Name::SWITCH, the port field is ignored
    void add_name_for_location(const datapathid &dpid, uint16_t port, 
                        const string &name, Name::Type name_type);

    // remove a switch/location as indicated by name_type
    // if name_type is empty string "", 
    // this removes all names for this switch/location.
    // If name_type is Name::SWITCH, the port field is ignored
    void remove_name_for_location(const datapathid &dpid, uint16_t port,
                          const string &name, Name::Type name_type); 

    // find all names of type 'name_type' associated this this
    // 'dpid' and 'port' (if name_type is Name::SWITCH, port
    // is ignored).  Valid types include SWITCH,LOCATION,LOC_TUPLE,PORT. 
    void get_names_for_location(const datapathid &dpid, uint16_t port, 
                        Name::Type name_type, const Get_names_callback &cb); 
    void get_names_for_location(storage::Query &q,  
                  const Get_names_callback &cb, Name::Type type); 
   
    // returns a list of location objects that are associated with 
    // a particular name.  If name_type is Name::SWITCH only
    // the dpid of the location object will be valid.  
    void get_location_by_name(const string &name, Name::Type name_type,
                              const Get_locations_callback &cb); 

    // utility function
    static void print_names(const NameList &name_list);
    static inline void str_replace(string &str, const string &target,
                                  const string &replace);

private:
    Async_storage* np_store; 
    bool is_ready; // indicates that tables were created
    uint64_t next_id; // used to pick a fresh id value for new records 

    Serial_Op_Queue name_serial_queue,link_serial_queue,
                    location_serial_queue; 

    // functions related to creating the table
    void create_tables();

    // functions related to adding binding state
    void run_add_fsm(Add_Binding_Op_ptr info, AddBindingState next = AB_NONE); 
    void add_get_cb(const Result & result, const Context & ctx, const Row &row,
                                                  Add_Binding_Op_ptr info);
    void add_put_cb(const Result & result, const storage::GUID &guid, 
                                                Add_Binding_Op_ptr info);

    // functions related to looking up binding state by network identifiers
    void run_get_names_fsm(Get_Names_Op_ptr info, GetNamesState next = GN_NONE); 
    void get_names_cb1(const Result & result, const Context & ctx, 
        const Row &row,Get_Names_Op_ptr info);
    void get_names_cb2(const Result & result, const Context & ctx, 
        const Row &row,Get_Names_Op_ptr info, int64_t id);
    void start_name_lookups(Get_Names_Op_ptr info); 
    void start_locname_lookups(Get_Names_Op_ptr info); 
    void get_locnames_cb(const NameList &names,Get_Names_Op_ptr info, 
                                                const Location &loc); 

    void get_all_names_cb(const Result & result, const Context & ctx, 
                          const Row &row, Get_All_Names_Op_ptr info); 

    // functions related to looking up binding state by name
    void run_get_entities_fsm(Get_Entities_Op_ptr info, 
                                      GetEntitiesState next = GE_NONE); 
    void get_entities_cb1(const Result &result, const Context & ctx, 
                          const Row &row, Get_Entities_Op_ptr info);
    void get_entities_cb2(const Result &result, const Context & ctx, 
                          const Row &row, Get_Entities_Op_ptr info,int64_t id);
    void start_entity_lookups(Get_Entities_Op_ptr info); 

    void get_entities_by_loc_cb1(const LocationList &loc_list,
                                      Get_Entities_By_Loc_Op_ptr op); 
    void get_entities_by_loc_cb2(const Result &result,const Context & ctx, 
                        const Row &row, Get_Entities_By_Loc_Op_ptr info,
                        const Location &loc); 

    // functions related to removing binding state
    void run_remove_fsm(Remove_Op_ptr info, RemoveState next = RM_NONE); 
    void remove_get_cb(const Result &result, const Context & ctx, 
                              const Row &row, Remove_Op_ptr info); 
    void remove_cb(const Result &result, Remove_Op_ptr info);
    
    // functions related to clearing all binding state
    void clear_cb1(const Result &r,Clear_callback cb); 
    void clear_cb2(const Result &r, Clear_callback cb); 


    // functions related to adding links
    void add_link_cb1(const list<Link> links, Link &to_add);
    void add_link_cb2(const Result & result, 
                  const storage::GUID &guid, Link &to_add);

    // functions related to lookup of links
    void run_get_links_fsm(Get_Links_Op_ptr op, 
                                GetLinksState next_state = GL_NONE); 
    void get_links_cb(const Result &result, const Context & ctx, 
                        const Row &row, Get_Links_Op_ptr op); 
    void filter_link_list(Get_Links_Op_ptr op); 

    // for removing links 
    void remove_link_cb(const storage::Result &result,Link &to_delete); 
    void clear_links_cb(const storage::Result &r, Clear_callback cb);  

    // private functions for location/switch bindings

    void add_loc_cb(const Result & result,const storage::GUID &guid);
    void remove_loc_cb(const Result & result);
    void get_locnames_cb(const Result &result, const Context & ctx, 
                         const Row &row, Get_LocNames_Op_ptr op); 
    void get_locnames_cb2(const NameList &names, Get_LocNames_Op_ptr op); 
    void get_locnames_cb3(const NameList &names, 
                          Get_LocNames_Op_ptr op, string switch_name);
    void get_loc_by_name_cb(const Result &result, const Context & ctx, 
                  const Row &row, Get_Loc_By_Name_Op_ptr op); 

    // private functions for renaming 
    // Currently, renaming is not directly exposed.  To cause a 
    // rename in bindings storage, throw a rename event. 
    
    Disposition rename_principal(const Event& e);
    void rename_principal(const string &oldname,
          const string &newname, Directory::Principal_Type type, 
          storage::GUID last_guid);
    void rename_cb(const Result &result, 
                const Context & ctx, const Row &row,
                const string &old_name, const string &new_name, 
                Directory::Principal_Type d_type, const string & op_type,
                storage::GUID last_guid); 

};


#ifdef TWISTED_ENABLED

// including these python functions in the main binding_storage.hh 
// because they are needed by the python proxy classes of other 
// components as well (e.g., user_event_log) that will not necessariliy
// include pybindings_storage as a dependancy. 

#endif 

} 
} 

namespace vigil { 

#ifdef TWISTED_ENABLED

// TODO:  apparently to_python<datapathid> returns a Long,
// which is lame.  It would be nice to fix that, or perhaps
// just swig out NetEntity, Link, and Location 

// NOTE: this declaration must be in namespace vigil
template <>
inline
PyObject *to_python(const NetEntity &entity) { 
 
    PyObject* main_tuple = PyTuple_New(4);
    PyTuple_SetItem(main_tuple,0,to_python(entity.dpid)); 
    PyTuple_SetItem(main_tuple,1,to_python(entity.port)); 
    PyTuple_SetItem(main_tuple,2,to_python(entity.dladdr));    
    PyTuple_SetItem(main_tuple,3,to_python(entity.nwaddr)); 
    return main_tuple;  
} 

template <>
inline
PyObject *to_python(const Link &link) { 
 
    PyObject* main_tuple = PyTuple_New(4);
    PyTuple_SetItem(main_tuple,0,to_python(link.dpid1)); 
    PyTuple_SetItem(main_tuple,1,to_python(link.port1)); 
    PyTuple_SetItem(main_tuple,2,to_python(link.dpid2));    
    PyTuple_SetItem(main_tuple,3,to_python(link.port2)); 
    return main_tuple;  
} 

template <>
inline
PyObject *to_python(const Location &loc) { 
 
    PyObject* main_tuple = PyTuple_New(2);
    PyTuple_SetItem(main_tuple,0,to_python(loc.dpid)); 
    PyTuple_SetItem(main_tuple,1,to_python(loc.port)); 
    return main_tuple;  
}


template <>
inline
PyObject *to_python(const Name &n) { 
 
    PyObject* main_tuple = PyTuple_New(2);
    PyTuple_SetItem(main_tuple,0,to_python(n.name)); 
    PyTuple_SetItem(main_tuple,1,to_python((int)n.name_type)); 
    return main_tuple;  
}


#endif

}// end vigil  


#endif
