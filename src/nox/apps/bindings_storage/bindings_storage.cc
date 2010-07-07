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
#include <ctime>
#include <inttypes.h>
#include <list>
#include <sys/time.h>
#include <sstream> 
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include "assert.hh"

#include "vlog.hh"
#include "storage/storage.hh" 
#include <xercesc/dom/DOM.hpp>
#include "bindings_storage.hh"
#include "storage/storage_util.hh"
#include "storage/storage-blocking.hh"
#include "directory/directory.hh"
#include "directory/principal_event.hh"

#include "pyrt/pyglue.hh" 

using namespace std;
using namespace vigil;
using namespace vigil::container;
using namespace vigil::applications;
using namespace storage;

namespace vigil {
namespace applications { 

static Vlog_module lg("bindings_storage");

const string Bindings_Storage::ID_TABLE_NAME = "bindings_id"; 
const string Bindings_Storage::NAME_TABLE_NAME = "bindings_name"; 
const string Bindings_Storage::LINK_TABLE_NAME = "bindings_link"; 
const string Bindings_Storage::LOCATION_TABLE_NAME = "bindings_location"; 

Bindings_Storage::Bindings_Storage(const container::Context* c,
                                        const xercesc::DOMNode*) 
                        : Component(c), is_ready(false), next_id(1), 
                          name_serial_queue(this,"Name Queue",lg), 
                          link_serial_queue(this, "Link Queue", lg),
                          location_serial_queue(this, "Location Queue", lg)
                          {} 

void Bindings_Storage::configure(const container::Configuration*) {
  resolve(np_store);
  register_handler<Principal_name_event>(boost::bind(
        &Bindings_Storage::rename_principal, this, _1));
        
}

void Bindings_Storage::install() {
    create_tables(); 
}

void Bindings_Storage::create_tables() { 
  
  // this is called from install, so use blocking
  // storage calls to create the table
  storage::Sync_storage sync_store(np_store);
  
  storage::Column_definition_map id_table_def; 
  id_table_def["id"] = (int64_t)0; 
  id_table_def["dpid"] = (int64_t)0; 
  id_table_def["port"] = (int64_t)0; 
  id_table_def["dladdr"] = (int64_t)0; 
  id_table_def["nwaddr"] = (int64_t)0; 
  
  storage::Index_list id_table_indices;
  
  storage::Index all_id_fields; // removing entry for IP address
  all_id_fields.columns.push_back("id");
  all_id_fields.columns.push_back("dpid");
  all_id_fields.columns.push_back("port");
  all_id_fields.columns.push_back("dladdr");
  all_id_fields.columns.push_back("nwaddr"); 
  all_id_fields.name = "all_id_fields"; 
  id_table_indices.push_back(all_id_fields); 

  storage::Index all_net_ids; // finding id for a machine 
  all_net_ids.columns.push_back("dpid");
  all_net_ids.columns.push_back("port");
  all_net_ids.columns.push_back("dladdr");
  all_net_ids.columns.push_back("nwaddr"); 
  all_net_ids.name = "all_net_ids"; 
  id_table_indices.push_back(all_net_ids); 
  
  storage::Index ap_only; 
  ap_only.columns.push_back("dpid");
  ap_only.columns.push_back("port");
  ap_only.name = "ap_only"; 
  id_table_indices.push_back(ap_only); 

  storage::Index mac_only; 
  mac_only.columns.push_back("dladdr");
  mac_only.name = "mac_only"; 
  id_table_indices.push_back(mac_only); 

  storage::Index ip_only; 
  ip_only.columns.push_back("nwaddr");
  ip_only.name = "ip_only"; 
  id_table_indices.push_back(ip_only); 
  
  storage::Index id_only; // needed to remove entries by id
  id_only.columns.push_back("id");
  id_only.name = "id_only"; 
  id_table_indices.push_back(id_only); 
  
  storage::Result result = 
      sync_store.create_table(ID_TABLE_NAME, id_table_def, id_table_indices);
  if(result.code != storage::Result::SUCCESS){ 
      lg.err("create table '%s' failed: %s \n", ID_TABLE_NAME.c_str(), 
          result.message.c_str());
      return; 
  }

  storage::Column_definition_map name_table_def;
  name_table_def["id"] = (int64_t)0;
  name_table_def["name"] =  ""; 
  name_table_def["name_type"] = (int64_t)0; 
  
  storage::Index_list name_table_indices;
  
  storage::Index ids; // find names by id 
  ids.columns.push_back("id");
  ids.name = "id"; 
  name_table_indices.push_back(ids);

  storage::Index all_name_fields; // remove a particular name bound to an id
  all_name_fields.columns.push_back("id");
  all_name_fields.columns.push_back("name");
  all_name_fields.columns.push_back("name_type");
  all_name_fields.name = "all_name_fields"; 
  name_table_indices.push_back(all_name_fields); 

  storage::Index name_and_type; // for finding ids based on a name 
  name_and_type.columns.push_back("name");
  name_and_type.columns.push_back("name_type");
  name_and_type.name = "name_and_type"; 
  name_table_indices.push_back(name_and_type); 

  result = sync_store.create_table(NAME_TABLE_NAME, name_table_def, 
                                                name_table_indices);
  if(result.code != storage::Result::SUCCESS){ 
      lg.err("create table '%s' failed: %s \n", NAME_TABLE_NAME.c_str(), 
            result.message.c_str());
      return; 
  }
  
  storage::Column_definition_map link_table_def;
  link_table_def["dpid1"] = (int64_t)0;
  link_table_def["port1"] = (int64_t)0;
  link_table_def["dpid2"] = (int64_t)0;
  link_table_def["port2"] = (int64_t)0;

  // only use a single index, for deletion
  // for search, we iterate through all rows
  storage::Index_list link_table_indices; 
  storage::Index all_link_fields; 
  all_link_fields.name = "all_link_fields"; 
  all_link_fields.columns.push_back("dpid1");
  all_link_fields.columns.push_back("port1");
  all_link_fields.columns.push_back("dpid2");
  all_link_fields.columns.push_back("port2"); 
  link_table_indices.push_back(all_link_fields); 

  result = sync_store.create_table(LINK_TABLE_NAME, link_table_def, 
                                                link_table_indices);
  if(result.code != storage::Result::SUCCESS){ 
      lg.err("create table '%s' failed: %s \n", LINK_TABLE_NAME.c_str(), 
            result.message.c_str());
      return; 
  }
  
  storage::Column_definition_map location_table_def;
  location_table_def["dpid"] = (int64_t)0;
  location_table_def["port"] = (int64_t)0;
  location_table_def["name"] = "";
  location_table_def["name_type"] = (int64_t)0;

  // only use a single index, for deletion
  // for search, we iterate through all rows
  storage::Index_list location_table_indices; 
  
  storage::Index no_name_fields; // for delete-no-name, lookup 
  no_name_fields.name = "no_name_fields"; 
  no_name_fields.columns.push_back("name_type");
  no_name_fields.columns.push_back("dpid");
  no_name_fields.columns.push_back("port"); 
  location_table_indices.push_back(no_name_fields); 
  storage::Index loc_dpid_only; // for delete-all
  loc_dpid_only.name = "loc_dpid_only"; 
  loc_dpid_only.columns.push_back("dpid");
  location_table_indices.push_back(loc_dpid_only); 
  storage::Index loc_name_fields;
  loc_name_fields.name = "loc_name_fields";
  loc_name_fields.columns.push_back("name");
  loc_name_fields.columns.push_back("name_type");
  location_table_indices.push_back(loc_name_fields); 
  storage::Index loc_net_fields; 
  loc_net_fields.name = "loc_net_fields";
  loc_net_fields.columns.push_back("dpid");
  loc_net_fields.columns.push_back("port"); 
  location_table_indices.push_back(loc_net_fields); 
  storage::Index all_loc_fields; // for delete-single 
  all_loc_fields.name = "all_loc_fields"; 
  all_loc_fields.columns.push_back("name");
  all_loc_fields.columns.push_back("name_type");
  all_loc_fields.columns.push_back("dpid");
  all_loc_fields.columns.push_back("port"); 
  location_table_indices.push_back(all_loc_fields); 

  result = sync_store.create_table(LOCATION_TABLE_NAME, location_table_def, 
                                                location_table_indices);
  if(result.code != storage::Result::SUCCESS){ 
      lg.err("create table '%s' failed: %s \n", LOCATION_TABLE_NAME.c_str(), 
            result.message.c_str());
      return; 
  }

  is_ready = true; 
} 

// store_binding_state wrapper for adding a record without a name 
void Bindings_Storage::store_binding_state(const datapathid &dpid, 
          uint16_t port, const ethernetaddr &mac, 
          uint32_t ip, bool existing_record, uint32_t ip_in_db){  

  store_binding_state(dpid,port,mac,ip,"", Name::NONE, 
                              existing_record, ip_in_db);  
} 

// main function to add binding state to the database.  
void Bindings_Storage::store_binding_state(const datapathid &dpid, 
          uint16_t port, const ethernetaddr &mac, 
          uint32_t ip, const string &name, Name::Type name_type, 
          bool existing_record, uint32_t ip_in_db) {  
  NetEntity ent(dpid,port,mac,ip); 
  Add_Binding_Op_ptr info = Add_Binding_Op_ptr(
                                  new Add_Binding_Op(ent,name,name_type, 
                                  existing_record, ip_in_db));  
  Serial_Op_fn fn = 
    boost::bind(&Bindings_Storage::run_add_fsm,this,info,AB_NONE); 
  name_serial_queue.add_serial_op(fn); 
} 

// finite-state machine for ADD
// State Desciptions: 
// AB_NEEDS_ID: do lookup to find an existing ID associated with the 
//              provided network identifiers 
// AB_NEEDS_ID_INSERT:  Adds a new ID to the database 
// AB_NEEDS_NAME_INSERT:  Adds a new name entry to the database
// AB_FINISHED :  frees memory and checks for pending seriall operations
void Bindings_Storage::run_add_fsm(Add_Binding_Op_ptr info,
                                  AddBindingState next_state) {
  storage::Query q;
  if(next_state != AB_NONE) 
    info->cur_state = next_state; 

  switch (info->cur_state) {

    case AB_NEEDS_ID:
      info->entity.fillQuery(q); 
      if(info->existing_record) 
        q["nwaddr"] = (int64_t) info->ip_in_db; 
      np_store->get(ID_TABLE_NAME, q, 
          boost::bind(&Bindings_Storage::add_get_cb, this, _1, _2,_3,info)); 
      return; 
    
    case AB_NEEDS_ID_INSERT: 
      info->entity.fillQuery(q); 
      q["id"] = (int64_t)info->id;
      np_store->put(ID_TABLE_NAME,q, boost::bind(&Bindings_Storage::add_put_cb, 
                                                          this, _1, _2, info)); 
      return;

    case AB_NEEDS_NAME_INSERT: 
      if(info->name_type != Name::NONE) { 
        assert(info->id);
        q["id"] = (int64_t)info->id;
        q["name"] = info->name;
        q["name_type"] = (int64_t)info->name_type;
        storage::Async_storage::Put_callback pcb =  
            boost::bind(&Bindings_Storage::add_put_cb, this, _1, _2, info); 
        np_store->put(NAME_TABLE_NAME,q,pcb); 
        return; 
      } // else, fall through to AB_FINISHED

    case AB_FINISHED: 
      name_serial_queue.finished_serial_op(); 
      return;
    case AB_NONE: 
      break; // error
  } 

  lg.err("Invalid state %d in run_add_fsm \n", info->cur_state); 
} 

// helper to handle callbacks for inserting IDs and names into the
// database during an add 
void Bindings_Storage::add_put_cb(const Result & result, 
                  const storage::GUID &guid, Add_Binding_Op_ptr info){
    if(result.code != storage::Result::SUCCESS) {
      lg.err("add_put_cb NDB error: %s \n", result.message.c_str());
      run_add_fsm(info,AB_FINISHED); 
      return; 
    }

    if(info->cur_state == AB_NEEDS_ID_INSERT)   
      run_add_fsm(info,AB_NEEDS_NAME_INSERT); 
    else // AB_NEEDS_NAME_INSERT
      run_add_fsm(info,AB_FINISHED); 
}

// NDB get callback for query into the ID-table to find the ID associated
// with particular network identifiers.  Lookup key was either
// (dpid,port,mac,ip) or (ip_in_db)  
void Bindings_Storage::add_get_cb(const Result & result, const Context & ctx, 
    const Row &row, Add_Binding_Op_ptr info){

  if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS) {
    lg.err("add_get_cb NDB error: %s \n", result.message.c_str());
    run_add_fsm(info,AB_FINISHED); 
    return; 
  }

  if(result.code == storage::Result::NO_MORE_ROWS) {  
    // lookup didn't find anything  
    // assign a new ID and insert into the id-table
    info->id = next_id++;          
    run_add_fsm(info,AB_NEEDS_ID_INSERT); 
    return; 
  }

  // result.code == SUCCESS
  try { 
    info->id = Storage_Util::get_col_as_type<int64_t>(row,"id"); 
    // if 'existing_record', we must add new id-table row with 'id',
    // otherwise we can just insert the names using 'id' 
    if(info->existing_record) 
      run_add_fsm(info,AB_NEEDS_ID_INSERT);
    else
      run_add_fsm(info,AB_NEEDS_NAME_INSERT); 
  } catch (exception &e) {
    lg.err("add_get_cb exception: %s \n", e.what());
    run_add_fsm(info,AB_FINISHED); 
  } 
}

void Bindings_Storage::get_all_names(Name::Type name_type, 
                                      const Get_names_callback &cb){
  Get_All_Names_Op_ptr info = Get_All_Names_Op_ptr(
                              new Get_All_Names_Op(cb,name_type)); 
  storage::Query q; // empty query retrives all rows

  string tablename; 
  if(name_type == Name::USER || name_type == Name::HOST)
    tablename = NAME_TABLE_NAME;
  else if(name_type == Name::LOCATION || name_type == Name::SWITCH
                                      || name_type == Name::PORT) 
    tablename = LOCATION_TABLE_NAME; 
  else { 
    lg.err("get_all_names() called with invalid type = %d \n", name_type); 
    post(boost::bind(cb, NameList()));
    return; 
  } 
  np_store->get(tablename, q, 
          boost::bind(&Bindings_Storage::get_all_names_cb, this, _1, _2,_3,info)); 

} 

void Bindings_Storage::get_all_names_cb(const Result & result, 
                  const Context & ctx, const Row &row, Get_All_Names_Op_ptr info){
    
  if(result.code != storage::Result::SUCCESS){ 
    if(result.code != storage::Result::NO_MORE_ROWS) 
      lg.err("get_all_names_cb NDB error: %s \n", result.message.c_str());
    post(boost::bind(info->callback, info->names_found));
    return; 
  }
  
  // we retrieve all entries, so we must reject those that don't match 
  // the requested name type
  try {
    Name::Type name_type = (Name::Type)
                    Storage_Util::get_col_as_type<int64_t>(row,"name_type");
    if(name_type == info->name_type) {
      string name = Storage_Util::get_col_as_type<string>(row,"name");
      info->names_found.push_back(Name(name,name_type)); 
    }
  } catch (exception &e) {
    lg.err("exception reading row in get_all_names(): %s \n", e.what()); 
    return; 
  } 
  np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_all_names_cb, 
        this, _1, _2,_3,info));
} 


void Bindings_Storage::get_names_by_mac(const ethernetaddr &mac, 
                              const Get_names_callback &cb) {
  Get_Names_Op_ptr info = Get_Names_Op_ptr(new Get_Names_Op(cb)); 
  info->query["dladdr"] = (int64_t)mac.hb_long();
  run_get_names_fsm(info); 
}

void Bindings_Storage::get_names_by_ap(const datapathid &dpid, uint16_t port, 
                                        const Get_names_callback &cb){
  Get_Names_Op_ptr info = Get_Names_Op_ptr(new Get_Names_Op(cb)); 
  info->query["dpid"] = (int64_t)dpid.as_host();
  info->query["port"] = (int64_t)port;
  run_get_names_fsm(info); 
} 
     
void Bindings_Storage::get_names_by_ip(uint32_t ip, 
                                  const Get_names_callback &cb){
  Get_Names_Op_ptr info = Get_Names_Op_ptr(new Get_Names_Op(cb)); 
  info->query["nwaddr"] = (int64_t)ip;
  run_get_names_fsm(info); 
} 
     
void Bindings_Storage::get_names(const datapathid &dpid, uint16_t port, 
          const ethernetaddr &mac, uint32_t ip, const Get_names_callback &cb){
  Get_Names_Op_ptr info = Get_Names_Op_ptr(new Get_Names_Op(cb)); 
  info->query["dpid"] = (int64_t)dpid.as_host();
  info->query["port"] = (int64_t)port;
  info->query["dladdr"] = (int64_t)mac.hb_long();
  info->query["nwaddr"] = (int64_t)ip;
  run_get_names_fsm(info); 
} 

// loc_type should be either Name::LOCATION or Name::LOC_TUPLE
// indicating the desired format for names of the location type 
void Bindings_Storage::get_names(const storage::Query &query, 
                     Name::Type loc_type, const Get_names_callback &cb) {
  Get_Names_Op_ptr info = Get_Names_Op_ptr(new Get_Names_Op(cb));
  info->loc_type = loc_type; 
  info->query = query;
  run_get_names_fsm(info); 
}


// finite-state machine for GET_NAMES
// State Desciptions: 
// GN_FIND_IDS: do lookup to find the IDs of all existing records 
//              associated with the provided network identifiers
// GN_FIND_NAMES: issue name table lookups for each of the IDs
// GN_DO_CALLBACK: perform callback to client with accumulated names,
//                 called once all GN_FIND_NAMES queries have completed
void Bindings_Storage::run_get_names_fsm(Get_Names_Op_ptr info, 
                                  GetNamesState next_state) { 

  if(next_state != GN_NONE) 
    info->cur_state = next_state; 

  switch(info->cur_state) { 

    case GN_FIND_IDS:
      np_store->get(ID_TABLE_NAME, info->query, 
          boost::bind(&Bindings_Storage::get_names_cb1, this, _1, _2,_3,info)); 
      return; 
    case GN_FIND_NAMES:
      start_name_lookups(info); 
      return; 
    case GN_FIND_LOCNAMES:
      start_locname_lookups(info); 
      return; 
    case GN_DO_CALLBACK:
      post(boost::bind(info->callback, info->names_found));
      return; 
    case GN_NONE:
      break; // error
  } 

  lg.err("Invalid state %d in run_get_names_fsm \n", info->cur_state); 
}

// Handles NDB get() and get_next() callbacks for id-table queries in
// the GN_FIND_IDS state.  Store reach ID found in info.ids_to_fetch
void Bindings_Storage::get_names_cb1(const Result & result, 
                  const Context & ctx, const Row &row, Get_Names_Op_ptr info){
    
  if(result.code != storage::Result::SUCCESS && 
     result.code != storage::Result::NO_MORE_ROWS){ 
        lg.err("get_names_cb1 NDB error: %s \n", result.message.c_str());
        run_get_names_fsm(info,GN_DO_CALLBACK); // on error, do empty callback
        return; 
  }
   
  if(result.code == storage::Result::NO_MORE_ROWS) {
    run_get_names_fsm(info, GN_FIND_NAMES); // done finding IDs 
    return; 
  }

  // result.code == SUCCESS 
  // found a row matching the mac.  we should add the ID to info
  // and also record the location (dpid,port) to a loc-name lookup
  try {
    int64_t id = Storage_Util::get_col_as_type<int64_t>(row,"id");
    info->ids_to_fetch.push_back(id); 
    int64_t dpid = Storage_Util::get_col_as_type<int64_t>(row,"dpid");
    int64_t port = Storage_Util::get_col_as_type<int64_t>(row,"port");
    Location loc(datapathid::from_host((uint64_t)dpid),(uint16_t)port);
    info->locs_to_lookup.push_back(loc);  
  } catch (exception &e) {
    lg.err("exception reading row from bindings_id: %s \n", e.what()); 
    run_get_names_fsm(info,GN_FIND_LOCNAMES); // on error, do empty callback
    return; 
  } 
  np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_names_cb1, 
        this, _1, _2,_3,info));
} 


// spawns an NDB table querying the name table for each unique ID
// in info.ids_to_fetch 
void Bindings_Storage::start_name_lookups(Get_Names_Op_ptr info) { 
  if(info->ids_to_fetch.size() == 0) {
    run_get_names_fsm(info, GN_FIND_LOCNAMES); 
    return; 
  }
     
  Storage_Util::squash_list(info->ids_to_fetch); 

  // NOTE: we know we will make progress to get_names_cb2, because
  // ids_to_fetch cannot be empty
  list<int64_t>::iterator it = info->ids_to_fetch.begin(); 
  while(it != info->ids_to_fetch.end()) {
    storage::Query q; 
    q["id"] = *it;
    storage::Async_storage::Get_callback gcb = 
      boost::bind(&Bindings_Storage::get_names_cb2, this,_1,_2,_3,info, *it); 
    np_store->get(NAME_TABLE_NAME, q,gcb); 
    ++it; 
  }

} 

// get and get_next() NDB callback for name-table queries 
// issued by start_names_lookups.  Once all queries have finished,
// we call run_get_names_fsm() with GN_FIND_LOCNAMES
void Bindings_Storage::get_names_cb2(const Result & result, 
      const Context & ctx, const Row &row, Get_Names_Op_ptr info, int64_t id){
  
  if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){ 
    lg.err("get_names_cb2 NDB error: %s \n", result.message.c_str());
  }
  
  // handle NO_MORE_ROWS or an error. Multiple queries may be
  // "in flight" so we can't just move on to GN_FIND_LOCNAMES 
  if(result.code != storage::Result::SUCCESS) {
    info->ids_to_fetch.remove(id); // done with this ID
    if(info->ids_to_fetch.size() == 0)   
      run_get_names_fsm(info,GN_FIND_LOCNAMES); // all done finding IDs
    return; 
  }

  // result.code == SUCCESS
  try { 
    int64_t name_type = 
      Storage_Util::get_col_as_type<int64_t>(row,"name_type");
    string name = Storage_Util::get_col_as_type<string>(row,"name");
    Name n(name, (Name::Type)name_type);
    info->names_found.push_back(n); 
  } catch (exception &e) {
    lg.err("exception reading row from bindings_name: %s \n", e.what()); 
    // still try to read subsequent rows 
  } 
  np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_names_cb2, 
        this, _1, _2,_3,info, id)); 
} 

// for each unique LOCATION we found in the id-table, spawn a location name
// lookup, appending those locations to the list of names
void Bindings_Storage::start_locname_lookups(Get_Names_Op_ptr info) { 
  if(info->locs_to_lookup.size() == 0) {
    run_get_names_fsm(info, GN_DO_CALLBACK); 
    return; 
  }
     
  Storage_Util::squash_list(info->locs_to_lookup); 
  LocationList::iterator it = info->locs_to_lookup.begin(); 
  while(it != info->locs_to_lookup.end()) {
    get_names_for_location(it->dpid, it->port, info->loc_type,  
        boost::bind(&Bindings_Storage::get_locnames_cb, this,_1,info,*it)); 
    ++it; 
  }

} 

// callback for LOCATION name lookup, which is provided this 
// the same class
void Bindings_Storage::get_locnames_cb(const NameList &names,
                    Get_Names_Op_ptr info, const Location &loc){
  
  info->names_found.insert(info->names_found.begin(), 
                          names.begin(),names.end()); 
  
  info->locs_to_lookup.remove(loc); // done with this location
  if(info->locs_to_lookup.size() == 0) { 
    run_get_names_fsm(info,GN_DO_CALLBACK); // all done finding IDs
    return; 
  }

} 

void Bindings_Storage::get_entities_by_name(string name, 
        Name::Type name_type, const Get_entities_callback &cb) {
  if(name_type == Name::HOST || name_type == Name::USER) { 
    Get_Entities_Op_ptr info = Get_Entities_Op_ptr(
                            new Get_Entities_Op(name,name_type,cb));
    run_get_entities_fsm(info); 
  } else { 
    // this just wraps another "external function", get_location_by_name()
    // which handles lookup for the following name types: 
    // location, switch, port, loc_tuple 
    Get_Entities_By_Loc_Op_ptr op = 
                  Get_Entities_By_Loc_Op_ptr(new Get_Entities_By_Loc_Op(cb));
    get_location_by_name(name, name_type, 
      boost::bind(&Bindings_Storage::get_entities_by_loc_cb1, this, _1,op)); 

  } 
} 

// finite-state machine for GET_ENTITIES
// State Desciptions: 
// GE_FIND_IDS: do lookup to find the IDs of all existing records 
//              associated with the provided network identifiers
// GE_FIND_ENTITIES: issue id table lookups for each of the IDs
// GE_DO_CALLBACK: perform callback to client with accumulated names,
//                 called once all GN_FIND_NAMES queries have completed
void Bindings_Storage::run_get_entities_fsm(Get_Entities_Op_ptr info, 
                                      GetEntitiesState next_state) {
  storage::Query q; 
  if(next_state != GE_NONE) 
    info->cur_state = next_state; 

  switch(info->cur_state) { 
    case GE_FIND_IDS:
      q["name"] = info->name; 
      q["name_type"] = (int64_t)info->name_type; 
      np_store->get(NAME_TABLE_NAME, q, 
        boost::bind(&Bindings_Storage::get_entities_cb1, this, _1, _2,_3,info)); 
      return; 
    case GE_FIND_ENTITIES:
      start_entity_lookups(info); 
      return; 
    case GE_DO_CALLBACK:
      post(boost::bind(info->callback, info->entities));
      return;
    case GE_NONE: 
      break; // error

  } 

  lg.err("Invalid state %d in run_get_entities_fsm \n", info->cur_state); 
} 

// get() and get_next() NDB callbacks for the name-table lookups
void Bindings_Storage::get_entities_cb1(const Result &result, 
              const Context & ctx, const Row &row, Get_Entities_Op_ptr info) {

  if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){ 
        lg.err("NDB error on get_entities_cb1: %s \n", result.message.c_str());
        run_get_entities_fsm(info, GE_DO_CALLBACK); 
        return;
  }

  // find ID associated with the queried entity
  if(result.code == storage::Result::NO_MORE_ROWS) {
    if(info->ids_to_fetch.size() == 0) { 
      lg.dbg("get_entities_cb1: no ID found for name = %s, type = %d \n", 
        info->name.c_str(), info->name_type);
    }
    run_get_entities_fsm(info,GE_FIND_ENTITIES);
    return;
  } 

  // result.code == SUCCESS 
  storage::Query q; 
  try { 
    int64_t id  = Storage_Util::get_col_as_type<int64_t>(row,"id");
    info->ids_to_fetch.push_back(id); 
    np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_entities_cb1, 
        this, _1, _2,_3,info));
  } catch (exception &e) {
    lg.err("exception in get_entities_cb1: %s \n", e.what()); 
    run_get_entities_fsm(info,GE_DO_CALLBACK); 
  } 
} 

// spawns a separate id-table query for each unique id in info.ids_to_fetch
void Bindings_Storage::start_entity_lookups(Get_Entities_Op_ptr info) { 
  if(info->ids_to_fetch.size() == 0) {
    run_get_entities_fsm(info,GE_DO_CALLBACK); 
    return; 
  } 

  Storage_Util::squash_list(info->ids_to_fetch); 

  list<int64_t>::iterator it = info->ids_to_fetch.begin();
  while(it != info->ids_to_fetch.end()) {
    storage::Query q; 
    q["id"] = *it;
    storage::Async_storage::Get_callback gcb = 
          boost::bind(&Bindings_Storage::get_entities_cb2, 
          this,_1,_2,_3,info, *it); 
    np_store->get(ID_TABLE_NAME, q,gcb); 
    ++it; 
  }
      
} 

// get and get_next() NDB callbacks for id-tables lookups spawned by
// start_entity_lookups.  Once all queries have completed, call 
// run_get_entities_fsm to do callback 
void Bindings_Storage::get_entities_cb2(const Result &result,
    const Context & ctx, const Row &row, Get_Entities_Op_ptr info,int64_t id) {
  
    if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){ 
        lg.err("NDB error on get_entities_cb2: %s \n", result.message.c_str());
    }
    
    // handle NO_MORE_ROWS or error
    if(result.code != storage::Result::SUCCESS) {
      info->ids_to_fetch.remove(id); // done with this ID
      if(info->ids_to_fetch.size() == 0)   
        run_get_entities_fsm(info,GE_DO_CALLBACK); // all done finding IDs
      return; 
    } 
      
    //result.code == SUCCESS
    try { 
      info->entities.push_back(NetEntity(row));
    } catch (exception &e) {
      lg.err("%s \n", e.what()); // skip this row, try and continue  
    } 
    np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_entities_cb2,
          this, _1, _2,_3,info,id));

} 


void Bindings_Storage::get_entities_by_loc_cb1(const LocationList &loc_list,
                                      Get_Entities_By_Loc_Op_ptr op) {
  op->locs_to_fetch = loc_list;
  if(loc_list.size() == 0) { 
    post(boost::bind(op->callback, op->entities)); 
  }

  LocationList::const_iterator it = loc_list.begin(); 
  for( ; it != loc_list.end(); ++it) { 
    storage::Query q; 
    q["dpid"] = (int64_t) it->dpid.as_host();
    q["port"] = (int64_t) it->port; 
    storage::Async_storage::Get_callback gcb = 
          boost::bind(&Bindings_Storage::get_entities_by_loc_cb2, 
          this,_1,_2,_3,op,*it); 
    np_store->get(ID_TABLE_NAME, q,gcb); 
  } 

} 

void Bindings_Storage::get_entities_by_loc_cb2(const Result &result,
    const Context & ctx, const Row &row, Get_Entities_By_Loc_Op_ptr info,
    const Location &loc) {
  
    if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){ 
        lg.err("NDB error on get_entities_by_loc_cb2: %s \n", 
            result.message.c_str());
    }
    
    // handle NO_MORE_ROWS or error
    if(result.code != storage::Result::SUCCESS) {
      info->locs_to_fetch.remove(loc); // done with this location
      if(info->locs_to_fetch.size() == 0)   
        post(boost::bind(info->callback, info->entities)); 
      return; 
    } 
      
    //result.code == SUCCESS
    try { 
      info->entities.push_back(NetEntity(row));
    } catch (exception &e) {
      lg.err("in get_entities_by_loc_cb2 %s \n", e.what()); 
      // skip this row, try and continue  
    } 
    np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_entities_by_loc_cb2,
          this, _1, _2,_3,info,loc));

} 

// removes a single binding from the name table, will never remove a 
// record entry from the id-table.  This operation is performed serially
void Bindings_Storage::remove_binding_state(const datapathid &dpid, 
    uint16_t port, const ethernetaddr &mac, uint32_t ip, 
    string name, Name::Type name_type) {
  NetEntity ent(dpid,port,mac,ip); 
  Remove_Op_ptr info = Remove_Op_ptr(new Remove_Op(ent,name,name_type,RM_NAME_ONLY));
  
  Serial_Op_fn fn = 
    boost::bind(&Bindings_Storage::run_remove_fsm,this,info,RM_NONE); 
  name_serial_queue.add_serial_op(fn); 
} 

// 
void Bindings_Storage::remove_machine(const datapathid &dpid, uint16_t port, 
              const ethernetaddr &mac, uint32_t ip,bool remove_all){
  RemoveType rm_type = (remove_all) ? (RM_ALL) : (RM_IP_ONLY); 
  NetEntity ent(dpid,port,mac,ip); 
  Remove_Op_ptr info = Remove_Op_ptr(new 
                            Remove_Op(ent,"",Name::NONE, rm_type)); 

  Serial_Op_fn fn = 
    boost::bind(&Bindings_Storage::run_remove_fsm,this,info,RM_NONE); 
  name_serial_queue.add_serial_op(fn); 
} 
    
// finite-state machine for REMOVE
// State Desciptions: 
// RM_FIND_ID: spawns id-table lookup to find the ID associated with the
//             network identifiers specificed in the remove command. 
// RM_REMOVE_NAME_ROWS: deletes all entries in the name table with the ID
//                      found in the last step. If remove_binding_state() 
//                      was called, we remove only the entries with a 
//                      specified name (i.e., only one row).  This state
//                      is skipped if rm_type is IP_ONLY, since there may
//                      be mutiple rows in id-table with the same ID.  
// RM_REMOVE_ID_ROWS: deletes row(s) from the id-table.  If rm_type is 
//                    NAME_ONLY this state is skipped, and if rm_type is
//                    IP_ONLY the remove query is limited to a single IP
//                    address. 
// RM_FINISHED:       Check for additional serial operations to run.  
void Bindings_Storage::run_remove_fsm(Remove_Op_ptr info,RemoveState next_state) {
  storage::Query q; 
  if(next_state != RM_NONE) 
    info->cur_state = next_state; 
  
  switch (info->cur_state) { 
    case RM_FIND_ID:
      info->entity.fillQuery(q); 
      np_store->get(ID_TABLE_NAME, q, 
          boost::bind(&Bindings_Storage::remove_get_cb, this, _1, _2,_3,info)); 
      return; 
    case RM_REMOVE_NAME_ROWS:
      q["id"] = (int64_t) info->id;
      if(info->rm_type == RM_NAME_ONLY) { 
          q["name"] = info->name;
          q["name_type"] = (int64_t) info->name_type; 
      }
      Storage_Util::non_trans_remove_all(np_store, NAME_TABLE_NAME, q, 
          boost::bind(&Bindings_Storage::remove_cb,this,_1, info)); 
      return;
    case RM_REMOVE_ID_ROWS: 
      q["id"] = (int64_t) info->id; 
      if(info->rm_type == RM_IP_ONLY) 
        info->entity.fillQuery(q); 
      Storage_Util::non_trans_remove_all(np_store, ID_TABLE_NAME, q, 
          boost::bind(&Bindings_Storage::remove_cb,this,_1, info)); 
      return;
    case RM_FINISHED: 
      name_serial_queue.finished_serial_op(); 
      return; 
    case RM_NONE:
      break; // error
  }
  lg.err("Invalid state %d in run_remove_fsm \n", info->cur_state); 
}
     
// get() callback for query into the id-table.  called in RM_FIND_ID state only
void Bindings_Storage::remove_get_cb(const Result &result, const Context & ctx, 
                                    const Row &row, Remove_Op_ptr info) {

  if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){ 
        lg.err("NDB error on remove_get: %s \n", result.message.c_str());
        run_remove_fsm(info,RM_FINISHED); 
        return;
  }

  assert(info->cur_state == RM_FIND_ID);

  if(result.code == storage::Result::NO_MORE_ROWS) { 
    // not necessarily an error
    lg.dbg("Remove failed: no ID found for dpid = %"PRId64", "
        "port = %d, mac = %"PRId64" ip = %d\n", info->entity.dpid.as_host(),
        info->entity.port,info->entity.dladdr.hb_long(), info->entity.nwaddr);
    run_remove_fsm(info,RM_FINISHED); 
    return;
  } 

  // result.code == SUCCESS
  try { 
    info->id = Storage_Util::get_col_as_type<int64_t>(row,"id");
    if(info->rm_type == RM_IP_ONLY) 
      run_remove_fsm(info,RM_REMOVE_ID_ROWS); // don't remove names
    else 
      run_remove_fsm(info,RM_REMOVE_NAME_ROWS); 
  } catch (exception &e) {
    lg.err("remove_get_cb exception: %s \n", e.what()); 
    run_remove_fsm(info,RM_FINISHED); 
  } 

  // there should only be a single ID in the table that matches
  // so we do not make a get_next() call
} 

// callback for remove_all NDB calls for both the id and name tables.  
void Bindings_Storage::remove_cb(const Result &result, Remove_Op_ptr info){

  if(result.code != storage::Result::SUCCESS) { 
        lg.err("remove_cb NDB error: %s \n", result.message.c_str());
        run_remove_fsm(info,RM_FINISHED); 
        return;
  }
  // if removing names succeed or failed, we still want to try and remove 
  // the associated ids, if we're supposed to 
  if(info->cur_state == RM_REMOVE_NAME_ROWS && info->rm_type != RM_NAME_ONLY)  
    run_remove_fsm(info,RM_REMOVE_ID_ROWS); 
  else
    run_remove_fsm(info,RM_FINISHED); // done  
  
}

// removes all bindings entries.  starts with id-table
void Bindings_Storage::clear(Clear_callback cb) { 
  storage::Query q; // empty query, remove all 
  Storage_Util::non_trans_remove_all(np_store,ID_TABLE_NAME,q, 
        boost::bind(&Bindings_Storage::clear_cb1,this,_1, cb));
} 

// continues clear() by removing all name table entries 
void 
Bindings_Storage::clear_cb1(const storage::Result &r, Clear_callback cb) { 
  if(r.code != storage::Result::SUCCESS)  
        lg.err("clear_cb1 NDB error: %s \n", r.message.c_str());
  
  storage::Query q; // empty query, remove all 
  Storage_Util::non_trans_remove_all(np_store,NAME_TABLE_NAME,q, 
        boost::bind(&Bindings_Storage::clear_cb2,this,_1, cb));
} 

void  // performs callback to indicate that clear() operation has finished 
Bindings_Storage::clear_cb2(const storage::Result &r, Clear_callback cb) { 
  if(r.code != storage::Result::SUCCESS)  
        lg.err("clear_cb2 NDB error: %s \n", r.message.c_str());
  post(cb); 
}
   
// links are now directional
void Bindings_Storage::add_link(const datapathid &dpid1, uint16_t port1, 
                  const datapathid &dpid2, uint16_t port2) {
  Link to_add = Link(dpid1,port1,dpid2,port2);
  Get_links_callback cb = boost::bind(&Bindings_Storage::add_link_cb1, this,
                              _1, to_add); 
  Serial_Op_fn fn = 
    boost::bind(&Bindings_Storage::get_all_links,this,cb); 
  link_serial_queue.add_serial_op(fn); 
} 

void Bindings_Storage::add_link_cb1(const list<Link> links, Link &to_add) {
  list<Link>::const_iterator it = links.begin(); 
  for( ; it != links.end(); ++it) { 
    if(*it == to_add) { 
      lg.err("Invalid attempt to add link already in the table: "
            " (dp = %"PRId64", port = %d) -> (dp = %"PRId64", port = %d) \n", 
              to_add.dpid1.as_host(),to_add.port1,
              to_add.dpid2.as_host(),to_add.port2); 
      link_serial_queue.finished_serial_op(); 
      return; // all done
    } 
  }
  
  // not a duplicate, we can proceed with insertion 
  storage::Query q; 
  to_add.fillQuery(q);   
  storage::Async_storage::Put_callback pcb =  
    boost::bind(&Bindings_Storage::add_link_cb2, this, _1, _2, to_add); 
  np_store->put(LINK_TABLE_NAME,q,pcb); 

}

void Bindings_Storage::add_link_cb2(const Result & result, 
                  const storage::GUID &guid, Link &to_add){
    if(result.code != storage::Result::SUCCESS)
      lg.err("add_link_cb2 NDB error: %s \n", result.message.c_str());
    
    link_serial_queue.finished_serial_op(); 
} 


void Bindings_Storage::remove_link(const datapathid &dpid1, uint16_t port1, 
                  const datapathid &dpid2, uint16_t port2) {
  Link to_delete = Link(dpid1,port1,dpid2,port2);
  
  storage::Query q; 
  to_delete.fillQuery(q);   
  storage::Async_storage::Remove_callback rcb = 
       boost::bind(&Bindings_Storage::remove_link_cb,this,_1, to_delete); 

  Serial_Op_fn fn = boost::bind(&Storage_Util::non_trans_remove_all,
                  np_store,LINK_TABLE_NAME, q, rcb); 
  link_serial_queue.add_serial_op(fn); 
}

void Bindings_Storage::remove_link_cb(const storage::Result &result,
                                        Link &to_delete) { 
  if(result.code != storage::Result::SUCCESS)  
        lg.err("remove_link_cb NDB error: %s \n", result.message.c_str());
    
  link_serial_queue.finished_serial_op(); 
}

void Bindings_Storage::get_all_links(const Get_links_callback &cb) {
  Get_Links_Op_ptr op = Get_Links_Op_ptr(new Get_Links_Op(GL_ALL,cb));
  run_get_links_fsm(op); 
} 

void Bindings_Storage::get_links(const datapathid dpid,
                                const Get_links_callback &cb) {
  Get_Links_Op_ptr op = Get_Links_Op_ptr(new Get_Links_Op(GL_DP,cb));
  op->filter_dpid = dpid;
  run_get_links_fsm(op); 
} 

void Bindings_Storage::get_links(const datapathid dpid,uint16_t port, 
                                  Get_links_callback &cb) {
  Get_Links_Op_ptr op = Get_Links_Op_ptr(new Get_Links_Op(GL_DP_Port,cb));
  op->filter_dpid = dpid;
  op->filter_port = port; 
  run_get_links_fsm(op); 
} 

void Bindings_Storage::run_get_links_fsm(Get_Links_Op_ptr op,
                                        GetLinksState next_state) {
  if(next_state != GL_NONE) 
    op->cur_state = next_state; 
  
  switch (op->cur_state) { 
    case GL_FETCH_ALL:
      { 
      storage::Query q; // empty query for fetch_all 
      np_store->get(LINK_TABLE_NAME, q, 
          boost::bind(&Bindings_Storage::get_links_cb,
          this, _1, _2,_3,op)); 
      return; 
      }
    case GL_FILTER_AND_CALLBACK:
      filter_link_list(op); 
      post(boost::bind(op->callback, op->links));       
      return; 
    case GL_NONE:
      break; // error
  }
  lg.err("Invalid state %d in run_get_link_fsm \n", op->cur_state); 

} 

void Bindings_Storage::filter_link_list(Get_Links_Op_ptr op) { 
      if(op->type != GL_DP and op->type != GL_DP_Port) 
        return; // don't filter anything 
      
      list<Link>::iterator it = op->links.begin(); 
      list<Link> filtered_list; 
      for( ; it != op->links.end(); ++it) { 
    
        bool switch_match = op->type == GL_DP && it->matches(op->filter_dpid);
        bool all_match = op->type == GL_DP_Port 
                          &&  it->matches(op->filter_dpid,op->filter_port);  
        if(switch_match || all_match) 
          filtered_list.push_back(*it); 
      } 
      op->links = filtered_list; 
} 

void Bindings_Storage::get_links_cb(const Result &result, 
                const Context & ctx, const Row &row, Get_Links_Op_ptr op) {
  if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){ 
        lg.err("NDB error on get_links_internal_cb: %s \n", 
            result.message.c_str());
        run_get_links_fsm(op,GL_FILTER_AND_CALLBACK); 
        return;
  }

  assert(op->cur_state == GL_FETCH_ALL);

  if(result.code == storage::Result::NO_MORE_ROWS) {
    run_get_links_fsm(op,GL_FILTER_AND_CALLBACK); 
    return;
  } 

  // result.code == SUCCESS
  try {
    uint64_t dp1 =(uint64_t)Storage_Util::get_col_as_type<int64_t>(row,"dpid1");
    uint16_t p1 =(uint16_t)Storage_Util::get_col_as_type<int64_t>(row,"port1");
    uint64_t dp2 =(uint64_t)Storage_Util::get_col_as_type<int64_t>(row,"dpid2");
    uint16_t p2 =(uint16_t)Storage_Util::get_col_as_type<int64_t>(row,"port2");
    Link l(datapathid::from_host(dp1),p1,datapathid::from_host(dp2),p2); 
    op->links.push_back(l); 
  } catch (exception &e) {
    // print error but keep trying to read more rows
    lg.err("get_links_cb exception: %s \n", e.what()); 
  } 

  np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_links_cb,
          this, _1, _2,_3,op));
} 

// removes all link entries.  
void Bindings_Storage::clear_links(Clear_callback cb) { 
  storage::Query q; // empty query, remove all 
  Storage_Util::non_trans_remove_all(np_store,LINK_TABLE_NAME,q, 
        boost::bind(&Bindings_Storage::clear_links_cb,this,_1, cb));
} 

void  // performs callback to indicate a clear_links() operation has finished 
Bindings_Storage::clear_links_cb(const storage::Result &r, Clear_callback cb) { 
  if(r.code != storage::Result::SUCCESS)  
        lg.err("clear_links_cb NDB error: %s \n", r.message.c_str());
  post(cb); 
}
    

void Bindings_Storage::add_name_for_location(const datapathid &dpid, 
              uint16_t port, const string &name, Name::Type name_type) { 
  storage::Query q; 
  q["dpid"] = (int64_t) dpid.as_host(); 
  if(name_type == Name::LOCATION || name_type == Name::PORT) 
      q["port"] = (int64_t) port; 
  else if (name_type == Name::SWITCH) 
      q["port"] = (int64_t) Location::NO_PORT;  
  else { 
    lg.err("invalid name type %d in add_name_for_location\n", (int)name_type); 
    return; 
  }
  q["name"] = name; 
  q["name_type"] = (int64_t) name_type; 
  storage::Async_storage::Put_callback pcb =  
    boost::bind(&Bindings_Storage::add_loc_cb, this, _1, _2); 
  Serial_Op_fn fn = boost::bind(&Async_storage::put,
                  np_store,LOCATION_TABLE_NAME, q, pcb); 
  location_serial_queue.add_serial_op(fn); 
} 

void Bindings_Storage::add_loc_cb(const Result & result,
                                  const storage::GUID &guid){
    if(result.code != storage::Result::SUCCESS) 
      lg.err("add_loc_cb NDB error: %s \n", result.message.c_str());

    location_serial_queue.finished_serial_op(); 
}

void Bindings_Storage::remove_name_for_location(const datapathid &dpid, 
            uint16_t port,const string &name, Name::Type name_type) {
 
  storage::Query q;
  int64_t port64 = (name_type == Name::SWITCH) ? Location::NO_PORT : port; 
  
  q["dpid"] = (int64_t) dpid.as_host(); 
 
  if (!(name_type == Name::SWITCH && name == "")) {
    q["port"] = port64; 
    q["name_type"] = (int64_t) name_type; 
    if(name != "") 
      q["name"] = name; 
  } 

  storage::Async_storage::Remove_callback rcb = 
        boost::bind(&Bindings_Storage::remove_loc_cb,this,_1); 

  Serial_Op_fn fn = boost::bind(&Storage_Util::non_trans_remove_all,
                  np_store, LOCATION_TABLE_NAME, q, rcb); 
  location_serial_queue.add_serial_op(fn); 
}

void Bindings_Storage::remove_loc_cb(const Result & result){
    if(result.code != storage::Result::SUCCESS) 
      lg.err("remove_loc_cb NDB error: %s \n", result.message.c_str());
  
    location_serial_queue.finished_serial_op(); 
}

void Bindings_Storage::get_names_for_location(const datapathid &dpid,
              uint16_t port,Name::Type name_type, const Get_names_callback &cb) {
  storage::Query q;
  q["dpid"] = (int64_t) dpid.as_host(); 
  if(name_type == Name::LOCATION || name_type == Name::PORT 
                                 || name_type == Name::LOC_TUPLE) 
      q["port"] = (int64_t) port; 
  else if (name_type == Name::SWITCH) 
      q["port"] = (int64_t) Location::NO_PORT;  
  else { 
    lg.err("invalid name type %d in get_names_for_location\n", (int)name_type); 
    return; 
  }
  if(name_type == Name::LOC_TUPLE) 
    q["name_type"] = (int64_t) Name::LOCATION; 
  else 
    q["name_type"] = (int64_t) name_type; 
  get_names_for_location(q,cb,name_type); 
} 

void Bindings_Storage::get_names_for_location(storage::Query &q, 
                  const Get_names_callback &cb, Name::Type type) {
  Get_LocNames_Op_ptr op = Get_LocNames_Op_ptr(
                            new Get_LocNames_Op(cb,q,type)); 
  np_store->get(LOCATION_TABLE_NAME, q, 
      boost::bind(&Bindings_Storage::get_locnames_cb,this, _1, _2,_3,op)); 
} 

void Bindings_Storage::get_locnames_cb(const Result &result, 
        const Context & ctx, const Row &row, Get_LocNames_Op_ptr op) {
  if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){
        // this call commonly sees concurrent mods when net event log
        // entries are generated due to a datapath leave. 
        if(result.code == storage::Result::CONCURRENT_MODIFICATION) { 
          lg.err("NDB error on get_locnames_cb (ok if transient): %s \n", 
                                result.message.c_str());
        } else {    
          lg.err("NDB error on get_locnames_cb: %s \n", 
                              result.message.c_str());
        } 
        goto do_callback; 
  }

  if(result.code == storage::Result::NO_MORE_ROWS) {
    if( (op->loc_names.size() == 0 && op->type == Name::LOCATION) 
          || op->type == Name::LOC_TUPLE) { 
   
      // continue lookups to find a switch name and port name 
      // if it exists.  First, look for the switch name
      storage::Query switch_query = op->query;
      switch_query["port"] = (int64_t) Location::NO_PORT; 
      switch_query["name_type"] = (int64_t) Name::SWITCH;
      get_names_for_location(switch_query,
          boost::bind(&Bindings_Storage::get_locnames_cb2,this,_1,op),
          Name::SWITCH); 
      return; 
    } else  
      goto do_callback; // all done
  }

  // result.code == SUCCESS
  try {
    string name = Storage_Util::get_col_as_type<string>(row,"name");
    int64_t type = Storage_Util::get_col_as_type<int64_t>(row,"name_type");
    op->loc_names.push_back(Name(name,(Name::Type)type)); 
  } catch (exception &e) {
    // print error but keep trying to read more rows
    lg.err("get_locnames_cb exception: %s \n", e.what()); 
  } 

  np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_locnames_cb,
          this, _1, _2,_3,op));
  return;

do_callback: 
  post(boost::bind(op->callback,op->loc_names)); 
} 

// continuation of look-up for switch-name and port name
void Bindings_Storage::get_locnames_cb2(const NameList &names, 
                                      Get_LocNames_Op_ptr op) {
    string s; 
    if(names.size() > 0) 
      s = names.front().name;
    else { 
      int64_t dp_i = 0;
      try { 
        dp_i = Storage_Util::get_col_as_type<int64_t>(op->query,"dpid");
        // this should no longer happen now that we have a discovered directory
        lg.dbg("failed to find name for switch with dpid = %"PRId64"\n",dp_i);
        datapathid dpid = datapathid::from_host((uint64_t)dp_i); 
        stringstream ss; 
        ss << "none;" << dpid.string(); 
        s = ss.str(); 
        } catch (exception &e) {
          lg.err("get_locnames_cb2 failed to read dpid: %s \n", e.what()); 
      } 
    } 
    storage::Query portname_query = op->query;
    portname_query["name_type"] = (int64_t) Name::PORT; 
    get_names_for_location(portname_query,
        boost::bind(&Bindings_Storage::get_locnames_cb3,this,_1,op,s),
        Name::PORT); 
}



void Bindings_Storage::str_replace(string &str, const string &target,
                                  const string &replace) { 
  size_t pos = 0;
  for (; (pos = str.find(target,pos)) != string::npos;) { 
    str.replace(pos, target.length(), replace); 
    pos += replace.size(); 
  }
} 

// callback for look-up of port name 
void Bindings_Storage::get_locnames_cb3(const NameList &names, 
                          Get_LocNames_Op_ptr op, string switch_name) {
    string portname; 
    if(names.size() > 0) { 
      portname = names.front().name;
    } else {  
      uint16_t port = 0;
      try { 
        port = (uint16_t)
            Storage_Util::get_col_as_type<int64_t>(op->query,"port");
      } catch (exception &e) {
          lg.err("get_locnames_cb3 failed to read port: %s \n", e.what()); 
      } 
      stringstream ss; 
      ss << port; 
      portname = ss.str(); 
    }
    // If no name was found, we want to add a single
    // switchname:port entry to op->loc_names, whether op->type
    // is LOCATION or LOC_TUPLE 
    if(op->loc_names.size() == 0) { 
      stringstream ss;  
      ss << switch_name << ":" << portname;
      op->loc_names.push_back(Name(ss.str(),Name::LOCATION));
    }  

    // Additionally, if the type was LOC_TUPLE, we want to append 
    // "#switch-name#portname" to each entry that is already in 
    // op->loc_names
    if(op->type == Name::LOC_TUPLE) { 
      NameList::iterator it = op->loc_names.begin();
      for( ; it != op->loc_names.end(); ++it) {
        string locname = it->name; 
        str_replace(locname,"\\","\\\\");
        str_replace(locname,"#","\\#");
        str_replace(switch_name,"\\","\\\\");
        str_replace(switch_name,"#","\\#");
        str_replace(portname,"\\","\\\\");
        str_replace(portname,"#","\\#");

        stringstream ss;
        ss << locname << "#" << switch_name << "#" << portname; 
        it->name = ss.str(); 
      } 
    } 
    // all done, do callback 
    post(boost::bind(op->callback,op->loc_names)); 
} 

void Bindings_Storage::get_location_by_name(const string &name, 
    Name::Type name_type, const Get_locations_callback &cb) { 
  Get_Loc_By_Name_Op_ptr op = 
          Get_Loc_By_Name_Op_ptr(new Get_Loc_By_Name_Op(cb)); 
  storage::Query q;
  q["name"] = name; 
  q["name_type"] = (int64_t) name_type; 
  np_store->get(LOCATION_TABLE_NAME, q, 
      boost::bind(&Bindings_Storage::get_loc_by_name_cb,this, _1, _2,_3,op)); 

} 

void Bindings_Storage::get_loc_by_name_cb(const Result &result, 
                const Context & ctx, const Row &row, 
                Get_Loc_By_Name_Op_ptr op) {
  if(result.code != storage::Result::SUCCESS && 
      result.code != storage::Result::NO_MORE_ROWS){ 
        lg.err("NDB error on get_loc_by_name_cb: %s \n", 
            result.message.c_str());
      goto do_callback; 
  }

  if(result.code == storage::Result::NO_MORE_ROWS) {
      goto do_callback; 
  }

  // result.code == SUCCESS
  try {
    int64_t dpid = Storage_Util::get_col_as_type<int64_t>(row,"dpid");
    int64_t port = Storage_Util::get_col_as_type<int64_t>(row,"port");
    op->locations.push_back(Location(datapathid::from_host(dpid),port)); 
  } catch (exception &e) {
    // print error but keep trying to read more rows
    lg.err("get_loc_by_name_cb exception: %s \n", e.what()); 
  } 

  np_store->get_next(ctx, boost::bind(&Bindings_Storage::get_loc_by_name_cb,
          this, _1, _2,_3,op));
  return;

do_callback:
  post(boost::bind(op->callback,op->locations)); 
} 


Disposition
Bindings_Storage::rename_principal(const Event& e) { 
  const Principal_name_event& pn = 
        assert_cast<const Principal_name_event&>(e);
  // if 'newname' is empty, this is a delete event
  // and should be ignored.  Authenticator will 
  // handle the removal of names from bindings storage. 
  // Also, renames with the same name are ignored
  if(pn.newname.length() > 0 && pn.newname != pn.oldname)  
    rename_principal(pn.oldname,pn.newname,pn.type, storage::GUID()); 
  return CONTINUE; 
} 

// 'last_guid' should only be set when this is called from 
// rename_cb.  It is an attempt to detect is storage is 
// incorrectly returning us the same row to modify multiple times
void Bindings_Storage::rename_principal(const string &oldname,
    const string &newname, Directory::Principal_Type type, 
    storage::GUID last_guid){

  storage::Query q;
  string table_name;
  Name::Type name_type; 
  if(type == Directory::HOST_PRINCIPAL) {  
    table_name = NAME_TABLE_NAME;
    name_type = Name::HOST; 
  }else if (type == Directory::USER_PRINCIPAL) { 
    table_name = NAME_TABLE_NAME;
    name_type = Name::USER; 
  }else if (type == Directory::SWITCH_PRINCIPAL) { 
    table_name = LOCATION_TABLE_NAME; 
    name_type = Name::SWITCH; 
  }else if (type == Directory::LOCATION_PRINCIPAL) { 
    table_name = LOCATION_TABLE_NAME; 
    name_type = Name::LOCATION; 
  }else { 
      lg.err("Invalid principal type in rename: %d", type);
      return; 
  }
  q["name"] = oldname; 
  q["name_type"] = (int64_t) name_type;

  np_store->get(table_name, q, boost::bind(&Bindings_Storage::rename_cb,this, 
        _1, _2,_3,oldname,newname,type,"get",last_guid)); 

} 

void Bindings_Storage::rename_cb(const Result &result, 
                const Context & ctx, const Row &row,
                const string &old_name, const string &new_name, 
                Directory::Principal_Type d_type, const string & op_type,
                storage::GUID last_guid) {
  if(result.code == storage::Result::CONCURRENT_MODIFICATION) { 
          lg.err("Retrying after NDB con_mod in rename_cb (op = %s): %s \n", 
                        op_type.c_str(),  result.message.c_str());
          lg.err("old name: '%s' new name '%s'  ptype = %d \n", 
              old_name.c_str(), new_name.c_str(), d_type); 
          lg.err("Not actually retrying to avoid infinite loop\n"); 
//          post(boost::bind(&Bindings_Storage::rename_principal,this,
//                old_name,new_name,d_type)); 
          return; 
  } 
  if(result.code != storage::Result::SUCCESS) {  
      if(result.code != storage::Result::NO_MORE_ROWS) 
        lg.err("NDB error in rename_cb (op = %s): %s \n", 
            op_type.c_str(), result.message.c_str());
      return; // all done
  }

  // result.code == SUCCESS
  Row ignore; 
  if(op_type == "get") { 
    if(last_guid == ctx.current_row.guid) { 
      // shouldn't happen, but better safe then spinning in an 
      // infinite loop.
      lg.err("Rename retry produced the same GUID: %s for oldname '%s'\n",
          last_guid.str().c_str(), old_name.c_str());
      return; 
    }

    // this is a callback from a get() or get_next(). Modify this row
    Row new_row(row);
    new_row["name"] = new_name; 
    np_store->modify(ctx,new_row,boost::bind(&Bindings_Storage::rename_cb,this, 
        _1, ctx,ignore,old_name,new_name,d_type,"modify",ctx.current_row.guid));
  } else if(op_type == "modify") {
    // this is a callback from a modify(), can't call get_next()
    // because that gives an 'index modified' because of the rename.
    // Therefore, we restart the rename operation in case there are any
    // other references to the name in the table.
    rename_principal(old_name,new_name,d_type,last_guid); 
  }else { 
    lg.err("Invalid operation string '%s' in rename_cb",op_type.c_str());
  } 

} 
    
void Bindings_Storage::print_names(const NameList &name_list) {
  if(name_list.size() == 0) 
    printf("[ Empty Name List ] \n"); 

  NameList::const_iterator it = name_list.begin(); 
  for( ; it != name_list.end(); it++) 
    printf("name = %s  type = %d \n", it->name.c_str(), it->name_type); 
  
} 


    

void
Bindings_Storage::getInstance(const container::Context* ctxt,
                           Bindings_Storage*& h) {
    h = dynamic_cast<Bindings_Storage*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(Bindings_Storage).name())));
}

REGISTER_COMPONENT(container::Simple_component_factory<Bindings_Storage>, 
                   Bindings_Storage);


}
} 
