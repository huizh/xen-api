(*
 * Copyright (C) 2006-2009 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)
(** Code for dealing with data read from the guest agent (via xenstore).
    Note this only deals with relatively static data (like version numbers) and
    not dynamic performance data. *)

open Fun
open Hashtblext
open Stringext
open Threadext

module D=Debug.Debugger(struct let name="xapi_guest_metrics" end)
open D

module IntSet = Set.Make(struct type t=int let compare=compare end)

(* A fixed set of standard keys are placed in the PV_drivers_version map.
   NB each key is annotated with whether it appears in windows and/or linux *)
let pv_drivers_version = 
  [ "drivers/xenevtchn",          "xenevtchn";   (* windows *)
    "drivers/xenvbd",             "xenvbd";      (* windows *)
    "drivers/xennet",             "xennet";      (* windows *)
    "attr/PVAddons/MajorVersion", "major";       (* linux + windows *)
    "attr/PVAddons/MinorVersion", "minor";       (* linux + windows *)
    "attr/PVAddons/MicroVersion", "micro";       (* linux + windows -- added in Miami Beta2 *)
    "attr/PVAddons/BuildVersion", "build";       (* windows *)
    "attr/PVAddons/Application",  "application"; (* linux *)
  ]

(* A fixed set of standard keys placed in the os_version map. *)
let os_version = 
  [ "data/os_name",               "name";        (* linux + windows *)
    "data/os_uname",              "uname";       (* linux *)
    "data/os_distro",             "distro";      (* linux + windows *)
    "data/os_majorver",           "major";       (* linux + windows *)
    "data/os_minorver",           "minor";       (* linux + windows *)
    "attr/os/spmajor",            "spmajor";     (* windows *)
    "attr/os/spminor",            "spminor";     (* windows *)
  ]

let memory = 
  [ "data/meminfo_free", "free";
    "data/meminfo_total", "total"
  ]

let device_id = [ "data/device_id", "device_id"]

(* This function is passed the 'attr' node and a function it can use to
 * find the directory listing of sub-nodes. It will return a map where the
 * keys are the xenstore paths of the VM's IP addresses, and the values are
 * the intended keys which will go into the VM_guest_metrics.networks field.
 * Example output for a single vif might be:
 * attr/eth0/ip -> 0/ip
 * attr/eth0/ipv6/0/addr -> 0/ipv6/0
 * attr/eth0/ipv6/1/addr -> 0/ipv6/1
 * *)
let networks path (list: string -> string list) =
	let extend base str = Printf.sprintf "%s/%s" base str in
	(* Find all ipv6 addresses under a path. *)
	let find_ipv6 path prefix = List.map
		(fun str -> (extend (extend path str) "addr", extend prefix str))
		(list path)
	in
	(* Find the ipv4 address under a path, and the ipv6 addresses if they exist. *)
	let find_all_ips path prefix =
		let ipv4 = (extend path "ip", extend prefix "ip") in
		if List.mem "ipv6" (list path) then
			ipv4 :: (find_ipv6 (extend path "ipv6") (extend prefix "ipv6"))
		else
			[ipv4]
	in
	(* Find all "ethn" or "xenbrn" under a path. *)
	let find_eths path = List.fold_left
		(fun acc eth ->
			if String.startswith "eth" eth then
				let n = String.sub eth 3 (String.length eth - 3) in
				(extend path eth, n) :: acc
			else if String.startswith "xenbr" eth then
				let n = String.sub eth 5 (String.length eth - 5) in
				(extend path eth, n) :: acc
			else
				acc)
		[] (list path)
	in
	path
		|> find_eths
		|> List.map (fun (path, prefix) -> find_all_ips path prefix)
		|> List.concat

(* This function is passed the "device/vif" node and a function it can use to
 * find the directory listing of sub-nodes. It will return a map where the
 * keys are the xenstore paths of the VIFs' states, and the values are
 * the corresponding state values.
 * Example output for two vifs might be:
 * 0/state -> 4
 * 1/state -> 4
 * *)
let vif_state path (list: string -> string list) =
	let extend base str = Printf.sprintf "%s/%s" base str in
	(* Find all state(s) of vif(s) under a path. *)
	let find_vifs path = List.fold_left
		(fun acc vif -> (extend (extend path vif) "state", extend vif "state") :: acc)
		[] (list path)
	in
	path
		|> find_vifs

(* This function is passed the "device/vbd" node and a function it can use to
 * find the directory listing of sub-nodes. It will return a map where the
 * keys are the xenstore paths of the VBDs' state and device-type, and
 * the values are the corresponding state and device-type values.
 * Example output for two vbds might be:
 * 5696/state -> 1
 * 5696/device-type -> cdrom
 * 768/state -> 4
 * 768/device-type -> disk
 * *)
let vbd_state path (list: string -> string list) =
	let extend base str = Printf.sprintf "%s/%s" base str in
	(* Find all state(s) and device-type(s) of vbd(s) under a path. *)
	let find_vbds path = List.fold_left
		(fun acc vbd -> (extend (extend path vbd) "state", extend vbd "state") 
			:: (extend (extend path vbd) "device-type", extend vbd "device-type")
			:: acc)
		[] (list path)
	in
	path
		|> find_vbds

(* One key is placed in the other map per control/* key in xenstore. This
   catches keys like "feature-shutdown" "feature-hibernate" "feature-reboot"
   "feature-sysrq" *)
let other all_control = 
  List.map (fun x -> "control/" ^ x, x) all_control

(* There are two memory keys: data/meminfo_free and data/meminfo_total. These are *)
(* inserted into the memory map with the keys 'free' and 'total' *)

(** Cache the results so that we only actually update the master's database when
    the results of these lookups differ *)

type m = (string * string) list
let cache : (int, (m*m*m*m*m*m*m*m*float)) Hashtbl.t = Hashtbl.create 20
let memory_targets : (int, int64) Hashtbl.t = Hashtbl.create 20
let dead_domains : IntSet.t ref = ref IntSet.empty
let mutex = Mutex.create ()

(** Reset all the guest metrics for a particular VM. 'lookup' reads a key from xenstore
    and 'list' reads a directory from xenstore. Both are relative to the guest's 
    domainpath. *)
let all (lookup: string -> string option) (list: string -> string list) ~__context ~domid ~uuid =
  let all_control = list "control" in
  let to_map kvpairs = List.concat (List.map (fun (xskey, mapkey) -> match lookup xskey with
    | Some xsval -> [ mapkey, xsval ]
    | None -> []) kvpairs) in

  let pv_drivers_version = to_map pv_drivers_version
  and os_version = to_map os_version
  and device_id = to_map device_id
  and networks = to_map (networks "attr" list)
  and other = to_map (other all_control)
  and memory = to_map memory
  and vif_state = to_map (vif_state "device/vif" list)
  and vbd_state = to_map (vbd_state "device/vbd" list)
  and last_updated = Unix.gettimeofday () in

  (* let num = Mutex.execute mutex (fun () -> Hashtbl.fold (fun _ _ c -> 1 + c) cache 0) in 
  debug "Number of entries in hashtbl: %d" num; *)

  (* to avoid breakage whilst 'micro' is added to linux and windows agents, default this field
     to -1 if it's not present in xenstore *)
  let pv_drivers_version =
    if List.mem_assoc "micro" pv_drivers_version then pv_drivers_version (* already there; do nothing *)
    else ("micro","-1")::pv_drivers_version in

  let self = Db.VM.get_by_uuid ~__context ~uuid in

  let (
    pv_drivers_version_cached,
    os_version_cached,
    networks_cached,
    other_cached,
    memory_cached,
    device_id_cached,
    vif_state_cached,
    vbd_state_cached,
    last_updated_cached
  ) = Mutex.execute mutex (fun () -> try
       Hashtbl.find cache domid 
    with _ -> 
      (* Make sure our cached idea of whether the domain is live or not is correct *)
      let vm_guest_metrics = Db.VM.get_guest_metrics ~__context ~self in
	  let live = true
		&& Db.is_valid_ref __context vm_guest_metrics 
		&& Db.VM_guest_metrics.get_live ~__context ~self:vm_guest_metrics in
      if live then
	dead_domains := IntSet.remove domid !dead_domains
      else
	dead_domains := IntSet.add domid !dead_domains;
      ([],[],[],[],[],[],[],[],0.0)) in

  (* Consider the data valid IF the data/updated key exists AND the pv_drivers_version map
     contains a major and minor version-- this prevents a migration mid-way through an update
     making us think the PV drivers are missing. Note we may still experience glitches in other
     fields like IP addresses. Alternatives to this include:
     * insist guest agents write everything transactionally
     * copy the xenstore tree in the critical downtime period during a migration
     * chmod RO the xenstore tree pre-migration, copy pre-migration and be prepared to unwind
  *)
  let data_updated = lookup "data/updated" <> None in
  if (
	  true
	  && data_updated
	  && List.mem_assoc "major" pv_drivers_version
	  && List.mem_assoc "minor" pv_drivers_version
  )
  then begin

      (* Only if the data is valid, cache it (CA-20353) *)
      Mutex.execute mutex (fun () -> Hashtbl.replace cache domid (pv_drivers_version,os_version,networks,other,memory,device_id,vif_state,vbd_state,last_updated));

      (* We update only if any actual data has changed *)
      if ( pv_drivers_version_cached <> pv_drivers_version 
	   ||
	   os_version_cached <> os_version
	   ||
	   networks_cached <> networks 
	   ||
	   other_cached <> other
     ||
     device_id_cached <> device_id
     ||
     vif_state_cached <> vif_state
     ||
     vbd_state_cached <> vbd_state)
(* Nb. we're ignoring the memory updates as far as the VM_guest_metrics API object is concerned. We are putting them into an RRD instead *)
(*	   ||
	   memory_cached <> memory)*)
      then 
	begin
     	  let gm = 
	    let existing = Db.VM.get_guest_metrics ~__context ~self in
	    if (try ignore(Db.VM_guest_metrics.get_uuid ~__context ~self:existing); true with _ -> false)
	    then existing
	    else 
	      (* if it doesn't exist, make a fresh one *)
	      let new_ref = Ref.make () and new_uuid = Uuid.to_string (Uuid.make_uuid ()) in
	      Db.VM_guest_metrics.create ~__context ~ref:new_ref ~uuid:new_uuid
		~os_version:os_version ~pV_drivers_version:pv_drivers_version ~pV_drivers_up_to_date:false ~memory:[] ~disks:[] ~networks:networks ~other:other
		~storages_path_optimized:false ~networks_path_optimized:false ~last_updated:(Date.of_float last_updated) ~other_config:[] ~live:true;
	      Db.VM.set_guest_metrics ~__context ~self ~value:new_ref; 
	      (* We've just set the thing to live, let's make sure it's not in the dead list *)
		  let sl xs = String.concat "; " (List.map (fun (k, v) -> k ^ ": " ^ v) xs) in
		  info "Received initial update from guest agent in VM %s; os_version = [ %s]; pv_drivers_version = [ %s ]; networks = [ %s ]; vif_state = [ %s ]; vbd_state = [ %s ]"
		  		(Ref.string_of self) (sl os_version) (sl pv_drivers_version) (sl networks) (sl vif_state) (sl vbd_state);
	      Mutex.execute mutex (fun () -> dead_domains := IntSet.remove domid !dead_domains);
	      new_ref in

	  (* We unconditionally reset the database values but observe that the database
	     checks whether a value has actually changed before doing anything *)
	  if(pv_drivers_version_cached <> pv_drivers_version) then
	    Db.VM_guest_metrics.set_PV_drivers_version ~__context ~self:gm ~value:pv_drivers_version;
	  if(os_version_cached <> os_version) then
	    Db.VM_guest_metrics.set_os_version ~__context ~self:gm ~value:os_version;
	  if(networks_cached <> networks) then
	    Db.VM_guest_metrics.set_networks ~__context ~self:gm ~value:networks;
	  if(other_cached <> other) then begin
	    Db.VM_guest_metrics.set_other ~__context ~self:gm ~value:other;
	    Helpers.call_api_functions ~__context (fun rpc session_id -> Client.Client.VM.update_allowed_operations rpc session_id self);
	  end;
	  if(vif_state_cached <> vif_state) then begin
	  	(* If state of all the VIFs are 4, then the networks path are optimized. *)
	  	let networks_path_optimized = List.for_all (fun (k, v) -> v = "4") vif_state in
	  	Db.VM_guest_metrics.set_networks_path_optimized ~__context ~self:gm ~value:networks_path_optimized;
	  end;
	  if(vbd_state_cached <> vbd_state) then begin
	  	(* Except cdrom, if state of all the VBDs are 4, then the storages path are optimized. *)
	  	let vbd_cdrom = List.filter (fun (k, v) -> v = "cdrom") vbd_state in
	  	let (vbd_cdrom_key, _) = List.split vbd_cdrom in
	  	let vbd_cdrom_id = List.map (fun k -> String.sub k 0 (String.length k - String.length "/device-type")) vbd_cdrom_key in
	  	let vbd_except_device_type = List.filter (fun (k, v) -> not(String.endswith "/device-type" k)) vbd_state in
	  	let vbd_state_except_cdrom = List.concat(List.fold_left (
	  		fun acc id ->
	  		List.filter (fun (k, v) -> not(String.startswith (id ^ "/") k)) vbd_except_device_type
	  		:: acc
	  	) [] vbd_cdrom_id) in
	  	let storages_path_optimized = List.for_all (fun (k, v) -> v = "4") vbd_state_except_cdrom in
	  	Db.VM_guest_metrics.set_storages_path_optimized ~__context ~self:gm ~value:storages_path_optimized;
	  end;
(*	  if(memory_cached <> memory) then
	    Db.VM_guest_metrics.set_memory ~__context ~self:gm ~value:memory; *)
	  
	  Db.VM_guest_metrics.set_last_updated ~__context ~self:gm ~value:(Date.of_float last_updated);
	  
    if(device_id_cached <> device_id) then begin
      if(List.mem_assoc Xapi_globs.device_id_key_name device_id) then begin
        let value = List.assoc Xapi_globs.device_id_key_name device_id in
        let platform = Db.VM.get_platform ~__context ~self in
				info "Updating VM %s platform:%s <- %s" (Ref.string_of self) Xapi_globs.device_id_key_name value;
				if List.mem_assoc Xapi_globs.device_id_key_name platform then
					(try
						Db.VM.remove_from_platform ~__context ~self ~key:Xapi_globs.device_id_key_name
					with _ -> ());
				try
					Db.VM.add_to_platform ~__context ~self ~key:Xapi_globs.device_id_key_name ~value:value;
				with _ -> ()
      end
    end;

	  (* Update the 'up to date' flag afterwards *)
	  (* Only when both networks and disks paths are optimized, the 'up to date' flag is set to true. *)
	  let up_to_date = Db.VM_guest_metrics.get_storages_path_optimized ~__context ~self:gm &&
	                   Db.VM_guest_metrics.get_networks_path_optimized ~__context ~self:gm in
	  Db.VM_guest_metrics.set_PV_drivers_up_to_date ~__context ~self:gm ~value:up_to_date;

	  (* CA-18034: If viridian flag isn't in there and we have current PV drivers then shove it in the metadata for next boot... *)
	  if up_to_date then begin
		  let platform = Db.VM.get_platform ~__context ~self in
		  if not(List.mem_assoc Xapi_globs.viridian_key_name platform) then begin
			  info "Setting VM %s platform:%s <- %s" (Ref.string_of self) Xapi_globs.viridian_key_name Xapi_globs.default_viridian_key_value;
			  try
				  Db.VM.add_to_platform ~__context ~self ~key:Xapi_globs.viridian_key_name ~value:Xapi_globs.default_viridian_key_value;
			  with _ -> ()
		  end
	  end;

	  (* We base some of our allowed-operations decisions on the PV driver version *)
	  if pv_drivers_version_cached <> pv_drivers_version then begin
	    Xapi_vm_lifecycle.update_allowed_operations ~__context ~self;
	    List.iter (fun self -> Xapi_vbd_helpers.update_allowed_operations ~__context ~self)
	      (Db.VM.get_VBDs ~__context ~self);
	    List.iter (fun self -> Xapi_vif_helpers.update_allowed_operations ~__context ~self)
	      (Db.VM.get_VIFs ~__context ~self);
	  end;	  
	end (* else debug "Ignored spurious guest agent update" *)
  end
  else if (data_updated && other_cached <> other) then (
	  (* For HVM Linux without guest agent we need to update "other" even if nothing else has changed. *)
	  (* The code to below is based on a copy of the block above, but updates only
	   * the "other" map. TODO consider refactoring rather than have this block similar to the one above. *)

	  (* Update only the "other" and "last_updated" fields of the cache *)
	  Mutex.execute mutex (fun () -> Hashtbl.replace cache domid (
		  pv_drivers_version_cached,
		  os_version_cached,
		  networks_cached,
		  other, (* not the cached version *)
		  memory_cached,
		  device_id_cached,
		  vif_state_cached,
		  vbd_state_cached,
		  last_updated)); (* not a cached version *)

	  let gm =
		  let existing = Db.VM.get_guest_metrics ~__context ~self in
		  if (try ignore(Db.VM_guest_metrics.get_uuid ~__context ~self:existing); true with _ -> false)
		  then existing
		  else
			  (* if it doesn't exist, make a fresh one using cached or blank data except for "other" map *)
			  let new_ref = Ref.make () and new_uuid = Uuid.to_string (Uuid.make_uuid ()) in
			  Db.VM_guest_metrics.create ~__context ~ref:new_ref ~uuid:new_uuid
				  ~os_version:os_version_cached
				  ~pV_drivers_version:pv_drivers_version_cached
				  ~pV_drivers_up_to_date:false
				  ~memory:[]
				  ~disks:[]
				  ~networks:networks_cached
				  ~other:other
				  ~storages_path_optimized:false
				  ~networks_path_optimized:false
				  ~last_updated:(Date.of_float last_updated)
				  ~other_config:[]
				  ~live:false;
			  Db.VM.set_guest_metrics ~__context ~self ~value:new_ref; 
			  (* We've just set the thing to dead (no guest agent). Now ensure it's in the dead list *)
			  let sl xs = String.concat "; " (List.map (fun (k, v) -> k ^ ": " ^ v) xs) in
			  info "Received initial update (but no PV driver version) about VM %s; os_version = [ %s]; other = [ %s ]; pv_drivers_version = [ %s ]; networks = [ %s ]; vif_state = [ %s ]; vbd_state = [ %s ]"
			  		(Ref.string_of self) (sl os_version) (sl other) (sl pv_drivers_version) (sl networks) (sl vif_state) (sl vbd_state);
			  Mutex.execute mutex (fun () -> dead_domains := IntSet.add domid !dead_domains);
			  (* Update cache with the empty memory item we've just put into the new guest metrics record. *)
			  Mutex.execute mutex (fun () -> Hashtbl.replace cache domid (
				  pv_drivers_version_cached,
				  os_version_cached,
				  networks_cached,
				  other, (* current version *)
				  [], (* memory *)
				  device_id_cached,
				  vif_state_cached,
				  vbd_state_cached,
				  last_updated)); (* not a cached version *)
			  new_ref
	  in

	  Db.VM_guest_metrics.set_other ~__context ~self:gm ~value:other;
	  Helpers.call_api_functions ~__context (fun rpc session_id -> Client.Client.VM.update_allowed_operations rpc session_id self);

	  Db.VM_guest_metrics.set_last_updated ~__context ~self:gm ~value:(Date.of_float last_updated);

	  (* We base some of our allowed-operations decisions on the feature-flags in the "other" map *)
	  Xapi_vm_lifecycle.update_allowed_operations ~__context ~self;
	  List.iter (fun self -> Xapi_vbd_helpers.update_allowed_operations ~__context ~self)
		  (Db.VM.get_VBDs ~__context ~self);
	  List.iter (fun self -> Xapi_vif_helpers.update_allowed_operations ~__context ~self)
		  (Db.VM.get_VIFs ~__context ~self);
	  ()
  )

(* XXX This function was previously called in the monitoring loop of the
 * RRD-related code, but that code has now been moved into rrdd, so there
 * is currently no caller. It probably needs to be called from whereever
 * the fields in this file are used. *)
let sync_cache valid_domids =
	Mutex.execute mutex
		(fun _ ->
			let stored_domids = Hashtbl.fold (fun k v acc -> k::acc) cache [] in
			List.iter (fun domid -> if not (List.mem domid valid_domids) then dead_domains := IntSet.remove domid !dead_domains) stored_domids;
			Hashtbl.remove_other_keys cache valid_domids;
		)
