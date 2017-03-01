(*
 * Copyright (C) 2006-2016 Citrix Systems Inc.
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

open Stdext
open Pervasiveext
open Xstringext
open Helpers
open Listext
open Client
open Stdext.Threadext
open Unixext

module D = Debug.Make(struct let name="xapi" end)
open D


let introduce ~__context ~protocol ~address ~port =
  let dbg = Context.string_of_task __context in
  match Net.Bridge.get_kind dbg () with
  | Network_interface.Openvswitch ->
    let pool = Helpers.get_pool ~__context in
    let current_address = Db.Pool.get_vswitch_controller ~__context ~self:pool in
    if current_address <> address then begin
      if address <> "" then
        Helpers.assert_is_valid_ip `ipv4 "address" address;
      Db.Pool.set_vswitch_controller ~__context ~self:pool ~value:address;
      List.iter (fun host -> Helpers.update_vswitch_controller ~__context ~host) (Db.Host.get_all ~__context)
    end
  | _ -> raise (Api_errors.Server_error(Api_errors.operation_not_allowed, ["host not configured for vswitch operation"]))



let forget ~__context ~self =