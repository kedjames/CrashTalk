# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================

from collections import defaultdict
import os
import sys
import hashlib
import pprint
import time
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_form_class, describe_DWARF_expr, 
    set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)


class VariableEntry:
    def __init__(self, name, var_type, register, offset, parent, key, 
                mem_addr, param_reg, frame_pointer, filename=None, linenum=None):
        self._name = name
        self._var_type = var_type
        self._register = register
        self._offset = offset
        self._parent = parent
        self._key = key
        self._mem_addr = mem_addr
        self._param_reg = param_reg
        self._frame_pointer = frame_pointer
        self._filename = filename
        self._linenum = linenum
    
    def __str__(self):
        return (f"(Name:{self._name}| Type:{self._var_type} | Reg:{self._register} | "+
                f"Offset:{self._offset} | Parent:{self._parent} | Key:{self._key} | Mem Addr:{hex(self._mem_addr)} | "+
                f"Param Reg:{self._param_reg} | Frame Pointer:{hex(list(self._frame_pointer)[0])})")
    
    def __repr__(self):
        return self.__str__()
    

def _get_module_base(elf_file):
    segment_addrs = [s.header.p_vaddr for s in elf_file.iter_segments()]
    return min(segment_addrs)


def get_key(val, item_dict):
    for key, value in item_dict.items():
         if val == value:
            return key
             
def parse_variable_info(var_list):
    var_tuple  = set([])
    for variable_entry in var_list:
        try:
            var_tuple.add((variable_entry._name, variable_entry._var_type))
        except:
            print("...")
            continue
    return var_tuple

def calc_mem_address(loc_reg, loc_offset, fp_entry, arch, module_base):
    if arch == 64:
        base = 16
    elif arch == 32:
        base = 8
    if loc_reg == None:
        return None
    if ";" in loc_offset.strip():
        loc_offset = loc_offset.strip().split()[0]
        loc_offset = loc_offset.replace(";","")
        
    if loc_reg.strip() == "DW_OP_addr":
        addr = int(loc_offset.strip(),16) + module_base
        return addr 
    elif loc_reg.strip() == "DW_OP_fbreg":     
        for fp_val in fp_entry:
            addr_calc = (int(loc_offset.strip())+base)+fp_val
            return addr_calc
    
def load_variables(binary_path, address_map, taint_path, zelos_module_base):
    start = time.time()
    # print("Parsing Variable info.....")
    with open(binary_path, "rb") as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            return
        symbols_module_base = _get_module_base(elffile)
        bin_offset = zelos_module_base - symbols_module_base
        if bin_offset != 0x1000:  # TODO TEMP for static binaries
            bin_offset = 0
        #print("Got offset: ", bin_offset)
        dwarfinfo = elffile.get_dwarf_info()
        location_lists = dwarfinfo.location_lists()       
        set_global_machine_arch(elffile.get_machine_arch())
        loc_parser = LocationParser(location_lists)
        file_lines = set(address_map.get_file_lines())
        # pprint.pprint(address_map.__str__())
        tainted_funcs = set(taint_path._addr2func.values()) 
        # pprint.pprint(tainted_funcs)
        type_dict = get_variable_type(dwarfinfo)
        var_dict = {}
        var_reg_dict = {}
        reg_dict = {-1:None, 0:"RDI", 1:"RSI", 2:"RDX",3:"RCX", 4:"R8", 5:"R9"}
        parent = None
        count = -1
        reg = None
        low_pc = 0
        fp_entry = None
        for CU in dwarfinfo.iter_CUs():
            # print(f"Processing CU: {CU}")
            for DIE in CU.iter_DIEs():
                try:
                    if DIE.tag == "DW_TAG_subprogram":
                        parent = DIE.attributes['DW_AT_name'].value.decode().strip()
                        low_pc = bin_offset + DIE.attributes['DW_AT_low_pc'].value
                    if DIE.tag == 'DW_TAG_formal_parameter' or DIE.tag == 'DW_TAG_variable':
                        if "DW_AT_external" in DIE.attributes:
                            parent = "Global"
                        # This applies only to X86-X64
                        # Fix that along with the base reg
                        if DIE.tag == 'DW_TAG_formal_parameter':
                            count+=1
                            reg = reg_dict[count]
                        else:
                            count = -1
                        name = DIE.attributes['DW_AT_name'].value.decode()
                        file_num = DIE.attributes['DW_AT_decl_file'].value
                        dec_file = ''
                        dec_line = DIE.attributes['DW_AT_decl_line'].value
                        key = ""
                        attr = DIE.attributes['DW_AT_location']
                        var_type = DIE.attributes['DW_AT_type'].value
                        if var_type not in type_dict:
                            var_type = CU.cu_offset + var_type
                        loc_reg = None
                        loc_offset = "-1"
                        # print(f"=> type: {var_type}") 
                        if type_dict and var_type in type_dict:
                            var_type = type_dict[var_type]
                        if isinstance(var_type,int):
                            var_type = ('Unknown', ('Unknown', "Unknown"))
                        # print(f"=> in type dict {var_type}")                         
                        if loc_parser.attribute_has_location(attr, CU['version']):
                            loc = loc_parser.parse_from_attribute(attr, CU['version'])
                            if isinstance(loc, LocationExpr):
                                loc_str = describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                if "DW_OP" in loc_str:
                                    loc_reg = loc_str.split(":")[0].split("(")[1]                          
                                if loc_reg.strip() == "DW_OP_addr":
                                    loc_offset = loc_str.split(":")[1].split(")")[0]
                                    parent = "Global"
                                elif loc_reg.strip() == "DW_OP_fbreg":
                                    loc_offset = loc_str.split(":")[1].split(")")[0]

                        if parent !="Global":
                            the_key = get_key(parent, taint_path._addr2func)
                            fp_entry = taint_path._dataflow.trace.get_fp(the_key)                                                  
                        if var_type[1] == "Structure":
                            mem_addr = 0
                            parse_struct_type(var_dict,mem_addr,name,var_type, loc_reg, loc_offset, parent,key,reg,fp_entry,elffile,bin_offset,type_dict)
                        elif var_type[0] == "Array":
                            mem_addr = calc_mem_address(loc_reg, loc_offset, fp_entry, elffile.elfclass,bin_offset)
                            if mem_addr in var_dict:
                                var_entry = VariableEntry(name, var_type, loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry)
                                var_dict[mem_addr].append(var_entry)                                                       
                            else:
                                var_entry = VariableEntry(name, var_type, loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry)
                                var_dict[mem_addr] = [var_entry] 
                            parse_array_type(var_dict, mem_addr, name, var_type, loc_reg, loc_offset, parent,key,reg,fp_entry,elffile,bin_offset)
                        else:
                            mem_addr = calc_mem_address(loc_reg, loc_offset, fp_entry, elffile.elfclass,bin_offset)
                            if mem_addr in var_dict: 
                                var_entry = VariableEntry(name, var_type, loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry)
                                var_dict[mem_addr].append(var_entry)                           
                            else:  
                                var_entry = VariableEntry(name, var_type, loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry)
                                var_dict[mem_addr] = [var_entry] 

                except KeyError as e:
                    continue
                except TypeError as e:
                    continue
    end = time.time()
    # print(f"Done parsing variables..... {(end - start)}")
    return var_dict

def parse_array_type(var_dict,mem_addr,name,var_type, loc_reg, loc_offset, parent,key,reg,fp_entry,elffile,bin_offset):
    for inc in range(int(var_type[2])+1):
        if inc == int(var_type[2]):
            name+="-[OB]"
        addr_size = var_type[1]
        try:
            addr_size = int(addr_size[1])
        except:
            continue
        mem_addr = mem_addr+addr_size
        if mem_addr in var_dict:  
            var_entry = VariableEntry(name, var_type, loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry) 
            var_dict[mem_addr].append(var_entry)                         
        else: 
            var_entry = VariableEntry(name, var_type, loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry)
            var_dict[mem_addr] = [var_entry] 

def parse_struct_type(var_dict,mem_addr,name,var_type, loc_reg, loc_offset, parent,key,reg,fp_entry,elffile,bin_offset,type_dict):
    # parse struct base  
    mem_addr = calc_mem_address(loc_reg, loc_offset, fp_entry, elffile.elfclass,bin_offset) 
    if mem_addr in var_dict:                            
        var_entry = VariableEntry(name, var_type[0:2], loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry) 
        var_dict[mem_addr].append(var_entry)
    else:
        var_entry = VariableEntry(name, var_type[0:2], loc_reg, loc_offset, parent, key, mem_addr, reg, fp_entry) 
        var_dict[mem_addr] = [var_entry]
    for member in var_type[3]:
        m_name = member[0]
        m_type = member[2]
        m_loc_offset = member[3]        
        d_type = type_dict[m_type]
        try:
            loc_offset_plus_base =  str(int(loc_offset)+int(m_loc_offset))
            mem_addr = calc_mem_address(loc_reg,loc_offset_plus_base, fp_entry, elffile.elfclass,bin_offset)
            if mem_addr in var_dict:                            
                var_entry = VariableEntry(m_name, d_type, loc_reg, loc_offset_plus_base, parent, key, mem_addr, reg, fp_entry) 
                var_dict[mem_addr].append(var_entry) 
            else:
                var_entry = VariableEntry(m_name, d_type, loc_reg, loc_offset_plus_base, parent, key, mem_addr, reg, fp_entry)
                var_dict[mem_addr] = [var_entry]
            if d_type[0] == "Array":
                parse_array_type(var_dict, mem_addr, m_name, d_type, loc_reg, loc_offset_plus_base, parent,key,reg,fp_entry,elffile,bin_offset)
        except:
            pass


def decode_file_line(dwarfinfo,file_number, target_CU=None):
    try:
        for CU in dwarfinfo.iter_CUs():
            if target_CU != None and CU != target_CU: continue
            lineprog = dwarfinfo.line_program_for_CU(CU)
            prevstate = None
            for entry in lineprog.get_entries():
                if entry.state is None:
                    continue
                return lineprog['file_entry'][file_number-1].name
    except Exception as e:
        return None
    return None


def get_variable_type(dwarfinfo):
    start = time.time()
    # print("Parsing variable type.....")
    type_dict = {}
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == "DW_TAG_subprogram":
                    parent = DIE.attributes['DW_AT_name'].value.decode().strip()
                if DIE.tag == 'DW_TAG_formal_parameter' or DIE.tag == 'DW_TAG_variable':
                    if "DW_AT_external" in DIE.attributes:
                        parent = "Global"
                    name = DIE.attributes['DW_AT_name'].value.decode()
                    var_type = DIE.attributes['DW_AT_type'].value               
                elif  DIE.tag == "DW_TAG_typedef":
                    name = DIE.attributes['DW_AT_name'].value
                    offset = DIE.offset
                    if 'DW_AT_byte_size' in DIE.attributes:
                        size = DIE.attributes['DW_AT_byte_size'].value
                    else:
                        size = -1
                    type_dict[offset] = (name.decode(),size)             
                    
                elif  DIE.tag == "DW_TAG_base_type":
                    name = DIE.attributes['DW_AT_name'].value
                    offset = DIE.offset
                    if 'DW_AT_byte_size' in DIE.attributes:
                        size = DIE.attributes['DW_AT_byte_size'].value
                    else:
                        size = -1
                    type_dict[offset] = (name.decode(),size)
                elif DIE.tag == 'DW_TAG_pointer_type':
                    name = "Pointer"   
                    offset = DIE.offset
                    if 'DW_AT_byte_size' in DIE.attributes:
                        size = DIE.attributes['DW_AT_byte_size'].value
                    else:
                        size = -1
                    var_type = size
                    if 'DW_AT_type' in DIE.attributes:
                        var_type = DIE.attributes['DW_AT_type'].value
                        if var_type in type_dict:
                            size = type_dict[var_type]
                    type_dict[offset] = (name,size)
                elif DIE.tag == "DW_TAG_array_type":
                    name = "Array"
                    size = 0
                    bound = 0
                    offset = DIE.offset
                    sub_range_child = list(DIE.iter_children())[0]
                    if sub_range_child.tag == "DW_TAG_subrange_type":
                        if 'DW_AT_upper_bound' in sub_range_child.attributes:
                            bound = sub_range_child.attributes['DW_AT_upper_bound'].value
                        else:
                            bound = -1
                    if 'DW_AT_type' in DIE.attributes:
                        var_type = DIE.attributes['DW_AT_type'].value
                        if var_type in type_dict:
                            size = type_dict[var_type]
                    type_dict[offset] = (name,size,bound)
                elif DIE.tag == "DW_TAG_structure_type":
                    s_name = DIE.attributes['DW_AT_name'].value.decode()
                    
                    if 'DW_AT_byte_size' in DIE.attributes:
                        size = DIE.attributes['DW_AT_byte_size'].value
                    else:
                        size = -1
                    offset = DIE.offset
                    member_list = []
                    for child in DIE.iter_children():
                        m_name = ""
                        m_var_type = ""
                        m_offset = ""
                        m_location = ""
                        if child.tag == "DW_TAG_member":
                            m_name = child.attributes['DW_AT_name'].value.decode()
                            m_offset = child.attributes['DW_AT_name'].offset
                            if 'DW_AT_type' in child.attributes:
                                m_var_type = child.attributes['DW_AT_type'].value
                            if 'DW_AT_data_member_location' in child.attributes:
                                m_location = child.attributes['DW_AT_data_member_location'].value
                                m_tuple = (m_name, m_offset-1, m_var_type, m_location)
                                member_list.append(m_tuple)
                    type_dict[offset] = (s_name, "Structure", size, member_list)
            except Exception as e:
                # print("Error "+str(e))
                continue
    end = time.time()
    return type_dict