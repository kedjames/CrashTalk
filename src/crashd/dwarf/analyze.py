# Copyright (C) 2024 Zeropoint Dynamics

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
from termcolor import colored
import os
import sys
import html
import hashlib
import pprint
import hashlib
import json
import re
import time
import pandas as pd
from pathlib import Path
from typing import Optional
from crashd.taint.render.graphviz import render_source_graph
from crashd.dwarf.helpers import get_nodes_and_edges, _construct_zcov_files
from crashd.taint.taint_graph import TaintGraph
from crashd.dwarf.dwarf_data import DwarfData
from crashd.dwarf.variable_data import load_variables, parse_variable_info
from zelos.exceptions import MemoryReadUnmapped
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_form_class, describe_DWARF_expr, 
    set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
from prettytable import PrettyTable, ALL 


class Analysis:
    def __init__(self, zelos, binary_path, dataflow, zelos_module_base, inst_address, mem_address=None, access=None):
        self.logger = dataflow.logger
        self._zelos = zelos
        self._binary_path = binary_path
        self._source_code_path = zelos.config.source_code_path
        self._dataflow = dataflow
        self._zelos_module_base = zelos_module_base
        self._inst_address = inst_address
        self._mem_address = mem_address
        self._access = access
        self._trace = dataflow.trace._trace
        self._asan_config = zelos.config.asan
        self._asan_plugin_handle = zelos.plugins.asan
        self._guard_mem_addr = None
        self._reason = None
        self._out_of_bounds = None
        self._access_size = None
        self._c_alloc_info = None
        self._taint_path = None
        self._dwarf_data = None 
        self._address_map  = None  
        self._operation = None
        self._files  = None
        self._variable_info = None
        self._stage = None
        self._owners = None
        self._addr2func = None
        self.crash_dict = None
        self.value_to_addr = None
        self.NPD_change_index = None
        self.change_index = None
        self.is_arith_error = False
        self.html_desc = None
      
    def init_crash_data(self):
        self.logger.info("[+]Parsing DWARF info from analysis...")
        if self._asan_config:
            self._dwarf_data = self._asan_plugin_handle.get_dwarf_data()
        
        if self._dwarf_data is None:
            self._dwarf_data = DwarfData(self._binary_path, self._source_code_path, self._zelos_module_base)
            
        self._dwarf_data.attach_src_to_external_addrs(self._trace)
        self._files = self._dwarf_data._file_lines
        self._file_to_syspath = self._dwarf_data._file_to_syspath
        self._address_map = self._dwarf_data._address_map 
        
        if self._asan_config and self._asan_plugin_handle.asan_guard_triggered:
            # print("guard triggered")
            self._guard_mem_addr = self._asan_plugin_handle.get_crash_info().mem_address
            self._reason = self._asan_plugin_handle.get_crash_info().reason
            self._c_alloc_info =  self._asan_plugin_handle.get_crash_info().alloc_info        
            self._out_of_bounds = self._asan_plugin_handle.get_crash_info().out_of_bounds
            self._access_size = self._asan_plugin_handle.get_crash_info().mem_access_size
            self._operation = self._asan_plugin_handle.get_crash_info().operation
            if self._reason == "heap-overflow":
                self.logger.info("[+]Creating source taint graph...") 
                self._taint_path = TaintGraph(self._dataflow, self._inst_address)
            elif self._reason == "heap-use-after-free":
                self.logger.info("[+]Creating source taint graph...") 
                self._taint_path = TaintGraph(self._dataflow, self._inst_address)
            elif self._reason == "double-free":
                self._inst_address = self.get_last_line_low_addr()
                self._owners = self.get_owners(self._c_alloc_info.address)
                self.logger.info("[+]Creating source taint graph...")                
                self._taint_path = TaintGraph(self._dataflow,  self._inst_address)
            elif self._reason == "stack-buffer-overflow":
                self._inst_address = self.get_last_line_low_addr()
                self.logger.info("[+]Creating source taint graph...") 
                self._taint_path = TaintGraph(self._dataflow, self._inst_address,self._mem_address)
        else:
            if self._mem_address == 0:
                self._reason = "null-pointer-dereference" 
            else:
                self._reason = "stack-buffer-overflow"
            self.logger.info("[+]Creating source taint graph...")
            self._taint_path = TaintGraph(self._dataflow, self._inst_address, self._mem_address) 
            # self._taint_path = TaintGraph(self._dataflow, self._inst_address)
        self._taint_path._dwarf_data = self._dwarf_data
        self._taint_path._addr2func = self._dwarf_data.get_function_info(self._taint_path)
        self._taint_path._dwarf_data._variable_info = load_variables(self._binary_path, 
                                                            self._taint_path._dwarf_data._address_map, 
                                                            self._taint_path, self._zelos_module_base)  
        self.logger.info("[+]Done parsing DWARFT in analyze..")  
       
    def construct_zcov(self):
        # print("Constructing zcov file...")
        trace = self._trace 
        files = self._files
        taint_path = self._taint_path
        file_to_syspath = self._file_to_syspath
        (nodes, edges) = get_nodes_and_edges(taint_path, self._address_map)
        if len(file_to_syspath) > 0:
            _construct_zcov_files(
                taint_path,
                self._address_map,
                trace,
                edges,
                files,
                file_to_syspath,
                self._source_code_path, self.html_desc
            )
            
    def get_taint_path(self):
        return self._taint_path,  self._address_map, self._files
    
    def get_reason(self):
        return self._reason
    
    def get_last_line_low_addr(self):
        count = -1
        last_line = list(self._dwarf_data._addr2source.items())[count][1].split("=>")[0].strip()
        while(last_line == "{" or last_line == "}" 
              or last_line == "within {" 
              or last_line == "within }"):
            count-=1
            last_line = list(self._dwarf_data._addr2source.items())[count][1].split("=>")[0].strip() 
        last_line = list(self._dwarf_data._addr2source.items())[count][1].split("=>")[1].strip()  
        last_line = last_line.split(":")
        addr_low, addr_high = self._address_map.get_addr_range_from_source(last_line[0], int(last_line[1]))
        return addr_low
      
    def diagnose_crash(self, tp=None, stage=None):  
        self._stage = stage
        files =  self._files  
        if tp == None:
            taint_path  = self._taint_path 
        else:
            taint_path = tp
        trace = self._trace    
        file_to_syspath =  self._file_to_syspath
        render_source_graph(taint_path, self._address_map, files)  
        html_desc = None  
        if tp!=None:    
            html_desc = self.associate_taint_source(tp)
        else:
            html_desc = self.associate_taint_source()
        
        # self.construct_zcov()
        if not self._zelos.config.taint_output == "terminal":
            return
        # print("generated .zcov file")
        crash_line = None
        source_path = {}
        changed_file_lines = defaultdict(list)
        key_list = []
        use_def_lines = {}   
        for k, v in taint_path.reduced_path.items():
            k_addr = k
            file, line = self._address_map.get(k_addr, (None, None))
            source_path[(file, line)] = v
            # print(str(v))
            if file is not None and line is not None:
                key_list.append((file,line))

            if file in files:
                if crash_line is None:
                    files[file][line] = colored(
                        f"!0x{k:x}" +
                        files[file][line] + str(v) + "\n",
                        color="red",
                    )
                    files[file][line] = files[file][line] + str(v) + "\n"
                    crash_line = line
                    changed_file_lines[file].append(line)
                else:
                    files[file][line] = colored(
                        f"*0x{k:x}" +
                        files[file][line] + str(v) + "\n",
                        color="green",
                        attrs=["bold"],
                    )
                    files[file][line] = files[file][line] + str(v) + "\n"
                    changed_file_lines[file].append(line)
                   

        count = 0
        for addr in reversed(trace):
            file, line = self._address_map.get(addr, (None, None))
            if file not in files:
                continue
            if line == crash_line:
                break
            files[file][line] = colored(
                files[file][line] + f" Count: {count}\n",
                color="green",
                attrs=["bold"],
            )
            changed_file_lines[file].append(line)
            count += 1

        if len(changed_file_lines) == 0:
            print(
                "There are no lines in source that correspond to the taint path."
                " There may have been a bug."
            )

        for path, lines in files.items():
            if path not in changed_file_lines:
                continue
            idxes = changed_file_lines[path]
            #print(path, idxes)
            lines_to_print = []
            indices_chosen = set()
            context = 3
            for idx in reversed(idxes):
                i = idx - context
                while i < idx + context + 1:
                    if i < 0 or i >= len(lines):
                        i += 1
                        continue
                    if i in indices_chosen:
                        i += 1
                        continue
                    if i > idx and i in idxes:
                        idx = i
                    lines_to_print.append(lines[i])
                    indices_chosen.add(i)
                    i += 1
                if lines_to_print[-1] != "...\n":
                    lines_to_print.append("...\n")
        return self._taint_path

    def associate_taint_source(self, tp=None):
        def_use_line = {}  
        count = 0
        crash_addr = 0
        crash_val = 0
        to_track = True
        track_line = set([])
        table = PrettyTable()
        table.hrules=ALL
        col_names = ["Use Line", "Defined Line","Func", "Mem/Reg","Value","Variable","Comment"]
        table.field_names = col_names 
        rows = []
        variable_dict = self._taint_path._dwarf_data._variable_info
        var_entry = None
        value_to_addr = {}
        if tp == None:
            # print("None")
            taint_path  = self._taint_path 
        else:
            taint_path = tp
        for def_addr, value in taint_path.reduced_path.items():
            if not value: continue
            node =  list(value.values())[0]
            use_addr = list(value.keys())[0]
            if count == 0:
                crash_addr = use_addr
            if node.val == -1 and node.use == -1: continue
            def_file, def_line = self._address_map.get(def_addr, (None, None))
            if def_file is not None and def_line is not None:
                def_file_line = def_file+':'+str(def_line+1)
                actual_def_line = self._files[def_file][def_line]
            use_file, use_line = self._address_map.get(use_addr, (None, None))
            if use_file is not None and use_line is not None:
                actual_use_line  = self._files[use_file][use_line]
                use_file_line = use_file+':'+str(use_line+1)
                
                if actual_def_line  == actual_use_line: continue
                if def_addr in taint_path._addr2func:
                    def_func = taint_path._addr2func[int(def_addr)]
                else:
                    def_func = 'unknown'
                if use_addr in  taint_path._addr2func:
                    use_func = taint_path._addr2func[int(use_addr)]
                else:
                    use_func = 'unknown'
                val_list = []
                use_type = []
                var_info = "   "
                comment = "-=-=-"
                for node in list(value.values()) :  
                    if use_addr == crash_addr:
                        if isinstance(node.use, int): 
                            if node.use in variable_dict:
                                var_info = parse_variable_info(variable_dict[node.use])
                            val_list.append(str(hex(self._mem_address)))
                            use_type.append(str(hex(node.use)))
                        else:
                            val_list.append(str(hex(self._mem_address)))
                            use_type.append(str(node.use))
                        crash_val = hex(int(val_list[0].replace("*","").strip(),16))
                        use_line_info = use_file_line+" => "+actual_use_line.strip()
                        def_line_info = def_file_line+" => "+actual_def_line.strip()
                        
                        if "malloc" in actual_def_line.strip().lower() or "realloc" in actual_def_line.strip().lower() or "calloc" in actual_def_line.strip().lower():
                            tmp_alloc_addr = node.val.replace("*","").strip()
                            if tmp_alloc_addr in value_to_addr:
                                value_to_addr[tmp_alloc_addr].append([def_addr,def_file_line.strip(),actual_def_line.strip(),node.use, var_info,count])
                            else:
                                value_to_addr[tmp_alloc_addr] = [def_addr,def_file_line.strip(),actual_def_line.strip(),node.use, var_info,count]
                                
                        row = [use_line_info, def_line_info,(use_func,def_func),"\n".join(use_type),"\n".join(val_list),var_info,"Crash Point"]
                    else:
                        if isinstance(node.use, int):                          
                            if node.use in variable_dict:
                                var_info = parse_variable_info(variable_dict[node.use])
                            val_list.append(str(node.val))
                            use_type.append(str(hex(node.use)))
                            
                        else:
                            val_list.append(str(node.val))
                            use_type.append(str(node.use)) 
                        if "malloc" in actual_def_line.strip().lower() or "realloc" in actual_def_line.strip().lower() or "calloc" in actual_def_line.strip().lower():
                            tmp_alloc_addr = node.val.replace("*","").strip()
                            if tmp_alloc_addr in value_to_addr:
                                value_to_addr[tmp_alloc_addr].append([def_addr,def_file_line.strip(),actual_def_line.strip(),node.use, var_info,count])
                            else:
                                value_to_addr[tmp_alloc_addr] = [def_addr,def_file_line.strip(),actual_def_line.strip(),node.use, var_info,count]
                        if to_track :
                            for item in val_list:
                                if "b'" in item : continue
                                if int(str(crash_val),16) != int(item.replace("*",""),16):
                                    comment = "<=="   
                                    if int(str(crash_val),16) == 0 and rows:
                                        blamed_val = rows[-1]
                                        rows.remove(rows[-1])
                                        blamed_val[6] = "<==="
                                        rows.append(blamed_val)
                                        to_track = False 
                                    else:
                                        to_track = False  
                        use_line_info = use_file_line+" => "+actual_use_line.strip()
                        def_line_info = def_file_line+" => "+actual_def_line.strip()
                        row = [use_line_info, def_line_info,(use_func,def_func),"\n".join(use_type),"\n".join(val_list),var_info, comment]           
                rows.append(row)
            count+=1
        count+=1
        for a_row in list(reversed(rows)):
            table.add_row(a_row)
        # print(table.get_string(title="Crash Summary"))
        df = pd.DataFrame(list(reversed(rows)), columns=col_names)
        # Save crash summary  to csv
        df.to_csv(os.path.basename(self._binary_path)+'-crash-dataflow.csv', index=False)
        df1 = pd.DataFrame(rows, columns=col_names)
        crash_dict = df1.to_dict('dict')
        self.crash_dict = crash_dict
        self.value_to_addr = value_to_addr
        html_desc = "None"
        html_desc = self.__heuristics(crash_dict, value_to_addr)
        return html_desc     

    def __heuristics(self, crash_dict, value_to_addr):
        print("**************************")
        print("Bug Framework Description")
        print("**************************")
        crash_val = 0
        crash_index = 0
        self.change_index = -1
        self.NPD_change_index = -1
        if not crash_dict['Value']: return
        v = crash_dict['Value'][0]
        val = v.split("\n")
        crash_val = int(val[0].strip(),0)
        for k, v in crash_dict['Comment'].items():
            if "<==" == v:
                self.change_index = k
            if "<===" == v:
                self.NPD_change_index = k