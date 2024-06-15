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

from termcolor import colored
from zelos.exceptions import MemoryReadUnmapped
import re
import os
import json
import pprint
import pandas as pd
import csv
import sys
from crashd.bf_models.IO_check_model import DataVerification
from crashd.bf_models.memory_model import MemoryAddressing, MemoryUse, MemoryManagement
from crashd.bf_models.data_type_model import TypeComputation
from crashd.bf_models.evaluate_severity import SeverityEvaluator
# from crashd.bf_models.generate_xml import GenerateBFCVEXML
from crashd.dwarf.analyze import Analysis
from prettytable import PrettyTable, ALL 
import datetime

class GenerateDiagnosis:
    def __init__(self, zelos, binary_path, dataflow, zelos_module_base, inst_address, mem_address=None, access=None):
        self.zelos = zelos
        self.binary_path = binary_path
        self.dataflow = dataflow
        self.zelos_module_base = zelos_module_base
        self.inst_address = inst_address
        self.mem_address = mem_address
        self.access = access
        self.direction = None
        self.is_pointer_addressing = False  
        self.mem_use = None
        self.mem_management = None
        self.mem_addressing = None
        self.type_computation = None
        self.data_verification = None
        self.severity_evaluator = None
        self.sink_type = None
        self.bf_chains_graph = None
        self.bfmodel_chain = []
        self.bf_chain_str = ''
        self.meta_data_dict = {}
        self.term_desc = None
        # regular expression patterns
        self.func_regex = re.compile(r"([a-zA-Z0-9_]+)\((.*)\)")
        self.func_call_regex = re.compile(r'(\s*)(.*)(\s*)\(.*\)|(\s*)}')
        self.loop_regex = re.compile(r'(\s*}\s*)?(do|while|for)\s*\(.*\)')
        self.loop_regex_2 = re.compile(r"(for\s*\(.*?;.*?;.*?\)\s*\{?|while\s*\(.*?\)\s*\{?)")
        self.cve_regex = re.compile(r"^(CVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,}))$")
        # regular expression to match pointer arithmetic
        self.pointer_arith_regex = re.compile(r'\b\w+\s*\*\s*\w+\s*[+\-*/%]\s*\w+\b')
        self.general_assignment = re.compile(r'\b\w+\s*(?:\*\s*)?=\s*[^;]+;')
        self.general_assignment_2 = re.compile(r'\b(\w+)\s*->\s*(\w+)|(\w+)\s*=\s*(\w+)\b')
        # regular expression to match bitwise operations
        self.bitwise_regex = re.compile(r"(\s*)(\&|\||\^)")
        # regular expression to match bit shift operations
        self.shifting_regex = re.compile(r"(\s*)(<<|>>)")        
        # regular expression to match pointer dereference
        self.dereference_regex = re.compile(r"(\s*)(\*)")
        # regular expression to match array indexing
        self.array_indexing = re.compile(r"(\s*)(\[)")
        self.array_index_pattern = r'(\w+)\[(.*?)\]'
        # regular expression to check for array subscript
        self.int_subscript_regex = re.compile(r"(\[)(\d+)(\])")
        self.var_subsrcipt_regex = re.compile(r"(\[)([a-zA-Z0-9_]+)(\])")
        self.pointer_increment_regex = r'\w+\s*\+\+'  # Regular expression pattern for pointer increment
        self.pointer_decrement_regex = r'\w+\s*\-\-'  # Regular expression pattern for pointer decrement 
        # regular expression to determine if a pointer of any type was declared as null using NULL or 0
        self.null_init_regex = r'(\w+\s*=\s*NULL|\w+\s*=\s*0)' 
        # regular expression for NULL return value
        self.null_return_regex = r'(return\s*NULL)'
        # regular expression to detect array assignment
        self.is_array_assignment_regex = r'(\w+\s*\[\s*\d+\s*\]\s*=\s*\w+)'
        # regular expression to detect pointer assignment
        self.is_pointer_assignment_regex = r'(\w+\s*\*\s*\w+\s*=\s*\w+)'
        # regular expression to detect memory allocation return
        self.alloc_return_regex = r'(\w+\s*=\s*malloc\s*\(\s*\w+\s*\))'
        self.memory_functions = set(['memcpy', 'memmove', 'memset'])
        self.string_functions = set(['strcpy', 'strncpy', 'strcat', 'strncat','wcscpy'])
        self.input_functions = set(['gets', 'fgets', 'fread', 'read'])
        self.output_functions = set(['sprintf', 'snprintf', 'vsprintf', 'vsnprintf'])
        self.crash_analyzer = Analysis(self.zelos, self.binary_path, self.dataflow, self.zelos_module_base, self.inst_address, self.mem_address, self.access)
        self.crash_analyzer.init_crash_data()
        self.crash_analyzer.diagnose_crash()
        self.get_cause()
        self.crash_analyzer.construct_zcov()
    
    def get_taint_path():
        return self.crash_analyzer._taint_path
    def get_cause(self):        
        if self.crash_analyzer.get_reason() == "heap-overflow":
            print(colored("Heap Overflow detected", "red"))
            # Get Mem Use Components
            self.mem_use = MemoryUse()
            self.get_heap_overflow_mem_use()
            self.bfmodel_chain.append(self.mem_use)
            self.mem_addressing = MemoryAddressing()
            self.get_memory_addressing_components()
            self.bfmodel_chain.append(self.mem_addressing)
            if self.mem_use.is_alloc_fault:
                self.mem_management = MemoryManagement()
                self.get_memory_management_components()
                self.bfmodel_chain.append(self.mem_management)
                if (self.mem_management.source_type == 'overflow-in-malloc' 
                or self.mem_management.source_type == 'overflow-before-malloc'):
                    self.type_computation = TypeComputation()
                    self.get_type_computation_components()
                    self.bfmodel_chain.append(self.type_computation)
                    self.severity_evaluator = SeverityEvaluator(self.zelos, self.dataflow, self.binary_path, self.mem_use, self.mem_addressing, self.type_computation, None)
                    self.severity_evaluator.evaluate()
                    self.severity_evaluator.calculate_metrics()
                    self.get_template(self.mem_use.consequence)                      
                else:
                    self.data_verification = DataVerification()
                    self.get_data_verification_components()
                    self.bfmodel_chain.append(self.data_verification)
                    self.severity_evaluator = SeverityEvaluator(self.zelos, self.dataflow, self.binary_path, self.mem_use, self.mem_addressing, None, self.data_verification)
                    self.severity_evaluator.evaluate()
                    self.severity_evaluator.calculate_metrics()
                    self.get_template(self.mem_use.consequence)     
            else:
                self.data_verification = DataVerification()
                self.get_data_verification_components()
                self.bfmodel_chain.append(self.data_verification)
                self.severity_evaluator = SeverityEvaluator(self.zelos, self.dataflow, self.binary_path, self.mem_use, self.mem_addressing, None, self.data_verification)
                self.severity_evaluator.evaluate()
                self.severity_evaluator.calculate_metrics()
                self.get_template(self.mem_use.consequence)
        elif self.crash_analyzer.get_reason() == "heap-use-after-free":
            print(colored("Use After Free detected", "red"))
            # Get Mem Use Components
            self.mem_use = MemoryUse()
            self.get_uaf_mem_use()  
            self.bfmodel_chain.append(self.mem_use)
            self.mem_addressing = MemoryAddressing()
            self.get_memory_addressing_components()
            self.bfmodel_chain.append(self.mem_addressing)
            # Evaluate Severity
            self.severity_evaluator = SeverityEvaluator(self.zelos, self.dataflow, self.binary_path, self.mem_use, self.mem_addressing, None, None)
            self.severity_evaluator.evaluate()
            self.severity_evaluator.calculate_metrics()
            # Build output template
            self.get_template(self.mem_use.consequence)
        elif self.crash_analyzer.get_reason() == "double-free":
            print(colored("Double Free detected", "red"))
            self.mem_management = MemoryManagement()
            self.get_memory_management_components()
            self.bfmodel_chain.append(self.mem_management)
            self.mem_addressing = MemoryAddressing()
            self.get_memory_addressing_components()
            self.bfmodel_chain.append(self.mem_addressing)
            self.get_template(self.mem_management.consequence)
        elif self.crash_analyzer.get_reason() == "null-pointer-dereference":
            print(colored("Null Pointer Dereference detected", "red"))
            # Get Mem Use Components
            self.mem_use = MemoryUse()
            self.get_npd_mem_use()
            self.bfmodel_chain.append(self.mem_use)
            if self.mem_use.source_type == "Pointer Arithmetic":
                print(colored("IMPLEMENT THIS CASE", "yellow"))   
            else:
                self.mem_addressing = MemoryAddressing()
                self.get_memory_addressing_components()
                self.bfmodel_chain.append(self.mem_addressing)
                # Evaluate Severity
                self.severity_evaluator = SeverityEvaluator(self.zelos, self.dataflow, self.binary_path, self.mem_use, self.mem_addressing, None, None)
                self.severity_evaluator.evaluate()
                self.severity_evaluator.calculate_metrics()
                # Build output template
                self.get_template(self.mem_use.consequence)
        elif self.crash_analyzer.get_reason() == "stack-buffer-overflow":
            print(colored("Stack Buffer Overflow detected", "red"))
            # Get Mem Use Components
            self.mem_use = MemoryUse()
            self.get_stack_buffer_overflow_mem_use()
            self.bfmodel_chain.append(self.mem_use)
            self.mem_addressing = MemoryAddressing()
            self.get_memory_addressing_components()
            self.bfmodel_chain.append(self.mem_addressing)
            self.data_verification = DataVerification()
            self.get_data_verification_components()
            self.bfmodel_chain.append(self.data_verification)
            self.severity_evaluator = SeverityEvaluator(self.zelos, self.dataflow, self.binary_path, self.mem_use, self.mem_addressing, None, self.data_verification)
            self.severity_evaluator.evaluate()
            self.severity_evaluator.calculate_metrics() 
            # Build output template
            self.get_template(self.mem_use.consequence)
                    
    def get_uaf_mem_use(self):
        self.direction = "from"
        self.is_pointer_addressing = False 
        self.mem_use.guard_triggered = self.crash_analyzer._asan_plugin_handle.asan_guard_triggered
        
        # Get alloc Info  
        self.mem_use.alloc_address = self.crash_analyzer._asan_plugin_handle.get_crash_info().alloc_info.address
        self.mem_use.alloc_size = self.crash_analyzer._asan_plugin_handle.get_crash_info().alloc_info.size
        if hex(self.mem_use.alloc_address) in self.crash_analyzer.value_to_addr:
            alloc_site = self.crash_analyzer.value_to_addr[hex(self.mem_use.alloc_address)]
            self.mem_use.alloc_site = alloc_site[1].strip()
            self.mem_use.alloc_expr = alloc_site[2].strip()
        else:
            self.mem_use.alloc_site = None 
            self.mem_use.alloc_expr = None 
        
        # get over_bounds_info
        self.mem_use.overbounds = self.crash_analyzer._asan_plugin_handle.get_crash_info().out_of_bounds
        self.mem_use.total_mem_accessed =  self.mem_use.overbounds + self.mem_use.alloc_size
        
        # get cause
        self.mem_use.cause = self.mem_use.cause_dict['address_fault'][3] # Dangling Pointer

        # get operation 
        if self.crash_analyzer._operation.lower() == 'read':
            # Read operation
            self.mem_use.operation = self.mem_use.operations_dict[3]
        elif self.crash_analyzer._operation.lower() == 'write':
            self.mem_use.operation = self.mem_use.operations_dict[4]
            self.direction = "to"
        # consequence
        self.mem_use.consequence = self.mem_use.consequences_dict['memory_corruption'][6] # Use After Free
       
        # get weakness type  
        self.mem_use.weakness_type = self.get_weakness_type('mem_use', self.mem_use.operation, self.mem_use.cause, self.mem_use.consequence, self.mem_use.address_state)
        
        # Set some attributes
        self.mem_use.source_code = self.mem_use._attributes_dict['source_code'][1] # Codebase
        self.mem_use.execution_space = self.mem_use._attributes_dict['execution_space'][1] # Userland
        self.mem_use.address_state = self.mem_use._attributes_dict['address_state'][2] # Heap
        self.mem_use.size_kind = self.mem_use._attributes_dict['size_kind'][2] # Used
        self.mem_use.mechanism = self.mem_use._attributes_dict['mechanism'][1] # Direct
        
        if self.mem_use.total_mem_accessed <=2:
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][3] # Little
        elif self.mem_use.total_mem_accessed in range(3, 1025):
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][2] # Moderate
        else:
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][1] # Huge       
            
        # Get Sink Site
        self.mem_use.sink_site = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[0].strip()
        self.mem_use.sink_expr = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[1].strip()
        self.mem_use.sink_var = list(self.crash_analyzer.crash_dict['Variable'][0])
        self.mem_use.sink_var = self.mem_use.sink_var[0][0]
        if self.mem_use.sink_var != "N/A":
            self.mem_use.consequence_comment = f"{self.mem_use.sink_var} used in {self.mem_use.sink_expr} has already been freed"
            # self.mem_use.consequence_comment = f"Variable used in expression {self.mem_use.sink_expr} has already been freed"
        else:
            self.mem_use.consequence_comment = f"Variable used in expression {self.mem_use.sink_expr} has already been freed"
            
        # Get source sites
        alloc_inst = self.crash_analyzer._asan_plugin_handle.get_crash_info().inst_address
        for key, value in self.crash_analyzer._taint_path._dwarf_data._addr2source.items():
            if "free(" not in value.split("=>")[0].lower():
                continue
            if key == alloc_inst:
                self.mem_use.source_expr = value.split("=>")[0].strip()
                self.mem_use.source_site  = value.split("=>")[1].strip()
                self.mem_use.source_var = self.mem_use.source_expr.split("(")[1].split(")")[0]
                self.mem_use.source_type = "free"
                break
            else:
                self.mem_use.source_expr = value.split("=>")[0].strip()
                self.mem_use.source_site = value.split("=>")[1].strip()
                self.mem_use.source_var = self.mem_use.source_expr.split("(")[1].split(")")[0]
                self.mem_use.source_type = "free"
                break
        self.mem_use.source_type = "free"
        if self.mem_use.source_expr == None:
            self.mem_use.source_type = "free unknown"
            self.mem_use.source_expr = self.mem_use.sink_expr
            self.mem_use.source_site = self.mem_use.sink_site 
            self.mem_use.source_var =  self.mem_use.sink_var
        self.mem_use.cause_comment = f"Expression {self.mem_use.source_expr} contains dangling pointer"
        self.mem_use.weakness_type = self.get_weakness_type('mem_use', self.mem_use.operation, self.mem_use.cause, self.mem_use.consequence, self.mem_use.address_state)
         
      
    def get_type_computation_components(self):
        # get cause
        self.type_computation.cause = self.type_computation.cause_dict['code_defect'][2] # Error in Calculation
        # get operation
        self.type_computation.operation = self.type_computation.operations_dict[1] # calculate
        # get consequence
        self.type_computation.consequence = self.type_computation.consequences_dict['data_error'][1] # Wrap Around
        
        # get attrinutes
        self.type_computation.mechanism = self.type_computation._attributes_dict['mechanism'][1] # Function
        self.type_computation.source_code = self.type_computation._attributes_dict['source_code'][1] # Codebase
        self.type_computation.execution_space = self.type_computation._attributes_dict['execution_space'][1] # Userland
        self.type_computation.name_state = self.type_computation._attributes_dict['name_state'][1] # Resolved
        self.type_computation.data_kind = self.type_computation._attributes_dict['data_kind'][1] # Numeric
        self.type_computation.type_kind = self.type_computation._attributes_dict['type_kind'][1] # Primitive
        
        if self.mem_management.source_type == 'overflow-in-malloc':
            # get sites
            self.type_computation.source_site = self.mem_management.source_site
            self.type_computation.source_expr = self.mem_management.source_expr
            self.type_computation.source_var = self.mem_management.source_var
            self.type_computation.source_type = self.mem_management.source_type
            self.type_computation.cause_comment = f"Expression {self.type_computation.source_expr} is {self.type_computation.cause}"
        else:
            # get sites # get source properly for overflows not in the malloc call
            self.type_computation.source_site = self.mem_management.source_site
            self.type_computation.source_expr = self.mem_management.source_expr
            self.type_computation.source_var = self.mem_management.source_var
            self.type_computation.source_type = self.mem_management.source_type
            self.type_computation.cause_comment = f"Expression {self.type_computation.source_expr} is {self.type_computation.cause}"
        
        # set up comment
        self.type_computation.consequence_comment = f"Expression {self.type_computation.source_expr} causes a {self.type_computation.consequence}"
        
        # get weakness type
        self.type_computation.weakness_type = self.get_weakness_type('type_computation', self.type_computation.operation, self.type_computation.cause, 
                                                                      self.type_computation.consequence, None)
            
    def get_memory_management_components(self):
        if self.mem_use!=None and self.mem_use.is_alloc_fault:
            self.mem_management.cause = self.mem_management.cause_dict['data_fault'][4] # Wrong Size
            if self.mem_addressing != None:
                self.mem_addressing.cause = self.mem_addressing.cause_dict['size_fault'][1] # Not Enough Memory
            # Get operation
            self.mem_management.operation = self.mem_management.operations_dict[1] # Allocate
            # Get consequence
            self.mem_management.consequence = self.mem_management.consequences_dict['size_error'][1] 
            
            # set attributes
            self.mem_management.mechanism = self.mem_management._attributes_dict['mechanism'][2] # Explicit
            self.mem_management.source_code = self.mem_management._attributes_dict['source_code'][1] # Codebase
            self.mem_management.execution_space = self.mem_management._attributes_dict['execution_space'][1] # Userland
            self.mem_management.address_state = self.mem_management._attributes_dict['address_state'][2] # Heap
            # Set sites 
            self.mem_management.source_site = self.mem_use.alloc_site
            self.mem_management.source_expr = self.mem_use.alloc_expr
            function_name, parameters, has_arithmetic = self.analyze_function_call(self.mem_use.alloc_expr)
            self.mem_management.cause_comment = f"{self.mem_management.source_expr}"
            self.mem_management.consequence_comment = f"{self.crash_analyzer._asan_plugin_handle.get_crash_info().alloc_info.size} bytes allocated at {self.mem_management.source_expr}"
            self.mem_addressing.cause_comment = f"{self.crash_analyzer._asan_plugin_handle.get_crash_info().alloc_info.size} bytes allocated at {self.mem_management.source_expr}"
            # ----------------------------------------------------
            
            if has_arithmetic != None and has_arithmetic:
                self.mem_management.source_type = 'overflow-in-malloc'
            elif  has_arithmetic != None and has_arithmetic == False:
                self.mem_management.source_type = 'overflow-before-malloc'
            else:
                self.mem_management.source_type = 'no-overflow'
        elif self.crash_analyzer.get_reason() == "double-free":
            # Get Cause
            self.mem_management.cause = self.mem_management.cause_dict['address_fault'][2] # Dangling Pointer
            # Get operation
            self.mem_management.operation = self.mem_management.operations_dict[4] # Deallocate
            # Get consequence
            self.mem_management.consequence = self.mem_management.consequences_dict['memory_corruption'][3] # Buffer Overflow
            # set attributes
            self.mem_management.mechanism = self.mem_management._attributes_dict['mechanism'][2] # Explicit
            self.mem_management.source_code = self.mem_management._attributes_dict['source_code'][1] # Codebase
            self.mem_management.execution_space = self.mem_management._attributes_dict['execution_space'][1] # Userland
            self.mem_management.address_state = self.mem_management._attributes_dict['address_state'][2] # Heap
            # Set sink sites 
            self.mem_management.sink_site = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[0].strip()
            self.mem_management.sink_expr = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[1].strip()
            self.mem_management.sink_var  = list(self.crash_analyzer.crash_dict['Variable'][0])
            self.mem_management.sink_var  = self.mem_management.sink_var[0][0]
            self.mem_management.consequence_comment = f"{self.mem_management.sink_expr}"
            # set source sites
            alloc_inst = self.crash_analyzer._asan_plugin_handle.get_crash_info().inst_address
            for key, value in self.crash_analyzer._taint_path._dwarf_data._addr2source.items():
                if "free(" not in value.split("=>")[0].lower():
                    continue
                if key == alloc_inst:
                    self.mem_management.source_expr = value.split("=>")[0].strip()
                    self.mem_management.source_site  = value.split("=>")[1].strip()
                    self.mem_management.source_var = self.mem_management.source_expr.split("(")[1].split(")")[0]
                    break
                else:
                    self.mem_management.source_expr = value.split("=>")[0].strip()
                    self.mem_management.source_site = value.split("=>")[1].strip()
                    self.mem_management.source_var = self.mem_management.source_expr.split("(")[1].split(")")[0]
                    break
            self.mem_management.source_type = "free"
            self.mem_management.cause_comment = f"{self.mem_management.source_expr}"
            # set weakness type
            self.mem_management.weakness_type = self.get_weakness_type('mem_management', self.mem_management.operation, self.mem_management.cause, 
                                                                          self.mem_management.consequence, self.mem_management.address_state)
            
    def get_data_verification_components(self): 
        if self.mem_addressing != None and self.mem_use != None and self.mem_use:
            # get cause
            self.data_verification.cause = self.data_verification.cause_dict['code_defect'][1] # Missing Code
            # get operation
            self.data_verification.operation = self.data_verification.operations_dict[1] # Verify
            # get consequence
            self.data_verification.consequence = self.data_verification.consequences_dict['data_error'][2] # Inconsistent Value
            
            # get attrinutes
            self.data_verification.mechanism = self.data_verification._attributes_dict['mechanism'][2] # quantity
            self.data_verification.source_code = self.data_verification._attributes_dict['source_code'][1] # Codebase
            self.data_verification.execution_space = self.data_verification._attributes_dict['execution_space'][1] # Local
            # add code to dynamically determine data state
            self.data_verification.data_state = self.data_verification._attributes_dict['data_state'][1] # Entered  
            
            # get sites
            if self.mem_use.is_alloc_fault:
                self.data_verification.source_site = self.mem_management.source_site
                self.data_verification.source_expr = self.mem_management.source_expr
                self.data_verification.source_var = self.mem_management.source_var
                self.data_verification.source_type = self.mem_management.source_type   
            else:
                self.data_verification.source_site = self.mem_addressing.source_site
                self.data_verification.source_expr = self.mem_addressing.source_expr
                self.data_verification.source_var = self.mem_addressing.source_var
                self.data_verification.source_type = self.mem_addressing.source_type  
            self.data_verification.cause_comment = f"No verification for an upper bound in {self.data_verification.source_expr}"
            self.data_verification.consequence_comment = f"{self.data_verification.source_var}"
            # get weakness type  
            self.data_verification.weakness_type = self.get_weakness_type('data_verification', self.data_verification.operation, self.data_verification.cause, 
                                                                          self.data_verification.consequence, None)
            
    def get_memory_addressing_components(self):
        
        if self.mem_use!= None and self.mem_use.consequence == "NULL Pointer Dereference":
            # get cause
            self.mem_addressing.cause = self.mem_addressing.cause_dict['code_defect'][1] # Missing Code
            # get operation
            self.mem_addressing.operation = self.mem_addressing.operations_dict[1] # Initilize
            # get consequence
            self.mem_addressing.consequence = self.mem_addressing.consequences_dict['address_error'][1] # Null Pointer
            
            # get attrinutes
            self.mem_addressing.mechanism = self.mem_addressing._attributes_dict['mechanism'][1] # Direct
            self.mem_addressing.source_code = self.mem_addressing._attributes_dict['source_code'][1] # Codebase
            self.mem_addressing.execution_space = self.mem_addressing._attributes_dict['execution_space'][1] # Userland
            self.mem_addressing.address_state = self.mem_addressing._attributes_dict['address_state'][1] # Stack
            self.mem_addressing.size_kind = self.mem_addressing._attributes_dict['size_kind'][1] # Actual
            
            # get sites
            self.mem_addressing.source_site = self.mem_use.source_site
            self.mem_addressing.source_expr = self.mem_use.source_expr
            self.mem_addressing.source_var = self.mem_use.source_var
            self.mem_addressing.source_type = self.mem_use.source_type
            
        elif self.mem_use!= None and self.mem_use.consequence == "Buffer Overflow":
             # get cause
            if self.mem_use.mechanism == "Direct":
                self.mem_addressing.mechanism = self.mem_addressing._attributes_dict['mechanism'][1] # Direct
                self.mem_addressing.cause = self.mem_addressing.cause_dict['data_fault'][3] # wrong index
            else:
                self.mem_addressing.mechanism = self.mem_addressing._attributes_dict['mechanism'][2] # Sequential
                self.mem_addressing.cause = self.mem_addressing.cause_dict['data_fault'][4] # wrong size
            # get operation
            self.mem_addressing.operation = self.mem_addressing.operations_dict[3] # Reposition 
            # get consequence
            self.mem_addressing.consequence = self.mem_addressing.consequences_dict['address_error'][5] # over bounds pointer
            
            # get attrinutes
            self.mem_addressing.source_code = self.mem_addressing._attributes_dict['source_code'][1] # Codebase
            self.mem_addressing.execution_space = self.mem_addressing._attributes_dict['execution_space'][1] # Userland
            if self.mem_use.address_state == 'Heap':
                self.mem_addressing.address_state = self.mem_addressing._attributes_dict['address_state'][2] # Heap
            else:
                self.mem_addressing.address_state = self.mem_addressing._attributes_dict['address_state'][1] # Stack
            self.mem_addressing.size_kind = self.mem_addressing._attributes_dict['size_kind'][2] # Actual
            
            # get sites
            # source
            self.mem_addressing.source_site = self.mem_use.source_site
            self.mem_addressing.source_expr = self.mem_use.source_expr
            self.mem_addressing.source_var = self.mem_use.source_var
            self.mem_addressing.source_type = self.mem_use.source_type
            # sink
            self.mem_addressing.sink_site = self.mem_use.sink_site
            self.mem_addressing.sink_expr = self.mem_use.sink_expr
            self.mem_addressing.sink_var = self.mem_use.sink_var
        
        elif (self.mem_use!= None and self.mem_use.consequence == "Use After Free") or (self.mem_management!= None and self.mem_management.consequence == "Double Free"):
            # get cause
            self.mem_addressing.cause = self.mem_addressing.cause_dict['code_defect'][1] # Missing Code
            # get operation
            self.mem_addressing.operation = self.mem_addressing.operations_dict[1] # Initilize
            # get consequence
            self.mem_addressing.consequence = self.mem_addressing.consequences_dict['address_error'][3] # Dangling Pointer
            # get attrinutes
            self.mem_addressing.mechanism = self.mem_addressing._attributes_dict['mechanism'][1] # Direct
            self.mem_addressing.source_code = self.mem_addressing._attributes_dict['source_code'][1] # Codebase
            self.mem_addressing.execution_space = self.mem_addressing._attributes_dict['execution_space'][1] # Userland
            self.mem_addressing.address_state = self.mem_addressing._attributes_dict['address_state'][2] # Heap
            self.mem_addressing.size_kind = self.mem_addressing._attributes_dict['size_kind'][1] # Actual
            # get sites
            if self.mem_use!= None and self.mem_use.consequence == "Use After Free":
                self.mem_addressing.source_site = self.mem_use.source_site
                self.mem_addressing.source_expr = self.mem_use.source_expr
                self.mem_addressing.source_var = self.mem_use.source_var
                self.mem_addressing.source_type = self.mem_use.source_type
            else:
                self.mem_addressing.source_site = self.mem_management.source_site
                self.mem_addressing.source_expr = self.mem_management.source_expr
                self.mem_addressing.source_var = self.mem_management.source_var
                self.mem_addressing.source_type = self.mem_management.source_type
        self.mem_addressing.cause_comment = f"{self.mem_addressing.source_expr}"
        if self.mem_addressing.sink_expr != None:
            if self.mem_addressing.sink_var != "N/A" and self.mem_addressing.sink_var != 'N':
                # self.mem_addressing.consequence_comment = f"{self.mem_addressing.sink_var} in {self.mem_addressing.sink_expr}"
                self.mem_addressing.consequence_comment = f"Expression: {self.mem_addressing.sink_expr}"
            else:
                self.mem_addressing.consequence_comment = f"Expression: {self.mem_addressing.sink_expr}"
        else:
            if self.mem_addressing.source_var != "N/A" and self.mem_addressing.source_var != 'N':
                # self.mem_addressing.consequence_comment = f"{self.mem_addressing.source_var} in {self.mem_addressing.source_expr}"
                self.mem_addressing.consequence_comment = f"Expression: {self.mem_addressing.sink_expr}"
            else:
                self.mem_addressing.consequence_comment = f"Expression: {self.mem_addressing.source_expr}"
       
    def set_overflow_mem_use_sources(self):
        taint_len = self.crash_analyzer.crash_dict['Defined Line'].keys()
        # Get Source Site
        index = None
        arr_name = None
        arr_dict = self.get_array_indexing()
        # print(arr_dict)
        # print(self.sink_type)
        if self.sink_type == None and arr_dict:
            self.sink_type = "array" 
            if '=' in self.mem_use.sink_expr:
                if self.mem_use.operation.lower() == 'read':
                        self.set_direct_mem_access()
                        index = arr_dict[1][1]
                        arr_name = arr_dict[1][0]
                elif self.mem_use.operation.lower() == 'write':
                    index = arr_dict[0][1]
                    arr_name = arr_dict[0][0]
                for k, source_line in self.crash_analyzer.crash_dict['Defined Line'].items():
                    tmp_use_line = self.crash_analyzer.crash_dict['Use Line'][k].split("=>")[0].strip()   
                    match = self.loop_regex.search(source_line) 
                    if  match != None and (tmp_use_line == self.mem_use.sink_site) and (index in source_line.split("=>")[1].strip()):     
                    # if  "for" in source_line and (tmp_use_line == self.mem_use.sink_site) and (index in source_line.split("=>")[1].strip()):
                        guard_value, guard_lsh, dec_lsh = self.parse_loop(source_line.split("=>")[1].strip())
                        self.mem_use.source_site = source_line.split("=>")[0].strip()
                        self.mem_use.source_expr = source_line.split("=>")[1].strip()
                        self.mem_use.mechanism = self.mem_use._attributes_dict['mechanism'][2] # Sequential
                        if guard_value != None:
                            self.mem_use.source_var = guard_value
                        else:
                            self.mem_use.source_var = self.mem_use.total_mem_accessed
                        self.mem_use.source_type = "loop"  
                        if arr_name != None:
                            self.mem_use.sink_var = arr_name
                        break
                    
            elif len(list(arr_dict.items())) == 1:
                self.set_direct_mem_access()
        elif self.sink_type == None:
            function_type, function_name, parameters, fault_param, fault_param_type = self.get_overflow_construct()
            if function_name != None and function_type != "unknown":
                self.sink_type = 'call'
                self.mem_use.mechanism = self.mem_use._attributes_dict['mechanism'][2] # Sequential
                self.mem_use.source_site = self.mem_use.sink_site
                self.mem_use.source_expr = self.mem_use.sink_expr
                self.mem_use.source_type = function_name
                self.mem_use.source_var = fault_param
                self.mem_use.sink_type = function_type
            else:
                self.mem_use.sink_type = f"Call => {function_name} => {function_type}"
                self.set_direct_mem_access()    
               
    def set_direct_mem_access(self):
        self.mem_use.mechanism = self.mem_use._attributes_dict['mechanism'][1] # Direct
        taint_len = self.crash_analyzer.crash_dict['Defined Line'].keys()
        if  self.crash_analyzer.change_index == -1:
            self.mem_use.source_site = self.crash_analyzer.crash_dict['Use Line'][len(taint_len)-1].split("=>")[0].strip()
            self.mem_use.source_expr = self.crash_analyzer.crash_dict['Use Line'][len(taint_len)-1].split("=>")[1].strip()
            self.mem_use.source_var = list(self.crash_analyzer.crash_dict['Variable'][len(taint_len)-1])
            self.mem_use.source_var = self.mem_use.source_var[0][0]        
        else:
            self.mem_use.source_site = self.crash_analyzer.crash_dict['Use Line'][ self.crash_analyzer.change_index].split("=>")[0].strip()
            self.mem_use.source_expr = self.crash_analyzer.crash_dict['Use Line'][ self.crash_analyzer.change_index].split("=>")[1].strip()
            self.mem_use.source_var = list(self.crash_analyzer.crash_dict['Variable'][ self.crash_analyzer.change_index])
            self.mem_use.source_var = self.mem_use.source_var[0][0]
    # -------------------------------      
                
    def set_mem_use_comment(self):
        if self.mem_use.source_var != "N/A" or self.mem_use.source_var != 'N':
            # self.mem_use.cause_comment = f"Variable {self.mem_use.source_var} in {self.mem_use.source_expr}"
            self.mem_use.cause_comment = f"Expression {self.mem_use.source_expr}"
        else:
            self.mem_use.cause_comment = f"Expression {self.mem_use.source_expr}"
        
        if self.mem_use.sink_var != "N/A" or self.mem_use.sink_var != 'N':
            # self.mem_use.consequence_comment = f"Variable {self.mem_use.sink_var} in {self.mem_use.sink_expr}"
            self.mem_use.consequence_comment = f"Expression {self.mem_use.sink_expr}"            
        else:
            self.mem_use.consequence_comment = f"Expression {self.mem_use.sink_expr}"
            
                       
    def get_heap_overflow_mem_use(self):
        # self.mem_use = MemoryUse()
        self.direction = "from"
        self.is_pointer_addressing = False 
        self.mem_use.guard_triggered = self.crash_analyzer._asan_plugin_handle.asan_guard_triggered
        
        # Get alloc Info  
        self.mem_use.alloc_address = self.crash_analyzer._asan_plugin_handle.get_crash_info().alloc_info.address
        self.mem_use.alloc_size = self.crash_analyzer._asan_plugin_handle.get_crash_info().alloc_info.size
        if hex(self.mem_use.alloc_address) in self.crash_analyzer.value_to_addr:
            alloc_site = self.crash_analyzer.value_to_addr[hex(self.mem_use.alloc_address)]
            self.mem_use.alloc_site = alloc_site[1].strip()
            self.mem_use.alloc_expr = alloc_site[2].strip()
        else:
            self.mem_use.alloc_site = None 
            self.mem_use.alloc_expr = None 
        
        if  self.crash_analyzer._asan_plugin_handle.is_bad_alloc():
            self.mem_use.is_alloc_fault = True
        else:
            self.mem_use.is_alloc_fault = False
        
        # get over_bounds_info
        self.mem_use.overbounds = self.crash_analyzer._asan_plugin_handle.get_crash_info().out_of_bounds
        self.mem_use.total_mem_accessed =  self.mem_use.overbounds + self.mem_use.alloc_size
        
        # get cause
        self.mem_use.cause = self.mem_use.cause_dict['address_fault'][5] # Over Bounds Pointer

        # get operation 
        if self.crash_analyzer._operation.lower() == 'read':
            # Read operation
            self.mem_use.operation = self.mem_use.operations_dict[3]
        elif self.crash_analyzer._operation.lower() == 'write':
            self.mem_use.operation = self.mem_use.operations_dict[4]
            self.direction = "to"
        
        # consequence
        self.mem_use.consequence = self.mem_use.consequences_dict['memory_corruption'][7] # Buffer Overflow 
        # get weakness type  
        self.mem_use.weakness_type = self.get_weakness_type('mem_use', self.mem_use.operation, self.mem_use.cause, self.mem_use.consequence, self.mem_use.address_state)
        
        # Set some attributes
        self.mem_use.source_code = self.mem_use._attributes_dict['source_code'][1] # Codebase
        self.mem_use.execution_space = self.mem_use._attributes_dict['execution_space'][1] # Userland
        self.mem_use.address_state = self.mem_use._attributes_dict['address_state'][2] # Heap
        self.mem_use.size_kind = self.mem_use._attributes_dict['size_kind'][2] # Used
        if self.mem_use.total_mem_accessed <=2:
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][3] # Little
        elif self.mem_use.total_mem_accessed in range(3, 1025):
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][2] # Moderate
        else:
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][1] # Huge       
            
        # Get Sink Site
        self.mem_use.sink_site = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[0].strip()
        self.mem_use.sink_expr = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[1].strip()
        self.mem_use.sink_var = list(self.crash_analyzer.crash_dict['Variable'][0])
        self.mem_use.sink_var = self.mem_use.sink_var[0][0]
        self.set_overflow_mem_use_sources()
        self.set_mem_use_comment()      
   
    
    def get_stack_buffer_overflow_mem_use(self):
        self.mem_use.total_mem_accessed = 0
        crash_mem = self.crash_analyzer.crash_dict['Mem/Reg'][0]
        if "\n" in crash_mem:
            crash_mem = crash_mem.split("\n")[0].strip()
        if "0x" in crash_mem:
            try:
                mem = self.crash_analyzer._taint_path._dataflow.zelos.memory.read(int(crash_mem.strip(),0), 100)
                if b"\x00_" in mem:
                    mem_total = len(mem.split(b"\x00_")[0].decode(errors="ignore"))
                else:
                    mem_total = len(mem.split(b"\x00")[0].decode(errors="ignore"))
                self.mem_use.total_mem_accessed = mem_total
            except MemoryReadUnmapped:
                print("None")   
        # set cause
        self.mem_use.cause = self.mem_use.cause_dict['address_fault'][5] # Over Bounds Pointer
        self.direction = "to"
        if self.crash_analyzer._access == 19:
            # Read operation
            self.mem_use.operation = self.mem_use.operations_dict[4]
        elif self.crash_analyzer._access == 20:
            self.mem_use.operation = self.mem_use.operations_dict[4]
        else:
            self.mem_use.operation = self.mem_use.operations_dict[4]
        if self.mem_use.operation == "Write":
            self.direction = "to"
        
        # set consequence
        self.mem_use.consequence = self.mem_use.consequences_dict['memory_corruption'][7] # Buffer Overflow
        # get weakness type  
        self.mem_use.weakness_type = self.get_weakness_type('mem_use', self.mem_use.operation, self.mem_use.cause, self.mem_use.consequence, self.mem_use.address_state)
        
        # Set some attributes
        self.mem_use.source_code = self.mem_use._attributes_dict['source_code'][1] # Codebase
        self.mem_use.execution_space = self.mem_use._attributes_dict['execution_space'][1] # Userland
        self.mem_use.address_state = self.mem_use._attributes_dict['address_state'][1] # Heap
        self.mem_use.size_kind = self.mem_use._attributes_dict['size_kind'][2] # Used
        if self.mem_use.total_mem_accessed <=2:
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][3] # Little
        elif self.mem_use.total_mem_accessed in range(3, 1025):
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][2] # Moderate
        else:
            self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][1] # Huge  
        
        # set sink sites
        self.mem_use.sink_site = self.crash_analyzer.crash_dict['Defined Line'][0].split("=>")[0].strip()
        self.mem_use.sink_expr = self.crash_analyzer.crash_dict['Defined Line'][0].split("=>")[1].strip()
        self.mem_use.sink_var = list(self.crash_analyzer.crash_dict['Variable'][0])
        self.mem_use.sink_var = self.mem_use.sink_var[0][0]
        # set source sites
        self.set_overflow_mem_use_sources()
        self.set_mem_use_comment() 
    
                       
    def get_npd_mem_use(self):
        # self.mem_use = MemoryUse()
        self.direction = "from"
        self.is_pointer_addressing = False   
        
        # get cause
        self.mem_use.cause = self.mem_use.cause_dict['address_fault'][1] # Null Pointer

        # get operation 
        if self.crash_analyzer._access == 19:
            # Read operation
            self.mem_use.operation = self.mem_use.operations_dict[3]
        elif self.crash_analyzer._access == 20:
            self.mem_use.operation = self.mem_use.operations_dict[3]
        else:
            self.mem_use.operation = self.mem_use.operations_dict[4]
        if self.mem_use.operation == "Write":
            self.direction = "to"
        
        # consequence
        self.mem_use.consequence = self.mem_use.consequences_dict['memory_corruption'][2] # Null Pointer Dereference   
        # get weakness type  
        self.mem_use.weakness_type = self.get_weakness_type('mem_use', self.mem_use.operation, self.mem_use.cause, self.mem_use.consequence, self.mem_use.address_state)
        # Attributes
        self.mem_use.mechanism = self.mem_use._attributes_dict['mechanism'][1] # Direct
        self.mem_use.source_code = self.mem_use._attributes_dict['source_code'][1] # Codebase
        self.mem_use.execution_space = self.mem_use._attributes_dict['execution_space'][1] # Userland
        self.mem_use.address_kind = self.mem_use._attributes_dict['address_kind'][3] # Little
        self.mem_use.address_state = self.mem_use._attributes_dict['address_state'][1] # Stack
        self.mem_use.size_kind = self.mem_use._attributes_dict['size_kind'][1] # Actual
        
        # sites 
        self.mem_use.sink_site = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[0].strip()
        self.mem_use.sink_expr = self.crash_analyzer.crash_dict['Use Line'][0].split("=>")[1].strip()
        self.mem_use.source_type = None
        self.mem_use.sink_var = list(self.crash_analyzer.crash_dict['Variable'][0])
        self.mem_use.sink_var = self.mem_use.sink_var[0][0]
        taint_len = self.crash_analyzer.crash_dict['Defined Line'].keys()
        if  self.crash_analyzer.NPD_change_index == -1:
            self.mem_use.source_site = self.crash_analyzer.crash_dict['Defined Line'][len(taint_len)-1].split("=>")[0].strip()
            self.mem_use.source_expr = self.crash_analyzer.crash_dict['Defined Line'][len(taint_len)-1].split("=>")[1].strip()
            self.mem_use.source_var = list(self.crash_analyzer.crash_dict['Variable'][len(taint_len)-1])
            # print(self.mem_use.source_var)
            self.mem_use.source_var = self.mem_use.source_var[0][0]         
        else:
            self.mem_use.source_site = self.crash_analyzer.crash_dict['Defined Line'][ self.crash_analyzer.NPD_change_index].split("=>")[0].strip()
            self.mem_use.source_expr = self.crash_analyzer.crash_dict['Defined Line'][ self.crash_analyzer.NPD_change_index].split("=>")[1].strip()
            self.mem_use.source_var = list(self.crash_analyzer.crash_dict['Variable'][ self.crash_analyzer.NPD_change_index])
            self.mem_use.source_var = self.mem_use.source_var[0][0]
              
        # regular expression for pointer arithmetic
        was_null_assigned = re.findall(self.null_init_regex, self.mem_use.source_expr)
        was_null_returned = re.findall(self.null_return_regex, self.mem_use.source_expr)
        # pointer_assigned = re.findall(self.is_pointer_assignment_regex, self.mem_use.source_expr)
        # pointer_incremented = re.findall(self.pointer_increment_regex, self.mem_use.source_expr)
        # pointer_decremented = re.findall(self.pointer_decrement_regex, self.mem_use.source_expr)
        # malloc_returned = re.findall(self.alloc_return_regex, self.mem_use.source_expr)
        # array_assigned = re.findall(self.is_array_assignment_regex, self.mem_use.source_expr)
        was_pointer_arith = re.findall(self.pointer_arith_regex, self.mem_use.source_expr) 
        was_general_assignment = re.findall(self.general_assignment_2, self.mem_use.source_expr)
       
        if was_null_assigned:
            var_name = re.findall(r'\w+', was_null_assigned[0])[0]
            self.mem_use.source_type = "Null Assigned"
            self.mem_use.source_var = var_name
        elif was_null_returned:
            self.mem_use.source_type = "Null Returned"
        elif was_pointer_arith:
            self.mem_use.source_type = "Pointer Arithmetic"
        elif was_general_assignment:
            self.mem_use.source_type = "General Assignment"
        else:
            self.mem_use.source_type = "Unknown"
        # elif array_assigned:
        #     print("Array assigned")
        #     self.mem_use.source_type = "Array Assigned"
        # elif pointer_assigned:
        #     print("Pointer assigned")
        #     self.mem_use.source_type = "Pointer Assigned"
        # elif pointer_incremented:
        #     print("Pointer incremented")
        #     self.mem_use.source_type = "Pointer Incremented"
        # elif pointer_decremented:
        #     print("Pointer decremented")
        #     self.mem_use.source_type = "Pointer Decremented"
        self.set_mem_use_comment() 
            
            
    def get_weakness_type(self, bug_class , operation, cause, consequence, address_state):
        if bug_class == 'mem_use':
            if cause == 'NULL Pointer' and consequence == 'NULL Pointer Dereference':
                return 'CWE-476 => NULL Pointer Dereference'
            elif consequence == 'Buffer Overflow' and operation.lower() == 'read':
                return 'CWE-125 => Out-of-bounds Read'
            elif consequence == 'Buffer Overflow' and operation.lower() == 'write':
                return 'CWE-787 => Out-of-bounds Write'
            elif consequence == 'Use After Free':
                return 'CWE-416 => Use After Free'
        elif bug_class == 'data_verification':
            if cause == 'Missing Code' and consequence == 'Inconsistent Value':
                return 'CWE-20 => Improper Input Validation'
        elif bug_class == 'type_computation':
            if cause == 'Erroneous Code' and (consequence == 'Wrap Around' or consequence == 'Wrong Result'):
                return 'CWE-190 => Integer Overflow or Wraparound'
        elif bug_class == 'mem_management':
            if cause == 'Dangling Pointer' and consequence == 'Double Free':
                return 'CWE-415 => Double Free'
        
        # if bug_class == 'memory_management':
        #     if cause == 'Wrong Size' and consequence == 'Not Enough Memory':
        #         return 'CWE-131 => Incorrect Calculation of Buffer Size'
        
    
    
    def analyze_function_call(self, line):
        function_name = None
        parameters = None
        has_arithmetic = None
        
        function_call_regex = r'(\w+)\s*\(([^)]*)\)'
        # Find all function calls in the text
        function_calls = re.finditer(function_call_regex, line)

        for match in function_calls:
            function_name = match.group(1)
            parameters = match.group(2)
        if parameters != None:
            has_arithmetic = re.search(r'[-+*/%]', parameters) is not None
        return function_name, parameters, has_arithmetic

    
    def get_overflow_construct(self):
        function_type = None
        function_name = None
        function_parameters = None
        line_num = self.mem_use.sink_site.split(":")[1]
        source_line = self.mem_use.sink_site.split(":")[0]
        parameters = None
        fault_param = None
        fault_param_type = None
        # Define a regular expression to match function calls
        function_call_regex = r'(\w+)\s*\(([^)]*)\)'
        # Find all function calls in the text
        function_calls = re.finditer(function_call_regex, self.mem_use.sink_expr)

        for match in function_calls:
            function_name = match.group(1)
            if function_name in self.memory_functions:
                function_type = "memory"
            elif function_name in self.string_functions:
                function_type = "string"
            elif function_name in self.input_functions:
                function_type = "input"
            elif function_name in self.output_functions:
                function_type = "output"
            else:
                function_type = "unknown"  
            parameters = match.group(2)
        if function_type == None:
            return function_type, function_name, parameters, fault_param, fault_param_type
            
        if self.mem_use.operation.lower() == 'read':
            fault_param = parameters.split(",")[0].strip()
            if fault_param.isnumeric():
                fault_param_type = "numeric"
            else:
                fault_param_type = "not_numeric"
        elif self.mem_use.operation.lower() == 'write':
            # if function_type == "memory":
                # assembly_inst = self.crash_analyzer._taint_path.get_assembly_from_source(source_line, int(line_num))
                # culprit = list(assembly_inst.items())[-4]
                # culprit_inst = culprit[1]
                # culprit_int_addr = culprit[0]
                # print(culprit_inst, culprit_int_addr)
            fault_param = parameters.split(",")[-1].strip()
            if fault_param.isnumeric():
                # print("Numeric")
                # print(f"param: {fault_param}")
                fault_param_type = "numeric"
            else:
                # print("Not Numeric")
                # print(f"param: {fault_param}")
                fault_param_type = "not_numeric"
                # pprint.pprint(self.crash_analyzer._taint_path.get_assembly_from_source(source_line, int(line_num)))
        # print(f"Function type: {function_type}")
        return function_type, function_name, parameters, fault_param, fault_param_type
    
    def match_double_script(self, input_string):
        array_name = None
        index1 = None
        index2 = None
        pattern = r"\b(\w+)\s*\[(\d+)\]\s*\[(\d+)\]\b"
        # Match the pattern in the input string
        match = re.match(pattern, input_string)
        # Check if there is a match
        if match:
            # Extract the array name and indexes
            array_name = match.group(1)
            index1 = int(match.group(2))
            index2 = int(match.group(3))
        return array_name, index1, index2
    
    
    def get_array_indexing(self):
        text = self.mem_use.sink_expr
        arr_dict = dict()
        count = 0
        # Split the text into lines
        lines = text.split('\n')
        # Extract array names and indices from each line
        for line_number, line in enumerate(lines, start=1):
            matches = re.findall(self.array_index_pattern, line)
            for match in matches:
                array_name, index = match
                arr_dict[count] = [array_name, index]
                count+=1
        return arr_dict
    
    
    def parse_loop(self, source_line):
        iterable = None
        incrementing_variable = None
        guard_value = None
        iteratable_name = None
        guard_lsh = None
        dec_lsh = None
        # Regular expression to extract components of a for loop
        for_loop_pattern = r'for\s*\((.*?);(.*?);(.*?)\)'
        match = re.match(for_loop_pattern, source_line)

        if match:
            incrementing_variable = match.group(1).strip()  # Incrementing variable
            guard = match.group(2).strip()  # Guard expression
            iterable = match.group(3).strip()  # Iterable
            m = re.match(r'(.+?)\s*<\s*(.+)', guard)
            if m:
                guard_lsh = m.group(1).strip() 
                guard_value = m.group(2).strip()  
            m = re.match(r'(.+?)\s*=\s*(.+)', incrementing_variable)
            if m:
                dec_lsh = m.group(1).strip()
                initial_value = m.group(2).strip()  
        return guard_value, guard_lsh, dec_lsh
    
    
    def get_impacr_str(self):
        impact_list = self.severity_evaluator.technical_impact_attributes.split("=>")
        impact_list = list(filter(None, impact_list))
        impact_str = ""
        num_impact = len(impact_list)
        if num_impact == 1:
            impact_str+= impact_list[0].strip()
            return impact_str
        for i in range(num_impact):
            if (i > 0) and (i != (num_impact - 1)):
                impact_str+= ", "
            elif (i > 0) and (i == (num_impact - 1)):
                impact_str+= " and "
            impact_str+= impact_list[i].strip()
        return impact_str
            
    def get_template(self, consequence):
        self.term_desc = None
        if consequence == "Double Free":
            prog = self.binary_path.split('/')[-1]
            if self.mem_management!= None and self.mem_addressing != None:
                self.term_desc = (f"In {prog}, {colored(self.mem_addressing.cause.lower(), 'yellow')} for an {colored(self.mem_addressing.operation.lower(), 'yellow')} "+
                            f"operation to NULL at ({colored(self.mem_addressing.source_site,'blue')}) leads to a "+
                            f"{colored(self.mem_addressing.consequence,'red')}. The {colored(self.mem_management.cause,'yellow')} was dereferenced via a {colored(self.mem_management.mechanism.lower(),'blue')} "+
                            f"{colored(self.mem_management.operation,'blue')} operation at ({colored(self.mem_management.sink_site,'blue')}), which resulted in a {colored(self.mem_management.consequence,'red')} Memory Error.")
        elif consequence == "Use After Free":
            prog = self.binary_path.split('/')[-1]
            if self.mem_use != None and self.mem_addressing != None:
                self.term_desc = (f"In {prog}, {colored(self.mem_addressing.cause.lower(), 'yellow')} for an {colored(self.mem_addressing.operation.lower(), 'yellow')} "+
                            f"operation to NULL at ({colored(self.mem_addressing.source_site,'blue')}) leads to a "+
                            f"{colored(self.mem_addressing.consequence,'red')}. The {colored(self.mem_use.cause,'yellow')} was dereferenced via a {colored(self.mem_use.mechanism.lower(),'blue')} "+
                            f"{colored(self.mem_use.operation,'blue')} operation at ({colored(self.mem_use.sink_site,'blue')}), which resulted in a {colored(self.mem_use.consequence,'red')} Memory Error.")     
        elif consequence == "NULL Pointer Dereference":
            if self.mem_use != None and self.mem_addressing != None:
                self.term_desc = (f"In {self.severity_evaluator.program}, {colored(self.mem_addressing.cause.lower(), 'yellow')} for an {colored(self.mem_addressing.operation.lower(), 'yellow')} "+
                            f"operation to valid memory at ({colored(self.mem_addressing.source_site,'blue')}) due to expression ({colored(self.mem_addressing.source_expr,'blue')}) leads to a "+
                            f"{colored(self.mem_addressing.consequence,'red')}. The {colored(self.mem_use.cause,'yellow')} was dereferenced via a {colored(self.mem_use.mechanism.lower(),'blue')} "+
                            f"{colored(self.mem_use.operation,'blue')} operation at ({colored(self.mem_use.sink_site,'blue')}), which resulted in a {colored(self.mem_use.consequence,'red')} Memory Error.")
                impact_str = self.get_impacr_str()
                self.term_desc+= (f" This may lead to {colored(impact_str,'red')}.")
                self.generate_html_description(consequence, impact_str)
                
        elif consequence == "Buffer Overflow":
            if self.mem_use != None and self.mem_addressing != None and self.data_verification != None:
                
                self.term_desc = (f"In {self.severity_evaluator.program}, {colored(self.data_verification.cause, 'yellow')} to {colored(self.data_verification.operation, 'yellow')} {colored(self.data_verification.mechanism, 'yellow')} {self.data_verification.source_var.strip()} in {colored(self.data_verification.source_code, 'blue')} "+
                f"{colored(self.data_verification.source_site, 'blue')} results in a {colored(self.data_verification.consequence, 'red')} of ({self.mem_use.total_mem_accessed}) bytes.")
            
                # MAD Desc
                self.term_desc+= (f" Subsequently, the {colored(self.mem_addressing.cause, 'yellow')} ({self.mem_use.total_mem_accessed}) derived from {self.data_verification.source_var.strip()} was used to perform a "+ 
                f"{colored(self.mem_addressing.mechanism, 'blue')} {colored(self.mem_addressing.operation, 'blue')} of pointer {self.mem_addressing.sink_var.strip()} in {colored(self.mem_addressing.source_code,'blue')} "+
                f"{colored(self.mem_addressing.sink_site,'blue')}, which resulted in an {colored(self.mem_addressing.consequence,'red')}. "+ 
                
                # MUS Desc
                f"Finally, using the {colored(self.mem_addressing.consequence,'yellow')} {self.mem_use.sink_var.strip()} "+ 
                f"to perform a {colored(self.mem_use.mechanism, 'blue')} {colored(self.mem_use.operation,'blue')} of {colored(self.mem_use.address_kind,'blue')} data [{colored(self.mem_use.total_mem_accessed,'blue')}] bytes {self.direction} "+
                f"{colored(self.mem_use.address_state,'blue')} object of size {self.mem_use.alloc_size} in {colored(self.mem_use.source_code,'blue')} {colored(self.mem_use.sink_site,'blue')} results in a final {colored(self.mem_use.consequence,'red')} Memory Error.")
                impact_str = self.get_impacr_str()
                self.term_desc+= (f" This may lead to {colored(impact_str,'red')}.")
                self.generate_html_description(consequence, impact_str)
            elif self.mem_use != None and self.mem_addressing != None and self.type_computation != None:
                if self.mem_management.operation == "Reallocate":
                    alloc_word = "reallocation"
                else:
                    alloc_word = "allocation"
                self.term_desc = ''
                self.term_desc+= (f"In {self.severity_evaluator.program}, {colored(self.type_computation.cause,'yellow')} ({self.type_computation.source_expr}) to {colored(self.type_computation.operation,'blue')} the size of a buffer at {colored(self.type_computation.source_site,'blue')} leads to {colored(alloc_word,'blue')} of not enough memory,"+ 
                f"allowing a pointer {colored(self.mem_use.sink_var,'blue')} to reposition over its bounds at ({colored(self.mem_addressing.source_site,'blue')}), which, when used in ({colored(self.mem_use.sink_expr,'blue')}) at line ({colored(self.mem_use.sink_site,'blue')}) leads to a heap buffer overflow.") 
                impact_str = self.get_impacr_str()
                self.term_desc+= (f" This may lead to {colored(impact_str,'red')}.")
        self.term_desc+ "\n"
        self.term_desc.replace("(-)", "")
        print("== Diagnosis ==")
        print(self.term_desc)
        # print("== Chain and Attributes ==")
        # self.extract_chains(self.binary_path.split('/')[-1])
        # print("== Weakness Types ==")
        if self.bfmodel_chain[0].weakness_type != None:
            print(colored(f"\n[+]Weakness Type (1):{self.bfmodel_chain[0].weakness_type}", "white"))
        if self.bfmodel_chain[-1].weakness_type != None:
            print(colored(f"[+]Weakness Type (2):{self.bfmodel_chain[-1].weakness_type}", "white"))
        se_level = self.severity_evaluator.eval_metrics_dict['severity_level']
        print('[+]CVSS v3.1 Rating: ', end="")
        if se_level == "CRITICAL" or se_level == "HIGH":
            print(colored(se_level, "red"))
        elif se_level == "MEDIUM":
            print(colored(se_level, "yellow"))
        elif se_level == "LOW":
            print(colored(se_level, "blue"))
        else:
            print(se_level)
        # print("\n== CVSS v3.1 Metrics ==")
        # print('[+]Base Score: ', self.severity_evaluator.eval_metrics_dict['base_score'])
        # print('[+]CVSS v3.1 Rating: ', self.severity_evaluator.eval_metrics_dict['severity_level'])
        # print('[+]Vector String: ', self.severity_evaluator.eval_metrics_dict['vector_string'])
        # print('[+]Impact Score: ', self.severity_evaluator.eval_metrics_dict['impact_score'])
        # print('[+]Exploitability Score: ', self.severity_evaluator.eval_metrics_dict['exploitability_score'])
        print("=====================================")
        return self.term_desc
    
    def extract_chains(self, program):
        # print("Extracting chains")
        # self.bf_chains_graph = nx.DiGraph()
        # reverse the bfmodel chain list to start from the source
        self.bfmodel_chain.reverse()
        # print(self.bfmodel_chain)
        for bug_model in self.bfmodel_chain:
            if isinstance(bug_model, DataVerification):
                attribute_cols = ["Cause", "Operation", "Consequence", "Mechanism", "Source Code", "Execution Space", "Data State"]
                dv_table = PrettyTable()
                dv_table.hrules=ALL
                dv_table.field_names = attribute_cols
                dv_table.add_row([bug_model.cause, bug_model.operation, bug_model.consequence, bug_model.mechanism, bug_model.source_code, bug_model.execution_space, bug_model.data_state])
                print(dv_table.get_string(title="Data Verification"))
                self.bf_chain_str+=f"({self.data_verification.cause}, {self.data_verification.operation}, {self.data_verification.consequence})->"
                self.save_tables(dv_table, "dv_table")
            elif isinstance(bug_model, TypeComputation):
                attribute_cols = ["Cause", "Operation", "Consequence", "Mechanism", "Source Code", "Execution Space", "Name State", "Data Kind", "Type Kind"]
                tc_table = PrettyTable()
                tc_table.hrules=ALL
                tc_table.field_names = attribute_cols
                tc_table.add_row([bug_model.cause, bug_model.operation, bug_model.consequence, bug_model.mechanism, bug_model.source_code, bug_model.execution_space, bug_model.name_state, bug_model.data_kind, bug_model.type_kind])
                print(tc_table.get_string(title="Type Computation"))
                self.bf_chain_str+=f"({self.type_computation.cause}, {self.type_computation.operation}, {self.type_computation.consequence})->"
                self.save_tables(tc_table, "tc_table")
            elif isinstance(bug_model, MemoryManagement):
                attribute_cols = ["Cause", "Operation", "Consequence", "Mechanism", "Source Code", "Execution Space","Address State"]
                mm_table = PrettyTable()
                mm_table.hrules=ALL
                mm_table.field_names = attribute_cols
                mm_table.add_row([bug_model.cause, bug_model.operation, bug_model.consequence, bug_model.mechanism, bug_model.source_code, bug_model.execution_space, bug_model.address_state])
                print(mm_table.get_string(title="Memory Management"))
                self.bf_chain_str+=f"({self.mem_management.cause}, {self.mem_management.operation}, {self.mem_management.consequence})->"
                self.save_tables(mm_table, "mm_table")
            elif isinstance(bug_model, MemoryAddressing):
                attribute_cols = ["Cause", "Operation", "Consequence", "Mechanism", "Source Code", "Execution Space", "Address State", "Size Kind"]
                ma_table = PrettyTable()
                ma_table.hrules=ALL
                ma_table.field_names = attribute_cols
                ma_table.add_row([bug_model.cause, bug_model.operation, bug_model.consequence, bug_model.mechanism, bug_model.source_code, bug_model.execution_space, bug_model.address_state, bug_model.size_kind])
                print(ma_table.get_string(title="Memory Addressing"))
                self.save_tables(ma_table, "ma_table")
                # check if this is the last element in the chain
                if bug_model == self.bfmodel_chain[-1]:
                    self.bf_chain_str+=f"({self.mem_addressing.cause}, {self.mem_addressing.operation}, {self.mem_addressing.consequence})"
                else:
                    self.bf_chain_str+=f"({self.mem_addressing.cause}, {self.mem_addressing.operation}, {self.mem_addressing.consequence})->"
            elif isinstance(bug_model, MemoryUse):
                attribute_cols = ["Cause", "Operation", "Consequence", "Mechanism", "Source Code", "Execution Space", "Address Kind", "Address State", "Size Kind"]
                mu_table = PrettyTable()
                mu_table.hrules=ALL
                mu_table.field_names = attribute_cols
                mu_table.add_row([bug_model.cause, bug_model.operation, bug_model.consequence, bug_model.mechanism, bug_model.source_code, bug_model.execution_space, bug_model.address_kind, bug_model.address_state, bug_model.size_kind])
                print(mu_table.get_string(title="Memory Use"))
                self.bf_chain_str+=f"({self.mem_use.cause}, {self.mem_use.operation}, {self.mem_use.consequence})"
                self.save_tables(mu_table, "mu_table")
            else:
                print("Unknown Bug Model")
            
        print("\n")
        print(f"[+]{self.bf_chain_str} \n")
        # self.create_BFCVEXML()
        # print(dir(self.crash_analyzer._zelos))
        # print(self.crash_analyzer._zelos.config.cmdline_args)
    
    def generate_html_description(self, consequence, impact_str):
        html_desc = None
        weakness_1 = "N/A"
        weakness_2 = "N/A"
        severity = "N/A"
        filename = ""
        
        if self.bfmodel_chain[0].weakness_type != None:
            weakness_1 = f"Weakness Type (1):{self.bfmodel_chain[0].weakness_type}"
        if self.bfmodel_chain[-1].weakness_type != None:
            weakness_2 = f"Weakness Type (2):{self.bfmodel_chain[-1].weakness_type}"
        severity = self.severity_evaluator.eval_metrics_dict['severity_level']
        
        if consequence == "Buffer Overflow":
            variable_mapping = {
                "@severity_evaluator_program@": self.severity_evaluator.program,
                "@data_verification.cause@": self.data_verification.cause,
                "@data_verification.operation@": self.data_verification.operation,
                "@data_verification.mechanism@": self.data_verification.mechanism,
                "@data_verification.source_var@": self.data_verification.source_var,
                "@data_verification.source_code@": self.data_verification.source_code,
                "@data_verification.source_site@": self.data_verification.source_site,
                "@data_verification.consequence@": self.data_verification.consequence,
                "@mem_use.total_mem_accessed@": self.mem_use.total_mem_accessed,
                "@mem_addressing.cause@": self.mem_addressing.cause,
                "@mem_addressing.mechanism@": self.mem_addressing.mechanism,
                "@mem_addressing.operation@": self.mem_addressing.operation,
                "@mem_addressing.sink_var@": self.mem_addressing.sink_var,
                "@mem_addressing.source_code@": self.mem_addressing.source_code,
                "@mem_addressing.sink_site@": self.mem_addressing.sink_site,
                "@mem_addressing.consequence@": self.mem_addressing.consequence,
                "@mem_use.sink_var@": self.mem_use.sink_var,
                "@mem_use.mechanism@": self.mem_use.mechanism,
                "@mem_use.operation@": self.mem_use.operation,
                "@mem_use.address_kind@": self.mem_use.address_kind,
                "@mem_use.address_state@": self.mem_use.address_state,
                "@mem_use.alloc_size@": self.mem_use.alloc_size,
                "@mem_use.source_code@": self.mem_use.source_code,
                "@mem_use.sink_site@": self.mem_use.sink_site,
                "@mem_use.consequence@": self.mem_use.consequence,
                "@direction@": self.direction,
                "@mus_code_base@": self.mem_use.sink_site,
                "@dvr_code_base@": self.data_verification.source_site,
                "@weakness_1@": weakness_1,
                "@weakness_2@": weakness_2,
                "@severity@": severity,            
                }
            filename = "overflow_template.txt"
        elif consequence == "NULL Pointer Dereference":
            variable_mapping = {
                "@severity_evaluator.program@": self.severity_evaluator.program,
                "@mem_addressing.cause@": self.mem_addressing.cause.lower(),
                "@mem_addressing.operation@": self.mem_addressing.operation.lower(),
                "@mem_addressing.source_site@": self.mem_addressing.source_site,
                "@mad_code_base@": self.mem_addressing.source_site,
                "@mem_addressing.source_expr@": self.mem_addressing.source_expr,
                "@mem_addressing.consequence@": self.mem_addressing.consequence,
                "@mem_use.cause@": self.mem_use.cause,
                "@mem_use.mechanism@": self.mem_use.mechanism.lower(),
                "@mem_use.operation@": self.mem_use.operation,
                "@mem_use.sink_site@": self.mem_use.sink_site,
                "@mus_code_base@": self.mem_use.sink_site,
                "@mem_use.consequence@": self.mem_use.consequence,
                "@impacr_str@": impact_str,
                "@weakness_1@": weakness_1,
                "@severity@": severity, 
            }
            filename = "null_template.txt"
        else:
            print("NOT YET IMPLEMENTED")
            return

        _cwd = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(_cwd, filename), "r") as inf:
            html_desc = inf.read()
            for i, j in variable_mapping.items():
                html_desc =  html_desc.replace(i, str(j))
        self.crash_analyzer.html_desc = html_desc
        # print(self.crash_analyzer.html_desc)
    
    def save_tables(self, table, name):
        pass
        # Get the table data as a list of lists
        # table_data = [table.field_names] + list(map(list, table._rows))

        # # Specify the CSV file path
        # csv_file_path = name+"-output.csv"

        # # Write the table data to a CSV file
        # with open(csv_file_path, mode='w', newline='') as file:
        #     writer = csv.writer(file)
        #     writer.writerows(table_data)
    
    # def create_BFCVEXML(self):
    #     # Get metadata 
    #     cmd_list = self.crash_analyzer._zelos.config.cmdline_args
    #     info_df = pd.read_csv('merged-cmd.csv')
    #     # print(self.crash_analyzer._zelos.target_binary_path)
    #     cmd_str = ''
    #     for item in cmd_list:
    #         if 'lib64' in item: continue
    #         cmd_str+=item+" "
    #     print(cmd_str)
    #     cmd_str = cmd_str.strip()
    #     cmd_str = cmd_str.replace("./", "/")
    #     cmd_df = info_df[info_df['cmd'].str.contains(cmd_str)]
    #     if cmd_df.empty:
    #         print("No metadata found for this program")
    #         return
    #     else:  
    #         # Define a regular expression to match ANSI escape codes
    #         ansi_escape = re.compile(r'\x1b[^m]*m')
    #         # Remove ANSI escape codes from colored text
    #         original_desc = ansi_escape.sub('', self.term_desc)
    #         # get date in this format 2023-02-10T11:16:21
    #         curr_date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S") 
    #         target_bin = self.binary_path.split('/')[-1].strip()
    #         program_name = cmd_df['program'].values[0].strip()
    #         if program_name in target_bin:
    #             title = f"{self.bfmodel_chain[-1].consequence} in {target_bin}."
    #         else:
    #             title = f"{self.bfmodel_chain[-1].consequence} in {program_name} utility {target_bin}."
    #         self.meta_data_dict["ID"] = cmd_df['cve'].values[0]
    #         self.meta_data_dict["Program"] = program_name
    #         self.meta_data_dict["Title"] = title
    #         self.meta_data_dict["Description"] = original_desc
    #         self.meta_data_dict["Author"] = "kedrian James, Kevin Valakuzhy, Kevin Snow, and Fabian Monrose"
    #         self.meta_data_dict["Date"]  = curr_date
    #         self.meta_data_dict["Criteria"] = f"{program_name}:{target_bin}"
    #         self.meta_data_dict["BugReport"] = cmd_df['bug_report'].values[0]
    #         self.meta_data_dict["CodeWithBug"] = cmd_df['bug_report'].values[0]
    #         self.meta_data_dict["CodeWithFix"] = cmd_df['fix'].values[0]
    #         self.meta_data_dict["Language"] = 'C'
    #     pprint.pprint(self.meta_data_dict)
    #     BFCVEXML = GenerateBFCVEXML(self.bfmodel_chain, self.meta_data_dict, self.severity_evaluator)
    #     BFCVEXML.generate_xml()
    
    
    
