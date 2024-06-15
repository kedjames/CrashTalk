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

class MemoryAddressing:
    def __init__(self):
        # Causes 
        self.cause_dict = {"code_defect": {1: "Missing Code", 2: "Mismatched Operation", 3: "Erroneous Code"},
                      "data_fault": {1: "Hardcoded Address", 2: "Single Owned Address", 3: "Wrong Index", 4: "Wrong Size"},
                      "type_fault": {1: "Wrong Type", 2: "Wrong Index Type", 3: "Casted Pointer"},
                      "address_fault": {1: "NULL Pointer", 2: "Wild Pointer", 3: "Dangling Pointer", 4: "Untrusted Pointer", 
                                        5: "Over Bounds Pointer", 5: "Under Bounds Pointer", 7: "Wrong Position Pointer"},
                      "size_fault": {1: "Not Enough Memory"}
                      }
        
        # Operation
        self.operations_dict = {1: "Initialize Pointer", 2: "Reassign", 3: "Reposition"}
        
        # Consequences
        self.consequences_dict = {"data_error": {1: "Forbidden Address"},
                             "type_error": {1: "Casted Pointer"},
                             "address_error":{1: "NULL Pointer", 2: "Wild Pointer", 3: "Dangling Pointer", 
                                              4: "Untrusted Pointer", 
                                              5: "Over Bounds Pointer", 
                                              6: "Under Bounds Pointer",
                                              7: "Wrong Position Pointer"}
                            }
        # Attributes
        self._attributes_dict = {"mechanism": {1: "Direct", 2: "Sequential"},
                            "source_code": {1: "Codebase", 2: "Thrid Party", 3: "Standard Library", 4: "Compiler/Interpreter"},
                            "execution_space": {1: "Userland", 2: "Kernel", 3: "Bare-Metal"},
                            "address_state": {1:"Stack", 2:"Heap", 3:"Global", 4:"Static", 5:"Register"},
                            "size_kind": {1: "Actual", 2: "Used"}
                            } 
        self.cause = None
        self.operation = None
        self.consequence = None
        self.mechanism = None
        self.source_code = None
        self.execution_space = None
        self.address_state = None
        self.size_kind = None
        self.source_site = None
        self.source_expr = None
        self.source_type = None
        self.source_var = None
        self.sink_site = None
        self.sink_expr = None
        self.sink_var = None
        self.cause_comment = None
        self.consequence_comment = None
        self.weakness_type = None
        
        
    def __str__(self):
        print("Memory Addressing")
        print("==================")
        str_value = "Cause: " + str(self.cause) + "\n"
        str_value += "Operation: " + str(self.operation) + "\n"
        str_value += "Consequence: " + str(self.consequence) + "\n"
        str_value += "Mechanism: " + str(self.mechanism) + "\n"
        str_value += "Source Code: " + str(self.source_code) + "\n"
        str_value += "Execution Space: " + str(self.execution_space) + "\n"
        str_value += "Address State: " + str(self.address_state) + "\n"
        str_value += "Size Kind: " + str(self.size_kind) + "\n"
        str_value += "Source Site: " + str(self.source_site) + "\n"
        str_value += "Sink Site: " + str(self.sink_site) + "\n"
        str_value += "Sink Expr: " + str(self.sink_expr) + "\n"
        str_value += "Source Expr: " + str(self.source_expr) + "\n"
        str_value += "Source Type: " + str(self.source_type) + "\n"
        str_value += "Source Var: " + str(self.source_var) + "\n"
        str_value += "Sink Var: " + str(self.sink_var) + "\n"
        str_value += "Cause Comment: " + str(self.cause_comment) + "\n"
        str_value += "Consequence Comment: " + str(self.consequence_comment) + "\n"
        str_value += "Weakness Type: " + str(self.weakness_type) + "\n"
        return str_value
        
class MemoryUse:
    def __init__(self):
        # Causes 
        self.cause_dict = {"code_defect": {1: "Missing Code", 2: "Mismatched Operation", 3: "Erroneous Code"},
                      "data_fault": {1: "Forbidden Address", 2: "Wrong Size"},
                      "type_fault": {1: "Casted Pointer"},
                      "address_fault": {1: "NULL Pointer", 2: "Wild Pointer", 3: "Dangling Pointer", 4: "Untrusted Pointer", 
                                        5: "Over Bounds Pointer", 6: "Under Bounds Pointer", 7: "Wrong Position Pointer"},
                      "size_fault": {1: "Not Enough Memory"}
                      }  
        
        # Operation
        self.operations_dict = {1: "Initialize", 2: "Dereference", 3: "Read", 4: "Write", 5: "Clear"}
        
        # Consequences
        self.consequences_dict = {"data_error": {1: "Uninitialized Object"},
                             "memory_corruption" :{1: "Not Cleared Object", 2: "NULL Pointer Dereference",
                                3: "Untrusted Pointer Dereference", 4: "Unitialized Pointer Dereference", 5: "Type Confusion", 
                                6: "Use After Free", 7: "Buffer Overflow", 8: "Buffer Underflow", 
                                9: "Buffer Over-Read", 10: "Buffer Under-Read", 11: "Object Corruption"}}
        
        # Attributes
        self._attributes_dict = {"mechanism": {1: "Direct", 2: "Sequential"},
                            "source_code": {1: "Codebase", 2: "Thrid Party", 3: "Standard Library", 4: "Compiler/Interpreter"},
                            "execution_space": {1: "Userland", 2: "Kernel", 3: "Bare-Metal"},
                            "address_kind": {1:"Huge", 2:"Moderate", 3:"Little"},
                            "address_state": {1:"Stack", 2:"Heap", 3:"Global", 4:"Static", 5:"Register"},
                            "size_kind": {1: "Actual", 2: "Used"}
                            } 
        self.cause = None
        self.operation = None
        self.consequence = None
        self.mechanism = None
        self.source_code = None
        self.execution_space = None
        self.address_kind = None
        self.address_state = None
        self.size_kind = None
        self.sink_site = None
        self.sink_expr = None
        self.sink_var = None
        self.sink_type = None
        self.source_site = None
        self.source_expr = None
        self.source_type = None
        self.source_var = None
        self.weakness_type = None
        # heap stuff 
        self.guard_triggered = False
        self.alloc_address = None
        self.alloc_size = None
        self.alloc_site = None
        self.alloc_expr = None
        self.overbounds = None
        self.total_mem_accessed = None
        self.is_alloc_fault = False
        
        self.cause_comment = None
        self.consequence_comment = None
        
    def __str__(self):
        print("Memory Use")
        print("==========")
        str_value = "Cause: " + str(self.cause) + "\n"
        str_value += "Operation: " + str(self.operation) + "\n"
        str_value += "Consequence: " + str(self.consequence) + "\n"
        str_value += "Mechanism: " + str(self.mechanism) + "\n"
        str_value += "Source Code: " + str(self.source_code) + "\n"
        str_value += "Execution Space: " + str(self.execution_space) + "\n"
        str_value += "Address Kind: " + str(self.address_kind) + "\n"
        str_value += "Address State: " + str(self.address_state) + "\n"
        str_value += "Size Kind: " + str(self.size_kind) + "\n"
        str_value += "Source Site: " + str(self.source_site) + "\n"
        str_value += "Sink Site: " + str(self.sink_site) + "\n"
        str_value += "Sink Expr: " + str(self.sink_expr) + "\n"
        str_value += "Source Expr: " + str(self.source_expr) + "\n"
        str_value += "Source Type: " + str(self.source_type) + "\n"
        str_value += "Source Var: " + str(self.source_var) + "\n"
        str_value += "Sink Var: " + str(self.sink_var) + "\n"
        str_value += "Alloc Address: " + str(self.alloc_address) + "\n"
        str_value += "Alloc Size: " + str(self.alloc_size) + "\n"
        str_value += "Alloc Site: " + str(self.alloc_site) + "\n"
        str_value += "Alloc Expr: " + str(self.alloc_expr) + "\n"
        str_value += "Overbounds: " + str(self.overbounds) + "\n"
        str_value += "Total Mem Accessed: " + str(self.total_mem_accessed) + "\n"
        str_value += "Weakness Type: " + str(self.weakness_type) + "\n"
        str_value += "Guard Triggered: " + str(self.guard_triggered) + "\n"
        str_value += "Is Alloc Fault: " + str(self.is_alloc_fault) + "\n"
        str_value += "Cause Comment: " + str(self.cause_comment) + "\n"
        str_value += "Consequence Comment: " + str(self.consequence_comment) + "\n"
        return str_value
        
        
class MemoryManagement:
    def __init__(self):
        # Causes 
        self.cause_dict = {"code_defect": {1: "Missing Code", 2: "Mismatched Operation", 3: "Erroneous Code"},
                      "data_fault": {1: "Hardcoded Address", 2: "Forbidden Address", 3: "Single Owned Address", 4: "Wrong Size"},
                      "address_fault": {1: "Wild Pointer", 2: "Dangling Pointer", 3: "Wrong Position Pointer"},
                      "size_fault": {1: "Not Enough Memory"}
                      }
        
        # Operation
        self.operations_dict = {1: "Allocate", 2: "Extend", 3: "Reallocate-Extend", 4: "Deallocate", 5: "Reduce", 6: "Reallocate-Reduce"}
        
        
        # Consequences
        self.consequences_dict = {"address_error":{1: "NULL Pointer", 2: "Wild Pointer", 3: "Dangling Pointer"},
                             "size_error": {1: "Not Enough Memory"},
                             "memory_corruption":{1: "Memory Overflow", 2: "Memory Leak",
                                                  3: "Double Free", 4: "Object Corruption"}
                            }

        # Attributes
        self._attributes_dict = {"mechanism": {1: "Implicit", 2: "Explicit"},
                            "source_code": {1: "Codebase", 2: "Thrid Party", 3: "Standard Library", 4: "Compiler/Interpreter"},
                            "execution_space": {1: "Userland", 2: "Kernel", 3: "Bare-Metal"},
                            "address_state": {1:"Stack", 2:"Heap", 3:"Global", 4:"Static", 5:"Register"}} 
        self.cause = None
        self.operation = None
        self.consequence = None
        self.mechanism = None
        self.source_code = None
        self.execution_space = None
        self.address_state = None
        self.source_site = None
        self.source_expr = None
        self.source_type = None
        self.source_var = None
        self.sink_site = None
        self.sink_expr = None
        self.sink_var = None
        self.cause_comment = None
        self.consequence_comment = None
        self.weakness_type = None
        # self.size_kind = None
    
    def __str__(self):
        str_value = "Cause: " + str(self.cause) + "\n"
        str_value += "Operation: " + str(self.operation) + "\n"
        str_value += "Consequence: " + str(self.consequence) + "\n"
        str_value += "Mechanism: " + str(self.mechanism) + "\n"
        str_value += "Source Code: " + str(self.source_code) + "\n"
        str_value += "Execution Space: " + str(self.execution_space) + "\n"
        str_value += "Address State: " + str(self.address_state) + "\n"
        str_value += "Source Site: " + str(self.source_site) + "\n"
        str_value += "Sink Site: " + str(self.sink_site) + "\n"
        str_value += "Sink Expr: " + str(self.sink_expr) + "\n"
        str_value += "Source Expr: " + str(self.source_expr) + "\n"
        str_value += "Source Type: " + str(self.source_type) + "\n"
        str_value += "Source Var: " + str(self.source_var) + "\n"
        str_value += "Sink Var: " + str(self.sink_var) + "\n"
        str_value += "Cause Comment: " + str(self.cause_comment) + "\n"
        str_value += "Consequence Comment: " + str(self.consequence_comment) + "\n"
        str_value += "Weakness Type: " + str(self.weakness_type) + "\n"
        return str_value
        
        
                             
        
        
    
        
        