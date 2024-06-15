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

class DataVerification:
   def __init__(self):
      # Causes 
      self.cause_dict = {"code_defect": {1: "Missing Code", 2: "Erroneous Code"},
                     "specification_defect": {1: "Under-Restrictive Policy", 2: "Over-Restrictive Policy"},
                     "data_fault": {1: "Invalid Data"}
                     }
      
      # Operation
      self.operations_dict = {1: "Verify", 2: "Correct"}
      
      # Consequences
      self.consequences_dict = {"data_error": {1: "Wrong Value", 2: "Inconsistent Value"},
                           "type_error": {1: "Wrong Type"}
                           }
      # Attributes
      self._attributes_dict = {"mechanism": {1: "Value", 2: "Quantity", 3: "Range", 4: "Data Type", 5: "Other Rules"},
                           "source_code": {1: "Codebase", 2: "Thrid Party", 3: "Standard Library", 4: "Compiler/Interpreter"},
                           "execution_space": {1: "Local", 2: "Admin", 3: "Bare-Metal"},
                           "data_state": {1:"Entered", 2:"Stored", 3:"In Use", 4:"Transferred"}
                           } 
      self.cause = None
      self.operation = None
      self.consequence = None
      self.mechanism = None
      self.source_code = None
      self.execution_space = None
      self.data_state = None
      self.source_site = None
      self.source_expr = None
      self.source_type = None
      self.source_var = None
      self.sink_site = None
      self.sink_expr = None
      self.sink_type = None
      self.sink_var = None
      self.cause_comment = None
      self.consequence_comment = None
      self.weakness_type = None
      
   def __str__(self):
      print("Data Verification")
      print("==================")
      str_value = "Cause: " + str(self.cause) + "\n"
      str_value += "Operation: " + str(self.operation) + "\n"
      str_value += "Consequence: " + str(self.consequence) + "\n"
      str_value += "Mechanism: " + str(self.mechanism) + "\n"
      str_value += "Source Code: " + str(self.source_code) + "\n"
      str_value += "Execution Space: " + str(self.execution_space) + "\n"
      str_value += "Data State: " + str(self.data_state) + "\n"
      str_value += "Source Site: " + str(self.source_site) + "\n"
      str_value += "Source Expr: " + str(self.source_expr) + "\n"
      str_value += "Source Type: " + str(self.source_type) + "\n"
      str_value += "Source Var: " + str(self.source_var) + "\n"
      str_value += "Sink Site: " + str(self.sink_site) + "\n"
      str_value += "Sink Expr: " + str(self.sink_expr) + "\n"
      str_value += "Sink Type: " + str(self.sink_type) + "\n"
      str_value += "Sink Var: " + str(self.sink_var) + "\n"
      str_value += "Cause Comment: " + str(self.cause_comment) + "\n"
      str_value += "Consequence Comment: " + str(self.consequence_comment) + "\n"
      str_value += "Weakness Type: " + str(self.weakness_type) + "\n"
      
      return str_value
        