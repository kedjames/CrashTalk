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

class TaintCFGNode:
    def __init__(self, address, mem_var, var_name, value, assembly, source, region, func, fp):
        self.address = address
        self.mem_var = mem_var
        self.var_name = var_name
        self.value = value
        self.assembly = assembly
        self.source = source
        self.region = region
        self.func = func
        self.fp = fp
    
    
    def __str__(self):
        str_value = f"address: {self.address}\n"
        str_value += f"mem_var: {self.mem_var}\n"
        str_value += f"var_name: {self.var_name}\n"
        str_value += f"value: {self.value}\n"
        str_value += f"assembly: {self.assembly}\n"
        str_value += f"source: {self.source}\n"
        str_value += f"region: {self.region}\n"
        str_value += f"func: {self.func}\n"
        str_value += f"fp: {self.fp}\n"
        return str_value
        
        
         
    