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

import math
import pandas as pd
import pprint
class SeverityEvaluator:
    def __init__(self, zelos, dataflow, binary_path, mem_use, mem_addressing, data_type, io_check):
        
        self.network_syscalls = {"socket", "socketpair", "bind","listen", "accept", "connect", "send",
                                "sendto", "sendmsg", "recv", "recvfrom", "recvmsg"}
        
        self.lib_list = {'libjpeg', 'libpng', 'libtiff', 'libxml2', 'libxslt', 'libyaml', 'libzip', 'pcre',
                        'zlib', 'opj_compress', 'opj_decompress','xmllint', 'cjpeg', 'cjpeg-static', 
                        'djpeg', 'djpeg-static','bmp2tiff' ,'jpegtran', 'potrace', 'libming', 'listfdb','libzip'}
        
        self.network_list = {'apache', 'nginx', 'openssh', 'openssl', 'php', 'w3m'}
        
        self.local_list = {'find', 'grep', 'sed', 'tar', 'zip', 'unzip', 'curl', 'wget','imginfo', 
                           'bash', 'test_example_1_debug', 'nasm', 'pcre', 'pcretest', 'readelf', 'objdump', 'nm', 
                           'strings', 'strip', 'objcopy', 'readelf', 'objdump', 'nm', 'strings', 'strip', 'objcopy', 'jasper'}
        self.zelos = zelos
        self.binary_path = binary_path
        self.mem_use = mem_use
        self.mem_addressing = mem_addressing
        self.type_computation = data_type
        self.data_verification = io_check
        # CVSS Metrics Base Attributes
        self.attack_vector = 'N'
        self.attack_complexity = 'L' # Leave as default Low (L)
        self.user_interaction = 'N'
        self.privileges_required = 'N'
        self.scope = 'U' # Leave as default Unchanged (U)
        self.confidentality_impact = 'N'
        self.integrity_impact = 'N'
        self.availability_impact = 'N'
        # CVSS scoring attributes
        self.impact_score = 0.0
        self.exploitability_score = 0.0
        self.base_score = 0.0
        self.vector_string = ''
        self.severity_level = ''
        self.dataflow = dataflow
        # print(dataflow.track_syscall)
        
        # metrics dictionary
        self.eval_metrics_dict = {}
        
        # Technical Impact message
        self.technical_impact_attributes = ''
        # program name
        self.program = self.binary_path.split('/')[-1]
        # print("Program: " + str(self.program) )
    
        # CVSS Metrics Base Attributes
        self.base_metrics = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            'AC': {'L': 0.77, 'H': 0.44},
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
            'MPR': {'N': 0.85, 'L': 0.68, 'H': 0.50},
            'UI': {'N': 0.85, 'R': 0.62},
            'S': {'U': 6.42, 'C': 7.52},
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},
            'A': {'N': 0, 'L': 0.22, 'H': 0.56}
        }
    
    def set_attack_vector(self):
        is_network_syscall = False
        if self.dataflow.track_syscall is not None:
            is_network_syscall = bool(self.network_syscalls.intersection(set(self.dataflow.track_syscall)))
        if self.program in self.lib_list or self.program in self.network_list or is_network_syscall:
            self.attack_vector = "N"
        elif self.program in self.local_list:
            self.attack_vector = "L"
        elif self.data_verification!=None:
            if self.data_verification.data_state.lower() == "network":
                self.attack_vector = "N"
            else:
                self.attack_vector = "L"
   
    def set_user_interaction(self):
        if self.data_verification!=None:
            if self.data_verification.data_state.lower() == "network" or self.data_verification.data_state.lower() == "entered":
                self.user_interaction = "R"
            else:
                self.user_interaction = "N"
        elif (self.program in self.lib_list) or (self.program in self.network_list) or (self.program in self.local_list):
            self.user_interaction = "R"
        else:
            self.user_interaction = "N"
            
    def set_privileges_required(self):
        if self.program in self.lib_list or self.program in self.network_list or self.program in self.local_list:
            self.privileges_required = "N"
        elif self.program in self.local_list:
            self.privileges_required = "L"
        elif self.data_verification!=None:
            if self.data_verification.execution_space.lower() == "admin":
                self.privileges_required = "H"
            elif self.data_verification.data_state.lower() == "network": 
                self.privileges_required = "N"
            elif self.data_verification.data_state.lower() == "entered":
                self.privileges_required = "L"
                
    def set_confidentiality_impact(self):
        if (self.mem_use!=None) and self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-125":
            if self.data_verification!=None:
                if self.data_verification.data_state.lower() == "network" or self.data_verification.data_state.lower() == "entered":
                    self.confidentality_impact = "H"
                elif self.data_verification.data_state.lower() == "stored":
                    self.confidentality_impact = "L"
            # self.confidentality_impact = "N"
            elif (self.type_computation!=None) and (self.type_computation.weakness_type.split("=>")[0].strip() == "CWE-190"):
                self.confidentality_impact = "H"
            self.technical_impact_attributes+= "information exposure =>"
        elif (self.mem_use!=None) and self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-416" and self.mem_use.operation.lower() == "read":
            self.confidentality_impact = "H"
            self.technical_impact_attributes+= "information exposure =>"
        
    
    def set_integrity_impact(self):
        if (self.mem_use!=None) and self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-787":
            if self.data_verification!=None:
                if self.data_verification.data_state.lower() == "network" or self.data_verification.data_state.lower() == "entered":
                    self.integrity_impact = "H"
                    self.technical_impact_attributes+= "data tampering or remote code execution =>"
                elif self.data_verification.data_state.lower() == "stored":
                    self.integrity_impact = "L"
                    self.technical_impact_attributes+= "data tampering or code execution =>"
            elif (self.type_computation!=None) and (self.type_computation.weakness_type.split("=>")[0].strip() == "CWE-190"):
                    self.integrity_impact = "H"
                    self.technical_impact_attributes+= "data tampering or code execution =>"
        elif self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-476" and self.mem_use.execution_space == "Kernel":
            self.integrity_impact = "H"
            self.technical_impact_attributes+= "data tampering or code execution =>"
            # self.integrity_impact = "N"
        elif (self.mem_use!=None) and self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-416" and self.mem_use.operation.lower() == "write":
            self.integrity_impact = "H"
            self.technical_impact_attributes+= "data tampering or code execution =>"    
        elif (self.type_computation!=None) and (self.type_computation.weakness_type.split("=>")[0].strip() == "CWE-190"):
            self.integrity_impact = "H"
            self.technical_impact_attributes+= "data corruption =>"
         
    def set_availability_impact(self):
        if (self.mem_use != None) and  (self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-476" or 
                                        self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-787" or 
                                        self.mem_use.weakness_type.split("=>")[0].strip() == "CWE-416"):
            if self.program in self.lib_list or self.program in self.network_list or self.program in self.local_list:
                self.availability_impact = "H"
            # elif self.program in self.local_list:
            #     self.availability_impact = "L"
            else:
                self.availability_impact = "L"
            # self.availability_impact = "N"
            self.technical_impact_attributes+= "denial of service - application crash =>"
        elif (self.type_computation != None) and (self.type_computation.weakness_type.split("=>")[0].strip() == "CWE-190"):
            if self.program in self.lib_list or self.program in self.network_list or self.program in self.local_list:
                self.availability_impact = "H"
            # elif self.program in self.local_list:
            #     self.availability_impact = "L"
            else:
                self.availability_impact = "L"
            self.technical_impact_attributes+= "denial of service - application crash =>"
            
                
    def evaluate(self):
        if self.mem_use is not None:
            # Set the CVSS metrics base attributes
            # Scope and Attack Complexity are left as default values
            self.set_attack_vector()
            self.set_user_interaction()
            self.set_privileges_required()
            self.set_confidentiality_impact()
            self.set_integrity_impact()
            self.set_availability_impact() 
        return self.technical_impact_attributes, self.program

    def roundup(self, input_value):
        int_input = round(input_value * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        else:
            return (math.floor(int_input / 10000) + 1) / 10.0
    
    
    def calculate_metrics(self):
        av = self.attack_vector.upper()
        ac = self.attack_complexity.upper()
        ui = self.user_interaction.upper()
        pr = self.privileges_required.upper()
        s = self.scope.upper()
        ci = self.confidentality_impact.upper()
        ii = self.integrity_impact.upper()
        ia = self.availability_impact.upper()
        
   
        # initialize metric values
        iss = 0.0
        pr_score = 0.0
        
        if s == 'U': 
            pr_score = float(self.base_metrics['PR'][pr])
        elif s == 'C':
            pr_score = float(self.base_metrics['MPR'][pr])
        
        # Step 1: Calculate the Impact Subscore (ISC)
        iss = 1 - ((1 - float(self.base_metrics['C'][ci])) * (1 - float(self.base_metrics['I'][ii])) * (1 - float(self.base_metrics['A'][ia])))
        iss = min([iss, 1])
        
        # Step 2: Calculate the Impact Score (IS)
        if s == 'U':
            self.impact_score = 6.42 * iss
        else:
            self.impact_score = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
            
        # Step 3: Calculate the Exploitability Subscore (ESS)
        self.exploitability_score = 8.22 * float(self.base_metrics['AV'][av]) * float(self.base_metrics['AC'][ac]) * float(pr_score) * float(self.base_metrics['UI'][ui])
        
        # Step 4: Calculate the Base Score (BS)
        if self.impact_score <= 0:
            self.base_score = 0.0
        else:
            if s == 'U':
                self.base_score = self.roundup(min([self.exploitability_score + self.impact_score, 10]))
            else:
                self.base_score = self.roundup(min([1.08 * (self.exploitability_score + self.impact_score), 10]))
                
        self.vector_string = 'CVSS:3.1/AV:' + av + '/AC:' + ac + '/PR:' + pr + '/UI:' + ui + '/S:' + s + '/C:' + ci + '/I:' + ii + '/A:' + ia
        self.score_to_rating()
        self.eval_metrics_dict = {"impact_score": self.roundup(self.impact_score), 
                                  "exploitability_score": self.roundup(self.exploitability_score), 
                                  "base_score": self.roundup(self.base_score), 
                                  "vector_string": self.vector_string, 
                                  "severity_level": self.severity_level}
        # print("\n== CVSS v3.1 Metrics ==")
        # print('[+]Base Score: ', self.roundup(self.base_score))
        # print('[+]Rating: ', self.severity_level)
        # print('[+]Vector String: ', self.vector_string)
        # print('[+]Impact Score: ', self.roundup(self.impact_score))
        # print('[+]Exploitability Score: ', self.roundup(self.exploitability_score))
        # print("=====================================")
        # pprint.pprint(self.eval_metrics_dict)
        
            
    # convert score to rating
    def score_to_rating(self):
        if self.base_score == 0.0:
            self.severity_level = 'NONE'
        elif self.base_score < 4.0:
            self.severity_level =  'LOW'
        elif self.base_score < 7.0:
            self.severity_level =  'MEDIUM'
        elif self.base_score < 9.0:
            self.severity_level = 'HIGH'
        else:
            self.severity_level =  'CRITICAL'
    