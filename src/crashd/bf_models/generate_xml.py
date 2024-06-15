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


import xml.etree.ElementTree as ET
from xml.dom import minidom
import os
from crashd.bf_models.IO_check_model import DataVerification
from crashd.bf_models.memory_model import MemoryAddressing, MemoryUse, MemoryManagement
from crashd.bf_models.data_type_model import TypeComputation

class GenerateBFCVEXML:
    def __init__(self, bug_class_list, meta_data_dict, severity_evaluator):
        self.bug_class_list = bug_class_list  # list of BugClass objects
        self.meta_data_dict = meta_data_dict  # dictionary of meta data
        self.bug_class = None
        self.bug_class_type = None
        self.is_final_class = False
        self.language = self.meta_data_dict["Language"]
        self.root = None
        self.weakness_sub_element = None
        self.failure_consequence = None
        self.cause_type = None
        self.consequence_type = None
        self.severity_evaluator = severity_evaluator
        self.key_to_cause_dict = {"code_defect": "Code Defect",
                                  "specification_defect": "Specification Defect",
                                  "data_fault": "Data",
                                  "type_fault": "Type",
                                  "address_fault": "Address",
                                  "size_fault": "Size",
                                  "computation_error": "Type Compute",
                                  "data_error": "Data",
                                  "type_error": "Type",
                                  "address_error": "Address",
                                  "size_error": "Size",
                                  "memory_corruption": "Memory Corruption/Disclosure",
                                  "memory_leak": "Memory Leak"}
        
    def find_key(self, dictionary, target_value):
        for category, sub_dict in dictionary.items():
            for key, value in sub_dict.items():
                if value == target_value:
                    return category, key
        return None, None


    def generate_xml(self):
        # Create the root element
        self.root = ET.Element("BFCVE")
        self.root.set("ID", self.meta_data_dict["ID"])
        self.root.set("Title", self.meta_data_dict["Title"])
        self.root.set("Description", self.meta_data_dict["Description"])
        self.root.set("Author", self.meta_data_dict["Author"])
        self.root.set("Date", self.meta_data_dict["Date"])
        self.root.set("Criteria", self.meta_data_dict["Criteria"])
        self.root.set("BugReport",self.meta_data_dict["BugReport"])
        self.root.set("CodeWithBug", self.meta_data_dict["CodeWithBug"])
        self.root.set("CodeWithFix", self.meta_data_dict["CodeWithFix"])
        # self.meta_data_dict["Language"]
        # Create weakness elements
        # self.bug_class_list.reverse()
        # print(self.bfmodel_chain)'
        # print(self.bug_class_list)
        for bug_model in self.bug_class_list:
            key_1 = None
            key_2 = None
            
            e_type="weakness"
            if bug_model == self.bug_class_list[0]:
                e_type="defect"
            elif bug_model == self.bug_class_list[-1]:
                self.failure_consequence = bug_model.consequence
                self.is_final_class = True
            key_1, _ = self.find_key(bug_model.cause_dict, bug_model.cause)
            self.cause_type = self.key_to_cause_dict[key_1].strip()
            key_2, _ = self.find_key(bug_model.consequences_dict, bug_model.consequence)
            self.consequence_type = self.key_to_cause_dict[key_2].strip()
            # print(self.cause_type, self.consequence_type)
            if isinstance(bug_model, DataVerification):
                self.bug_class_type = "_INP"
                self.bug_class = "DVR"
                self.add_sub_element(bug_model, element_type=e_type)
            elif isinstance(bug_model, TypeComputation):
                self.bug_class_type = "_DAT"
                self.bug_class = "TCM"
                self.add_sub_element(bug_model, element_type=e_type)
            elif isinstance(bug_model, MemoryManagement):
                self.bug_class_type = "_MEM"
                self.bug_class = "MMN"
                self.add_sub_element(bug_model, element_type=e_type)
            elif isinstance(bug_model, MemoryAddressing):
                self.bug_class_type = "_MEM"
                self.bug_class = "MAD"
                self.add_sub_element(bug_model, element_type=e_type)
            elif isinstance(bug_model, MemoryUse):
                self.bug_class_type = "_MEM"
                self.bug_class = "MUS"
                self.add_sub_element(bug_model, element_type=e_type)
            else:
                print("Unknown Bug Model")
        # failure attributes
        # Create Failures element
        failures = ET.SubElement(self.root, "Failures", ClassType="_FLR")

        # Add elements and attributes for Failures
        if self.severity_evaluator!=None:
            if self.severity_evaluator.confidentality_impact != 'N' or self.severity_evaluator.integrity_impact != 'N':
                ET.SubElement(failures, "Cause", Comment="", Type="Memory Corruption/Disclosure").text = self.failure_consequence
                ET.SubElement(failures, "Failure", Class="IEX")
            if self.severity_evaluator.availability_impact != 'N':
                ET.SubElement(failures, "Cause", Comment="", Type="Memory Corruption/Disclosure").text = self.failure_consequence
                ET.SubElement(failures, "Failure", Class="DOS")
        # save xml file
        tree = ET.ElementTree(self.root)
        filename = os.path.join("./bfcve-xml/", f"{self.meta_data_dict['ID']}.bfcve")
        # tree.write(filename, xml_declaration=True, method="xml", encoding="utf-8")
        xml_str = ET.tostring(self.root, encoding="utf-8", method="xml").decode()
        dom = minidom.parseString(xml_str)
        with open(filename, "w") as file:
            file.write(dom.toprettyxml(indent="  ")) 
                
    def add_sub_element(self, current_bug_class,  element_type="weakness"):
        if element_type == "defect":
            sub_element = ET.SubElement(self.root, "DefectWeakness")
        elif element_type == "weakness":
            sub_element = ET.SubElement(self.root, "Weakness")
        else:   
            print("Unknown sub element type")
            return None
        sub_element.set("Class", self.bug_class)
        sub_element.set("ClassType", self.bug_class_type)
        sub_element.set("Language", self.language)
        if self.bug_class == "MUS":
            sub_element.set("File", current_bug_class.sink_site)
        else:
            sub_element.set("File", current_bug_class.source_site)
            
        cause = ET.SubElement(sub_element, "Cause", Comment=f"{current_bug_class.cause_comment}", Type=self.cause_type).text = current_bug_class.cause
        operation = ET.SubElement(sub_element, "Operation", Comment="").text = current_bug_class.operation
        consequence = ET.SubElement(sub_element, "Consequence", Comment=f"{current_bug_class.consequence_comment}", Type=self.consequence_type).text = current_bug_class.consequence
        # set up attributes for the weakness sub element
        # operand attributes
        attributes = ET.SubElement(sub_element, "Attributes")
        if self.bug_class == "DVR":
            operand_data = ET.SubElement(attributes, "Operand", Name="Data")
            ET.SubElement(operand_data, "Attribute", Comment="", Type="State").text = current_bug_class.data_state
            # bug_model.mechanism, bug_model.source_code, bug_model.execution_space, bug_model.data_state
        elif self.bug_class == "TCM":
            operand_name = ET.SubElement(attributes, "Operand", Name="Name")
            ET.SubElement(operand_name, "Attribute", Comment="", Type="State").text = current_bug_class.name_state
            operand_data = ET.SubElement(attributes, "Operand", Name="Data")
            ET.SubElement(operand_data, "Attribute", Comment="", Type="Kind").text = current_bug_class.data_kind
            operand_type = ET.SubElement(attributes, "Operand", Name="Type")
            ET.SubElement(operand_type, "Attribute", Comment="", Type="Kind").text = current_bug_class.type_kind
            #  bug_model.name_state, bug_model.data_kind, bug_model.type_kind
        elif self.bug_class_type == "_MEM":
            operand_address = ET.SubElement(attributes, "Operand", Name="Address")
            ET.SubElement(operand_address, "Attribute", Comment="", Type="State").text = current_bug_class.address_state
            if self.bug_class == "MUS":
                ET.SubElement(operand_address, "Attribute", Comment="", Type="Kind").text = current_bug_class.address_kind
            if self.bug_class != "MMN":
                operand_size = ET.SubElement(attributes, "Operand", Name="Size")
                ET.SubElement(operand_size, "Attribute", Type="Kind").text = current_bug_class.size_kind
        # operation attributes
        operation_elem = ET.SubElement(attributes, "Operation")
        ET.SubElement(operation_elem, "Attribute", Comment="", Type="Mechanism").text = current_bug_class.mechanism
        if self.is_final_class:
            ET.SubElement(operation_elem, "Attribute", Comment=f"{current_bug_class.sink_site}", Type="Source Code").text = current_bug_class.source_code
        else:
            ET.SubElement(operation_elem, "Attribute", Comment=f"{current_bug_class.source_site}", Type="Source Code").text = current_bug_class.source_code
        ET.SubElement(operation_elem, "Attribute", Type="Execution Space").text = current_bug_class.execution_space

        
        
        
        
            
            
        
        
        
        
        
        
        
        
        
        
        
