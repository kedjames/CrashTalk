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
from crashd.dwarf.dwarf_data import DwarfData

from zelos import Zelos, IPlugin, CommandLineOption, HookType
import hexdump
import pandas as pd
import pprint


CommandLineOption("asan", action="store_true", help="ASAN-like capabilities")


class WriteRecord:
    def __init__(self, ip_addr, mem_addr, value):
        self.ip_addr = ip_addr
        self.mem_addr = mem_addr
        self.value = value

    def __repr__(self):
        return f"(ip 0x{self.ip_addr:x}: {self.value} -> 0x{self.mem_addr:x})"


class AllocInfo:
    def __init__(self, addr, size, inst_addr, desc, is_free=False):
        # Address of the corresponding heap buffer allocation
        self.address = addr
        # Size of the corresponding heap buffer allocation
        self.size = size
        # Address of the corresponding heap buffer allocation inst.
        self.inst_address = inst_addr
        # Short string describing the allocation site,
        #   e.g. "malloc(0x100)"
        self.description = desc
        # True if the corresponding allocation had been free'd
        self.is_free = is_free

        self.writes = defaultdict(list)
        # an alternative inst address when the alloc address cannot 
        # be found
        self.alt_inst_address = None

    def __str__(self):
        return f"Origin Inst: 0x{self.inst_address:x} {self.description}"

    def _record_write(self, ip_addr: int, mem_addr: int, value: int):
        self.writes[mem_addr].append(WriteRecord(ip_addr, mem_addr, value))

    def get_writes(self, mem_addr: int, size: int):
        """
        Returns all addresses that wrote to this memory region
        """
        accessors = []
        for addr in range(mem_addr, mem_addr + size):
            accessors.extend(self.writes[addr])
        return accessors

    def summarize_buffer(self, memory) -> str:
        """
        Returns a string summarizing the memory buffer.
        """
        memory_buffer = memory.read(self.address, self.size)
        chunk_size = 16
        chunks = [
            memory_buffer[i : i + chunk_size]
            for i in range(0, len(memory_buffer), chunk_size)
        ]
        lines = []
        current_chunk = None
        duplicate_line_count = 0
        for i, chunk in enumerate(chunks):
            if current_chunk == chunk:
                if lines[-1] != "...":
                    lines.append("...")
                duplicate_line_count += 1
                continue
            elif len(lines) > 0 and lines[-1] == "...":
                lines[
                    -1
                ] = f"... omitting {duplicate_line_count} duplicate lines"
                duplicate_line_count = 0

            current_chunk = chunk
            line = hexdump.hexdump(chunk, result="return")
            offset, rest = line.split(":", 1)
            offset = int(offset, 16) + i * chunk_size
            writes = self.get_writes(self.address + offset, chunk_size)
            line = f"{offset:08x}:{rest} {writes}"            
            # line = f"{offset:08x}:{rest}"
            lines.append(line)
            pprint.pprint(writes)

        if len(lines) > 20:
            lines = (
                ["First ten lines:"]
                + lines[:10]
                + [f"Last ten lines:"]
                + lines[-10:]
            )

        return "  Buffer Contents:\n" + "\n".join(lines)


class CrashInfo:
    def __init__(
        self,
        reason: str = "",
        operation: str = "",
        inst_address=None,
        mem_address=None,
        mem_access_size=None,
        alloc_info=None,
        out_of_bounds = None,
    ):
        # Short description of the crash problem
        self.reason = reason
        # Either READ, WRITE or the empty string
        self.operation = operation
        # Address of the crashing instruction
        self.inst_address = inst_address
        # Address of the memory location causing the crash
        self.mem_address = mem_address
        # Number of bytes read starting at the mem_address
        self.mem_access_size = mem_access_size
        # Amount of data read out of bounds
        self.out_of_bounds = out_of_bounds 
        # Information about the buffer of origin for the crash
        self.alloc_info = alloc_info
       

    @property
    def exploitability(self):
        """
        An estimate on whether the crash is exploitable
        """
        reason = self.reason
        operation = self.operation
        addr = self.mem_address

        near_zero = False
        if addr > 0 and addr < 0x1000:
            near_zero = True

        if reason in ["double-free", "bad-free"]:
            return "EXPLOITABLE"
        if reason == "heap-use-after-free":
            return "EXPLOITABLE"
        if reason == "heap-overflow":
            if operation == "READ":
                if near_zero:
                    return "PROBABLY_NOT_EXPLOITABLE"
                else:
                    return "UNKNOWN"
            if operation == "WRITE":
                if near_zero:
                    return "PROBABLY_EXPLOITABLE"
                else:
                    return "EXPLOITABLE"
        return "UNKNOWN"

    def get_summary(self, memory):
        s = f"\nCrash Summary:\n"
        s += f"  Exploitable: {self.exploitability}\n"
        s += f"  Reason: {self.reason}\n"
        s += f"  Crashing Instruction: 0x{self.inst_address:x}\n"
        if self.mem_address is not None:
            s += f"  Crashing Access: {self.operation} of size {self.out_of_bounds} at memory location: 0x{self.mem_address:x}"
        if self.alloc_info is not None:
            if self.mem_address:
                s += f" (buf + 0x{(self.mem_address-self.alloc_info.address):x})"
                s += f" size: {self.mem_access_size:x} byte(s)\n"
            else:
                s += "\n"
            s += "  " + str(self.alloc_info) + "\n"
            s += self.alloc_info.summarize_buffer(memory)
        else:
            s += "\n"
        return s


class Asan(IPlugin):
    """
        Implements heap sanitization similar to ASAN or libdislocator.

        Specifically:
            - Creates a GUARD_SIZE region of protected memory:
                - Immediately following malloc'd buffers
    """

    def __init__(self, zelos: Zelos):
        super().__init__(zelos)

        self._allocs = {}
        self._frees = {}
        self._generic_failure = {}
        self._reason = None
        self._guard_size = 0x10
        self._crash_info = None
        self._bad_alloc = False
        self.rows = []
        self.headers = ["addr", "aloc_req", "desc", "alloc_plus_guard", "low_addr", "high_addr", "valid_start", "inst"]
        # Dwarf data
        self._dwarf_data = None
        self._files = None
        self.__load_dwarf_data(zelos)
        self._malloc_count = 0

        if not zelos.config.asan:
            return

        # Used to correct invalid crashing address for runs with
        # INST.EXEC hook.
        self._inst_hook_triggered = False
        self._add_hooks()
        
    def get_dwarf_data(self):
        return self._dwarf_data
        
    def __load_dwarf_data(self, zelos):
        # self.logger.info("[+]Parsing DWARF info...")
        # zelos_module_base = zelos.internal_engine.memory.get_module_base(zelos.target_binary_path)
        zelos_module_base = 4096
        binary_path = zelos.target_binary_path
        source_code_path =  zelos.config.source_code_path
        self._dwarf_data = DwarfData(binary_path, source_code_path, zelos_module_base)
        self._files = self._dwarf_data._file_lines
        # self._dwarf_data.attach_src_to_external_addrs(self.zelos.plugins.dataflow.trace._trace)
    
    def is_bad_alloc(self):
        return self._bad_alloc
    
    def is_whitelisted_function(self, c_line):
        whitelist = ["strcmp", "strlen", "strcpy", "strncpy", "strcat", "strncat"]
        pattern = r'\b(' + '|'.join(re.escape(func) for func in whitelist) + r')\b'
        match = re.search(pattern, c_line)
        return match is not None

    def _add_hooks(self):
        """ Add linux memory allocator hooks and generic invalid
            memory access hook.
        """
        hooks = {
            "malloc": ([("void*", "ptr")], self._malloc),
            "calloc": ([("size_t", "num"), ("size_t", "size")], self._calloc),
            "realloc": (
                [("void*", "ptr"), ("size_t", "new_size")],
                self._realloc,
            ),
            "free": ([("void*", "ptr")], self._free),
            "__stack_chk_fail": ([("void", "num")], self.__stack_chk_fail),
        }
        for fn_name, fn_hook in hooks.items():
            self.zelos.internal_engine.hook_manager.register_func_hook(
                fn_name, fn_hook[1]
            )

        self.zelos.hook_memory(HookType.MEMORY.INVALID, self._invalid_hook)

    def _invalid_hook(self, zelos, access, address, size, value):
        """ Hook invoked any time an invalid memory access is triggered.
        """
        # print(self._reason)
        if self._reason == "double-free" or self._reason == "stack-buffer-overflow":
            info = self._generic_failure.get(self._reason)
            # print(info)
            operation = "READ"
            if access == 22:
                operation = "WRITE"
            if self._crash_info is None: 
                self._crash_info = CrashInfo(
                    reason=self._reason,
                    operation=operation,
                    inst_address=info[2],
                    mem_address=info[0],
                    mem_access_size=info[1],
                    out_of_bounds = info[1],
                    alloc_info=info[3],
                )    
                # self.logger.warning(self._crash_info.get_summary(zelos.memory))  
                return      
        else:
            operation = "READ"
            if access == 22:
                operation = "WRITE"
            if self._crash_info is None: 
                self._crash_info = CrashInfo(
                    reason="unknown-crash",
                    operation=operation,
                    inst_address=self.zelos.thread.getIP(),
                    mem_address=address,
                    mem_access_size=size,
                    out_of_bounds = None,
                    alloc_info=None,
                )

                # self.logger.warning(self._crash_info.get_summary(zelos.memory))
                # self.logger.warning(self._reason)
            else:
                self._crash_info.operation=operation


    @property
    def asan_guard_triggered(self) -> bool:
        return self.get_crash_alloc_info() is not None
    
    def get_crash_alloc_info(self) -> AllocInfo:
        if self._crash_info is None:
            return None
        return self._crash_info.alloc_info

    def get_crash_info(self) -> CrashInfo:
        if self._crash_info is None:
            return None
        return self._crash_info

    def set_inst_hook(self):
        def inst_hook(z, addr, size):
            pass

        return self.zelos.hook_execution(HookType.EXEC.INST, inst_hook)

    def _add_memory_guard(self, start: int, end: int, alloc_info: AllocInfo):
        def guard_access(zelos, access, addr, size, value):           
            accessed_mem = addr + size 
            oob_access = (accessed_mem - start)
                        
            if accessed_mem <= start:
                return
            
            if access == 16:
                file, line = self._dwarf_data._address_map.get(self.zelos.thread.getIP(), (None, None))
                if file is not None and line is not None:
                    if file in self._files and line in self._files[file]:
                        line = self._files[file][line]   
                        print(self.is_whitelisted_function(line)) 
                        if oob_access <= 4:
                            return
                else:
                    return
                
            if not self._inst_hook_triggered:
                # If you are running zelos without an EXEC.INST hook,
                # the crash at the memory guard page will not return
                # the proper instruction address. We set the
                # instruction hook and run again to get the correct
                # address.
                zelos.internal_engine.scheduler.stop_and_exec(
                    "pre-crash inst hook", self.set_inst_hook
                )
                self._inst_hook_triggered = True
                return
            
            if alloc_info.is_free:
                if start in self._frees:
                    reason = "double-free"
                else:
                    reason = "heap-use-after-free"
            else:
                reason = "heap-overflow"
                if alloc_info.size <= 0:
                    self._bad_alloc = True
            operation = "READ"
            if access == 17:
                operation = "WRITE"

            self._crash_info = CrashInfo(
                reason=reason,
                operation=operation,
                inst_address=self.zelos.thread.getIP(),
                mem_address=addr,
                mem_access_size=size,
                out_of_bounds = oob_access,
                alloc_info=alloc_info,
            )
            
            # self.logger.warning(self._crash_info.get_summary(zelos.memory))

            def crash():
                # Now make the underlying page a guard page so zelos
                # will fault and end execution.
                # start, max(0x1000, end - start), 0
                zelos.memory._memory.protect(
                    start, max(0x1000, end - start), 0
                )

            zelos.internal_engine.scheduler.stop_and_exec("Crash", crash)
            
        return self.zelos.hook_memory(
            HookType.MEMORY.VALID,
            guard_access,
            mem_low=start-7,
            mem_high=end,
            end_condition=lambda: self.asan_guard_triggered,
        )

    def _safe_alloc(self, size: int, desc: str = "") -> int:
        """
        Allocates memory and ensures that a crash will happen if memory
        is written outside of the boundaries.
        """
        if (size + self._guard_size) >= self.zelos.memory._memory.HEAP_MAX_SIZE:
            self._bad_alloc = True            
        addr = self.zelos.memory._memory.heap.alloc(
            size + self._guard_size, name="safe_malloc"
        )
    
        alloc_info = AllocInfo(addr, size, self.zelos.thread.getIP(), desc)
        alloc_info.alt_inst_address = self.zelos.plugins.trace.last_instruction
        self._record_writes(alloc_info)
        low_addr = addr + size
        high_addr = low_addr + self._guard_size - 1
        high_hook = self._add_memory_guard(
            low_addr, high_addr, alloc_info
        )
        self._allocs[addr] = (size, high_hook)
        return addr

    def _record_writes(self, alloc_info: AllocInfo):
        def record_write(zelos, access, addr, size, value):
            alloc_info._record_write(
                zelos.thread.getIP(),
                addr,
                zelos.memory.pack(value, bytes=size),
            )

        return self.zelos.hook_memory(
            HookType.MEMORY.WRITE,
            record_write,
            mem_low=alloc_info.address,
            mem_high=alloc_info.address + alloc_info.size,
        )

    def _handle_return(self, retval: int):
        if retval is not None:
            self.zelos.internal_engine.kernel.set_return_value(retval)
            dfa = self.zelos.plugins.dataflow
            if dfa.dataflow_enabled:
                dfa.trace.add_define(
                    self.zelos.internal_engine.kernel._REG_RETURN,
                    retval,
                    label_override="Memory API",
                )
        thread = self.zelos.thread
        # FIXME: this line only works on architectures with stack-based
        #   return addresses.
        retaddr = thread.popstack()

        def set_ip():
            thread.setIP(retaddr)

        self.zelos.internal_engine.scheduler.stop_and_exec(
            "syscall_ip_change", set_ip
        )
        
        if self._reason == "double-free" or self._reason == "stack-buffer-overflow":
            # print(f"{self._reason}.......")
            for item in self.zelos.thread.threads.get_all_threads():
                self.zelos.thread.threads.kill_thread(item.id)

    def _get_args(self, args):
        return self.zelos.internal_engine.kernel.get_args(args)

    def _malloc(self, zelos):
        """ Add a GUARD_SIZE guard immediately following the buffer.
        """
        self._malloc_count += 1
        args = self._get_args([("int", "size")])
        retval = self._safe_alloc(args.size, f"malloc(size=0x{args.size:x})")
        self._handle_return(retval)

    def _calloc(self, zelos):
        """ Add a GUARD_SIZE guard immediately following the buffer.
        """
        args = self._get_args([("size_t", "num"), ("size_t", "size")])
        size = args.num * args.size
        if size <= 0:
            self._handle_return(0)
        retval = self._safe_alloc(
            size, f"calloc(num=0x{args.num:x}, size=0x{args.size:x})"
        )
        self.zelos.memory.write(retval, b"\x00" * size)
        self._handle_return(retval)

    def _realloc(self, zelos):
        """ Add a GUARD_SIZE guard immediately following the buffer.
        """        
        args = self._get_args([("void*", "ptr"), ("size_t", "new_size")])
        if args.ptr == 0:
            retval = self._safe_alloc(
                args.new_size,
                f"realloc(ptr=0x{args.ptr:x}, new_size=0x{args.new_size:x})",
            )
        else:
            retval = self._safe_alloc(
                args.new_size,
                f"realloc(ptr=0x{args.ptr:x}, new_size=0x{args.new_size:x})",
            )
        self._handle_return(retval)

    def _free(self, zelos):
        """ Add guard in the entirety of the free'd buffer space.
        """
        args = self._get_args([("void*", "ptr")])
        if args.ptr == 0:
            return
               
        if args.ptr in self._allocs:
            size, high_hook = self._allocs.pop(args.ptr)
            self.zelos.delete_hook(high_hook)
            dfa = self.zelos.plugins.dataflow
            alloc_info = AllocInfo(
            args.ptr,
            size,
            self.zelos.thread.getIP(),
            f"free(f{args.ptr:x})",
            is_free=True,
            )
        
            # Add guard in the free'd space
            self._add_memory_guard(
                args.ptr - self._guard_size,
                args.ptr + size + self._guard_size - 1,
                alloc_info,
            )
            self._frees[args.ptr] = (size, dfa.trace.last_addr, alloc_info)           
            
        elif args.ptr in self._frees:
            print(f"Trying to Free {hex(args.ptr)} again.. Double Free")
            dfa = self.zelos.plugins.dataflow
            self._reason = "double-free"
            (size, IP, alloc_info) = self._frees[args.ptr]
            self._generic_failure["double-free"] = (args.ptr, size, IP, alloc_info)
        self._handle_return(None)
    # self._handle_return(None)
     
    def __stack_chk_fail(self, str):
        dfa = self.zelos.plugins.dataflow
        alloc_info = AllocInfo(
        dfa.trace.last_addr,
        0x10,
        self.zelos.thread.getIP(),
        f"stack alloc",
        is_free=False,
        )
        self._reason = "stack-buffer-overflow"
        self._generic_failure["stack-buffer-overflow"] = (self.zelos.thread.getIP(), 0x10, dfa.trace.last_addr, alloc_info)
        self._handle_return(None)
        
        
