import angr
import simuvex
import simuvex.engines.vex.dirty as vex_dirtyhelpers
from simuvex.plugins.plugin import SimStatePlugin
import claripy

from random import randint, getrandbits

TICKS_PER_MS = 10000  # Windows TicksPerMillisecond = 10000
MALWARE_STRINGS = ['malware', 'sample', 'virus']
VM_STRINGS = ['vm', 'hgfs', 'vbox', 'virtualbox', 'sandboxie', 'sboxie', 'wine', 'qemu', 'bochs']
API_HOOK_CHECKS = ['DeleteFileW', 'ShellExecuteExW', 'CreateProcessA']
BLACKLISTED_MODULES = ['sbiedll.dll']
BLACKLISTED_SYMBOLS = ['IsWow64Process', 'wine_get_unix_file_name']


# PLUGINS #

class SimStateParanoid(SimStatePlugin):
    """
        This state plugin keeps track of various paranoid stuff:
    """

    def __init__(self):
        SimStatePlugin.__init__(self)
        self.tsc = 15 * 1000 * 60 * TICKS_PER_MS  # init tick count ~= 15 minutes
        self.last_error = 0  # should be thread-local, but angr does NOT currently support threads

    def copy(self):
        c = SimStateParanoid()
        c.tsc = self.tsc
        c.last_error = self.last_error
        return c


# HOOKS #

# Utilities

class SetLastError(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(SetLastError, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, dwErrCode):

        self.argument_types = {
            0: simuvex.s_type.SimTypeInt(),
        }

        self.state.paranoid.last_error = dwErrCode.args[0]

        self.return_type = None

        print "SetLastError: " + str(dwErrCode) + " " + "=> " + "void"
        return


class GetLastError(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetLastError, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self):

        self.argument_types = {}

        self.return_type = simuvex.s_type.SimTypeInt()

        ret_expr = self.state.paranoid.last_error
        print "GetLastError: " + "=> " + str(ret_expr)
        return ret_expr


class GetModuleHandle(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetModuleHandle, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpModuleName):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
        }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpModuleName)
        module_name = self.state.mem[self.state.se.any_int(lpModuleName)].string.concrete

        if module_name.lower() in BLACKLISTED_MODULES:
            ret_expr = 0  # NULL, i.e. module not found
        else:
            ret_expr = self.state.se.BVS("unc_ret_GetModuleHandle_{}".format(module_name), 32)

        print "GetModuleHandle: " + str(lpModuleName) + " " + "=> " + str(ret_expr)
        return ret_expr


class GetProcAddress(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetProcAddress, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, hModule, lpProcName):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(simuvex.s_type.SimTypeString())
        }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpProcName)

        lpProcName_int_high = self.state.se.any_int(lpProcName) & 0xFFFF0000

        if lpProcName_int_high == 0:  # ordinal import
            assert False  # TODO: add support ordinal value
        else:
            sym_name = self.state.mem[self.state.se.any_int(lpProcName)].string.concrete
            if sym_name in BLACKLISTED_SYMBOLS:
                ret_expr = 0  # NULL, i.e. symbol not found
            else:
                ret_expr = self.state.se.BVS("unc_ret_GetProcAddress_{}".format(sym_name), 32)

        print "GetProcAddress: " + str(hModule) + " " + str(lpProcName) + " => " + str(ret_expr)
        return ret_expr


class IsWow64Process(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(IsWow64Process, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, hProcess, Wow64Process):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(simuvex.s_type.SimTypeInt()),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(Wow64Process)
        self.state.memory.store(Wow64Process, self.state.se.BVV(0, 32))  # always return FALSE
        ret_expr = 1  # success
        print "IsWow64Process: " + str(hProcess) + " " + str(Wow64Process) + " " + "=> " + str(ret_expr)
        return ret_expr


class LocalAlloc(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(LocalAlloc, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, uFlags, uBytes):

        self.argument_types = {
            0: simuvex.s_type.SimTypeInt(),
            1: simuvex.s_type.SimTypeLength(),
        }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(uBytes)
        # use malloc's simprocedure (copied and pasted)
        if self.state.se.symbolic(uBytes):  # dead code for now (bc of the previous assert)
            size = self.state.se.max_int(uBytes)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(uBytes)
        size = self.state.se.any_int(uBytes)

        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size

        # now handle flags
        if not self.state.se.symbolic(uFlags):
            flags = self.state.se.any_int(uFlags)
            if flags & 0x0040:  # LMEM_ZEROINIT
                self.state.memory.store(addr, self.state.se.BVV(0, size * 8), endness=self.arch.memory_endness)

        ret_expr = addr
        print "{}: ".format(self.__class__.__name__) + str(uFlags) + " " + str(uBytes) + " " + "=> " + hex(ret_expr)
        return ret_expr


class GlobalAlloc(LocalAlloc):
    pass


class LocalFree(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(LocalFree, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hMem):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        # just a stub, don't really need to free anything in the libc plugin
        ret_expr = self.state.se.Unconstrained(self.__class__.__name__, self.state.arch.bits)
        print "{}: ".format(self.__class__.__name__) + str(hMem) + " " + "=> " + str(ret_expr)
        return ret_expr


class GlobalFree(LocalFree):
    pass


class GetFileAttributes(simuvex.SimProcedure):
    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetFileAttributes, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpFileName):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(lpFileName)
        file_name = self.state.mem[self.state.se.any_int(lpFileName)].string.concrete

        malware_related = any(mal_str in file_name.lower() for mal_str in MALWARE_STRINGS)
        vm_related = any(vm_str in file_name.lower() for vm_str in VM_STRINGS)

        if malware_related or vm_related:
            ret_expr = -1  # INVALID_FILE_ATTRIBUTES, i.e. file not found
        else:
            ret_expr = self.state.se.BVS("unc_ret_GetFileAttributes_{}".format(file_name), 32)

        print "GetFileAttributes: " + str(lpFileName) + " " + "=> " + str(ret_expr)
        return ret_expr


class RegOpenKeyEx(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(RegOpenKeyEx, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, hKey, lpSubKey, ulOptions, samDesired, phkResult):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(simuvex.s_type.SimTypeString()),
            2: simuvex.s_type.SimTypeInt(),
            3: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            4: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = simuvex.s_type.SimTypeLong()

        assert not self.state.se.symbolic(lpSubKey)
        regkey_name = self.state.mem[self.state.se.any_int(lpSubKey)].string.concrete

        vm_related = any(vm_str in regkey_name.lower() for vm_str in VM_STRINGS)

        if vm_related:
            ret_expr = 2  # ERROR_FILE_NOT_FOUND
        else:
            assert not self.state.se.symbolic(phkResult)
            self.state.memory.store(phkResult, self.state.se.BVS("unc_data_RegOpenKeyEx_{}".format(regkey_name), 32),
                                    endness=self.arch.memory_endness)
            ret_expr = self.state.se.BVS("unc_ret_RegOpenKeyEx_{}".format(regkey_name), 32)

        print "RegOpenKeyEx: " + str(hKey) + " " + str(lpSubKey) + " " + str(ulOptions) + " " +\
            str(samDesired) + " " + str(phkResult) + " " + "=> " + str(ret_expr)
        return ret_expr


class RegQueryValueEx(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(RegQueryValueEx, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 6

    def run(self, hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(simuvex.s_type.SimTypeString()),
            2: self.ty_ptr(simuvex.s_type.SimTypeInt()),
            3: self.ty_ptr(simuvex.s_type.SimTypeInt()),
            4: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            5: self.ty_ptr(simuvex.s_type.SimTypeInt()),
        }

        self.return_type = simuvex.s_type.SimTypeLong()

        assert not self.state.se.symbolic(lpData)
        if self.state.se.any_int(lpData) != 0:  # not NULL
            assert not self.state.se.symbolic(lpcbData)
            size = self.state.mem[self.state.se.any_int(lpcbData)].int.concrete
            data_str = "These aren't the droids you're looking for."[:size-1] + '\0'
            data = self.state.se.BVV(data_str)
            self.state.memory.store(lpData, data)
            self.state.memory.store(lpcbData, self.state.se.BVV(len(data_str), 32), endness=self.arch.memory_endness)

        ret_expr = 1
        print "RegQueryValueEx: " + str(hKey) + " " + str(lpValueName) + " " + str(lpReserved) + " " +\
              str(lpType) + " " + str(lpData) + " " + str(lpcbData) + " " + "=> " + str(ret_expr)
        return ret_expr


# Debuggers detection

class IsDebuggerPresent(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(IsDebuggerPresent, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self):

        self.argument_types = {}

        self.return_type = simuvex.s_type.SimTypeInt()

        ret_expr = 0  # always return false
        print "IsDebuggerPresent: " + "=> " + str(ret_expr)
        return ret_expr


class OutputDebugString(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(OutputDebugString, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpOutputString):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
        }

        self.state.paranoid.last_error = 1284  # Update last error since debugger is not present

        self.return_type = None

        print "OutputDebugString: " + str(lpOutputString) + " " + "=> " + "void"
        return


# CPU information based detection

def rdtsc_hook(state):
    state.paranoid.tsc += 500  # magic number (pafish detects if consecutive runs diff is between 0 and 750)
    return state.se.BVV(state.paranoid.tsc, 64), []

# CPUID based detection tricks don't need any handling (simuvex dirty helper emulates a real cpu info)


# Generic sandbox detection

class GetCursorPos(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetCursorPos, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpPoint):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
        }

        x = self.state.se.BVV(randint(0, 300), 32)
        y = self.state.se.BVV(randint(0, 300), 32)

        self.state.memory.store(lpPoint, x, endness=self.arch.memory_endness)
        self.state.memory.store(lpPoint+4, y, endness=self.arch.memory_endness)

        self.return_type = simuvex.s_type.SimTypeInt()
        ret_expr = 1
        print "GetCursorPos: " + str(lpPoint) + " " + "=> " + str(ret_expr)
        return ret_expr


class GetUserName(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetUserName, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, lpBuffer, lpnSize):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
            1: self.ty_ptr(simuvex.s_type.SimTypeInt()),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(lpBuffer)
        if self.state.se.any_int(lpBuffer) != 0:  # not NULL
            assert not self.state.se.symbolic(lpnSize)
            size_ptr = self.state.se.any_int(lpnSize)
            size = self.state.mem[size_ptr].int.concrete  # assuming lpcbData is not null
            user_str = "AngryPafish"[:size-1] + '\0'
            user = self.state.se.BVV(user_str)
            self.state.memory.store(lpBuffer, user)
            self.state.memory.store(lpnSize, self.state.se.BVV(len(user_str), 32), endness=self.arch.memory_endness)

        ret_expr = 1
        print "GetUserName: " + str(lpBuffer) + " " + str(lpnSize) + " " + "=> " + str(ret_expr)
        return ret_expr


class GetModuleFileName(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetModuleFileName, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 3

    def run(self, hModule, lpFilename, nSize):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(simuvex.s_type.SimTypeString()),
            2: simuvex.s_type.SimTypeInt(),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(hModule)
        assert not self.state.se.symbolic(lpFilename)
        if self.state.se.any_int(hModule) == 0:  # NULL, retrieve path of the exe of the current process
            assert not self.state.se.symbolic(nSize)
            size = self.state.se.any_int(nSize)
            path_str = "//AngryPafish"[:size-1] + '\0'
            path = self.state.se.BVV(path_str)
            self.state.memory.store(lpFilename, path)
            ret_expr = len(path_str)
        else:
            self.state.memory.store(lpFilename, self.state.se.BVS("unc_data_GetModuleFileName", 32))
            ret_expr = self.state.se.BVS("unc_ret_GetModuleFileName", 32)

        print "GetModuleFileName: " + str(hModule) + " " + str(lpFilename) + " " + str(nSize) +\
              " " + "=> " + str(ret_expr)
        return ret_expr


class GetLogicalDriveStrings(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetLogicalDriveStrings, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, nBufferLength, lpBuffer):

        self.argument_types = {
            0: simuvex.s_type.SimTypeInt(),
            1: self.ty_ptr(simuvex.s_type.SimTypeString()),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(lpBuffer)
        assert not self.state.se.symbolic(nBufferLength)
        drives_str = "C:\\"

        if self.state.se.any_int(nBufferLength) >= len(drives_str):  # nBufferLength does NOT include terminating null
            data = self.state.se.BVV(drives_str + '\0')
            self.state.memory.store(lpBuffer, data)
        else:
            pass  # return the required buffer size to store it all

        ret_expr = len(drives_str)
        print "GetLogicalDriveStrings: " + str(nBufferLength) + " " + str(lpBuffer) + " " + "=> " + str(ret_expr)
        return ret_expr


class CreateFile(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CreateFile, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 7

    def run(self, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
            1: simuvex.s_type.SimTypeInt(),
            2: simuvex.s_type.SimTypeInt(),
            3: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            4: simuvex.s_type.SimTypeInt(),
            5: simuvex.s_type.SimTypeInt(),
            6: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpFileName)
        assert not self.state.se.symbolic(dwDesiredAccess)
        file_name = self.state.mem[self.state.se.any_int(lpFileName)].string.concrete
        ret_expr = self.state.se.BVS("unc_ret_CreateFile_{}".format(file_name), 32)

        access = self.state.se.any_int(dwDesiredAccess)
        if access & 0x80000000:  # GENERIC_READ
            vm_related = any(vm_str in file_name.lower() for vm_str in VM_STRINGS)
            if vm_related:
                ret_expr = -1  # INVALID_HANDLE_VALUE

        if file_name == '\\\\.\\PhysicalDrive0':  # gensandbox_drive_size hack
            ret_expr = -1  # INVALID_HANDLE_VALUE

        print "CreateFile: " + str(lpFileName) + " " + str(dwDesiredAccess) + " " + str(dwShareMode) + " " +\
              str(lpSecurityAttributes) + " " + str(dwCreationDisposition) + " " + str(dwFlagsAndAttributes) + " " +\
              str(hTemplateFile) + " " + "=> " + str(ret_expr)
        return ret_expr


class GetDiskFreeSpaceEx(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetDiskFreeSpaceEx, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, lpDirectoryName, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
            1: self.ty_ptr(simuvex.s_type.SimTypeInt()),
            2: self.ty_ptr(simuvex.s_type.SimTypeInt()),
            3: self.ty_ptr(simuvex.s_type.SimTypeInt()),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        ret_expr = 0  # fail the call
        print "GetDiskFreeSpace: " + str(lpDirectoryName) + " " + str(lpFreeBytesAvailable) + " " +\
              str(lpTotalNumberOfBytes) + " " + str(lpTotalNumberOfFreeBytes) + " " + "=> " + str(ret_expr)
        return ret_expr


class Sleep(simuvex.SimProcedure):
    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(Sleep, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, dwMilliseconds):
        self.argument_types = {
            0: simuvex.s_type.SimTypeInt(),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        self.state.paranoid.tsc += dwMilliseconds.args[0] * TICKS_PER_MS

        print "Sleep: " + str(dwMilliseconds) + " " + "=> " + "void"
        return


class GetTickCount(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetTickCount, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self, ):

        self.argument_types = {}

        self.return_type = simuvex.s_type.SimTypeInt()

        self.state.paranoid.tsc += TICKS_PER_MS  # increase it just to be on the safe side

        ret_expr = self.state.paranoid.tsc // TICKS_PER_MS
        print "GetTickCount: " + "=> " + str(ret_expr)
        return ret_expr


class GetSystemInfo(simuvex.SimProcedure):
    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetSystemInfo, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpSystemInfo):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = None

        sysinfo_struct = self.state.se.BVS('SYSTEM_INFO', 36*8)
        self.state.memory.store(lpSystemInfo, sysinfo_struct)
        dwNumberOfProcessors = sysinfo_struct.get_bytes(20, 4)
        self.state.se.add(claripy.UGE(dwNumberOfProcessors, 2))  # dwNumberOfProcessors >= 2
        self.state.memory.store(lpSystemInfo+20, dwNumberOfProcessors)
        # Note: the value is correctly constrained, still angr doesn't seem to be aware of it.
        # This is because angr only checks satisfiability for branches that affect control flow.
        # Because of the particular structure of the gensandbox_one_cpu_GetSystemInfo check,
        # i.e. return siSysInfo.dwNumberOfProcessors < 2 ? TRUE : FALSE;
        # the branch does not affect control flow and thus the return value remains conditional.

        print "GetSystemInfo: " + str(lpSystemInfo) + " " + "=> " + 'void'
        return


class GlobalMemoryStatusEx(simuvex.SimProcedure):
    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GlobalMemoryStatusEx, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpBuffer):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        memstatus_struct = self.state.se.BVS('MEMORYSTATUSEX', 68*8)  # dwLength is concrete
        self.state.memory.store(lpBuffer+4, memstatus_struct)
        ullTotalPhys = memstatus_struct.get_bytes(8, 8)
        self.state.se.add(claripy.UGE(ullTotalPhys, 2**30))  # ullTotalPhys >= 1 GB
        self.state.memory.store(lpBuffer+8, ullTotalPhys, endness=self.arch.memory_endness)

        ret_expr = 1
        print "GlobalMemoryStatusEx: " + str(lpBuffer) + " " + "=> " + str(ret_expr)
        return ret_expr


# Sandboxie detection tricks


# Wine detection tricks


# VirtualBox detection tricks

class GetAdaptersAddresses(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetAdaptersAddresses, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, Family, Flags, Reserved, AdapterAddresses, SizePointer):

        self.argument_types = {
            0: simuvex.s_type.SimTypeLong(),
            1: simuvex.s_type.SimTypeLong(),
            2: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
            4: self.ty_ptr(simuvex.s_type.SimTypeLong()),
        }

        self.return_type = simuvex.s_type.SimTypeLong()

        assert not self.state.se.symbolic(AdapterAddresses) and not self.state.se.symbolic(SizePointer)
        if self.state.se.any_int(AdapterAddresses) == 0:  # NULL, insert required buffer size in SizePointer
            # insert 0x90 (i.e. sizeof(IP_ADAPTER_ADDRESSES)) in SizePointer
            self.state.memory.store(SizePointer, self.state.se.BVV(0x90, 32), endness=self.arch.memory_endness)
            ret_expr = 0x6F  # return 0x6F (i.e. ERROR_BUFFER_OVERFLOW)
        else:  # return a single random address (assuming function has been correctly invoked and space allocated)
            adapter_struct = self.state.se.BVS('IP_ADAPTER_ADDRESSES', 0x90 * 8)
            self.state.memory.store(AdapterAddresses, adapter_struct)
            # concretize relevant fields
            PhysicalAddressLength = AdapterAddresses + 52
            self.state.memory.store(PhysicalAddressLength, self.state.se.BVV(6, 32), endness=self.arch.memory_endness)
            PhysicalAddress = AdapterAddresses + 44
            for i in range(6):  # generate random mac
                self.state.memory.store(PhysicalAddress + i, self.state.se.BVV(getrandbits(8), 8))
            Next = AdapterAddresses + 8
            self.state.memory.store(Next, self.state.se.BVV(0, 32))
            ret_expr = 1  # NO_ERROR

        print "GetAdaptersAddresses: " + str(Family) + " " + str(Flags) + " " + str(Reserved) + " " +\
              str(AdapterAddresses) + " " + str(SizePointer) + " " + "=> " + str(ret_expr)
        return ret_expr


class FindWindow(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(FindWindow, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, lpClassName, lpWindowName):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
            1: self.ty_ptr(simuvex.s_type.SimTypeString()),
        }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpClassName)
        assert not self.state.se.symbolic(lpWindowName)
        class_name_ptr = self.state.se.any_int(lpClassName)
        class_name = ''
        if class_name_ptr != 0:
            class_name = self.state.mem[class_name_ptr].string.concrete
        win_name_ptr = self.state.se.any_int(lpWindowName)
        win_name = ''
        if win_name_ptr != 0:
            win_name = self.state.mem[win_name_ptr].string.concrete
        vm_related_class_name = any(vm_str in class_name.lower() for vm_str in VM_STRINGS)
        vm_related_win_name = any(vm_str in win_name.lower() for vm_str in VM_STRINGS)
        if vm_related_class_name or vm_related_win_name:
            ret_expr = 0  # NULL, i.e. not found
        else:
            ret_expr = self.state.se.BVS("unc_ret_FindWindow_{}_{}".format(class_name, win_name), 32)

        print "FindWindow: " + str(lpClassName) + " " + str(lpWindowName) + " " + "=> " + str(ret_expr)
        return ret_expr


class WNetGetProviderName(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(WNetGetProviderName, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 3

    def run(self, dwNetType, lpProviderName, lpBufferSize):
        self.argument_types = {
            0: simuvex.s_type.SimTypeInt(),
            1: self.ty_ptr(simuvex.s_type.SimTypeString()),
            2: self.ty_ptr(simuvex.s_type.SimTypeInt()),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(dwNetType)
        assert not self.state.se.symbolic(lpProviderName)
        assert not self.state.se.symbolic(lpBufferSize)
        if self.state.se.any_int(dwNetType) == 0x00250000:  # WNNC_NET_RDR2SAMPLE, for vbox shared folders
            size = self.state.se.any_int(lpBufferSize)
            name_str = "//AngryPafish"[:size - 1] + '\0'
            name = self.state.se.BVV(name_str)
            self.state.memory.store(lpProviderName, name)
            ret_expr = 1  # NO_ERROR
        else:
            self.state.memory.store(lpProviderName, self.state.se.BVS("unc_data_WNetGetProviderName", 32))
            ret_expr = self.state.se.BVS("unc_ret_WNetGetProviderName", 32)

        print "WNetGetProviderName: " + str(dwNetType) + " " + str(lpProviderName) + " " + str(
            lpBufferSize) + " " + "=> " + str(ret_expr)
        return ret_expr


class CreateToolhelp32Snapshot(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CreateToolhelp32Snapshot, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, dwFlags, th32ProcessID):
        self.argument_types = {
            0: simuvex.s_type.SimTypeInt(),
            1: simuvex.s_type.SimTypeInt(),
        }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(dwFlags)
        flags = self.state.se.any_int(dwFlags)
        if flags & 0x00000002:  # TH32CS_SNAPPROCESS, to enumerate processes
            ret_expr = -1  # INVALID_HANDLE_VALUE
        else:
            ret_expr = self.state.se.BVS("unc_ret_CreateToolhelp32Snapshot", 32)
        print "CreateToolhelp32Snapshot: " + str(dwFlags) + " " + str(th32ProcessID) + " " + "=> " + str(ret_expr)
        return ret_expr


# Auxiliary functions #

def rdtsc_monkey_patch():
    vex_dirtyhelpers.amd64g_dirtyhelper_RDTSC = rdtsc_hook
    vex_dirtyhelpers.x86g_dirtyhelper_RDTSC = rdtsc_hook


def hook_all(proj):
    # Utilities
    proj.hook_symbol("SetLastError", angr.Hook(SetLastError))
    proj.hook_symbol("GetLastError", angr.Hook(GetLastError))
    proj.hook_symbol("IsWow64Process", angr.Hook(IsWow64Process))
    proj.hook_symbol("LocalAlloc", angr.Hook(LocalAlloc))
    proj.hook_symbol("GlobalAlloc", angr.Hook(GlobalAlloc))
    proj.hook_symbol("LocalFree", angr.Hook(LocalFree))
    proj.hook_symbol("GlobalFree", angr.Hook(GlobalFree))
    proj.hook_symbol("GetFileAttributesA", angr.Hook(GetFileAttributes))
    proj.hook_symbol("RegOpenKeyExA", angr.Hook(RegOpenKeyEx))
    proj.hook_symbol("RegQueryValueExA", angr.Hook(RegQueryValueEx))

    # Debuggers detection
    proj.hook_symbol("IsDebuggerPresent", angr.Hook(IsDebuggerPresent))
    proj.hook_symbol("OutputDebugStringA", angr.Hook(OutputDebugString))

    # CPU info based detection
    rdtsc_monkey_patch()

    # Generic sandbox detection
    proj.hook_symbol("GetCursorPos", angr.Hook(GetCursorPos))
    proj.hook_symbol("GetUserNameA", angr.Hook(GetUserName))
    proj.hook_symbol("GetModuleFileNameA", angr.Hook(GetModuleFileName))
    proj.hook_symbol("GetLogicalDriveStringsA", angr.Hook(GetLogicalDriveStrings))
    proj.hook_symbol("CreateFileA", angr.Hook(CreateFile))
    proj.hook_symbol("GetDiskFreeSpaceExA", angr.Hook(GetDiskFreeSpaceEx))
    proj.hook_symbol("GetTickCount", angr.Hook(GetTickCount))
    proj.hook_symbol("Sleep", angr.Hook(Sleep))
    proj.hook_symbol("GetSystemInfo", angr.Hook(GetSystemInfo))
    proj.hook_symbol("GlobalMemoryStatusEx", angr.Hook(GlobalMemoryStatusEx))

    # Sandboxie detection tricks
    proj.hook_symbol("GetModuleHandleA", angr.Hook(GetModuleHandle))

    # Wine detection tricks
    proj.hook_symbol("GetProcAddress", angr.Hook(GetProcAddress))

    # Virtualbox detection tricks
    proj.hook_symbol("GetAdaptersAddresses", angr.Hook(GetAdaptersAddresses))
    proj.hook_symbol("FindWindowA", angr.Hook(FindWindow))
    proj.hook_symbol("WNetGetProviderNameA", angr.Hook(WNetGetProviderName))
    proj.hook_symbol("CreateToolhelp32Snapshot", angr.Hook(CreateToolhelp32Snapshot))


def patch_memory(proj, state):
    # patch memory to pass number of processors checks - STUB
    # check uses the info contained in the Win32 Thread Information Block (TIB)
    # DON'T THINK WE CAN ACTUALLY DO THIS - SYMBOLIC INDIRECTION

    # patch memory to pass hook evasion checks
    for api in API_HOOK_CHECKS:
        try:
            api_code_addr = proj.loader.main_bin.imports[api].resolvedby.rebased_addr
            state.memory.store(api_code_addr, state.se.BVV(0x8bff, 16))
        except (KeyError, AttributeError):  # api not imported or not resolved
            pass
