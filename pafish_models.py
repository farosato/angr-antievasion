import angr
import simuvex
import simuvex.engines.vex.dirty as vex_dirtyhelpers
from simuvex.plugins.plugin import SimStatePlugin
import claripy

from random import randint

TICKS_PER_MS = 10000  # Windows TicksPerMillisecond = 10000
MALWARE_STRINGS = ['malware', 'sample', 'virus']
VM_STRINGS = ['vm', 'vbox', 'virtualbox', 'sandboxie', 'sboxie', 'wine', 'qemu', 'bochs']
API_HOOK_CHECKS = ['DeleteFileW', 'ShellExecuteExW', 'CreateProcessA']


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


class GetFileAttributes(simuvex.SimProcedure):
    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetFileAttributes, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpFileName):
        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeString()),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        file_name = self.state.mem[lpFileName.args[0]].string.concrete

        malware_related = any(mal_str in file_name.lower() for mal_str in MALWARE_STRINGS)
        vm_related = any(vm_str in file_name.lower() for vm_str in VM_STRINGS)

        print file_name, "malware:", malware_related, "vm:", vm_related

        if malware_related or vm_related:
            ret_expr = -1  # INVALID_FILE_ATTRIBUTES, i.e. file not found
        else:
            ret_expr = self.state.se.BVS("unconstrained_ret_GetFileAttributes", 32)

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

        regkey_name = self.state.mem[lpSubKey.args[0]].string.concrete

        vm_related = any(vm_str in regkey_name.lower() for vm_str in VM_STRINGS)

        if vm_related:
            ret_expr = 2  # ERROR_FILE_NOT_FOUND
        else:
            ret_expr = 0  # self.state.se.Unconstrained("unconstrained_ret_RegOpenKeyEx", 32)

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

        if lpData.args[0] != 0:  # not NULL
            size_ptr = lpcbData.args[0]
            size = self.state.mem[size_ptr].int.concrete  # assuming lpcbData is not null
            data_str = "These aren't the droids you're looking for."[:size-1] + '\0'
            data = self.state.se.BVV(data_str)
            self.state.memory.store(lpData.args[0], data)
            self.state.memory.store(size_ptr, self.state.se.BVV(len(data_str), 32))

        ret_expr = 0
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

        self.state.memory.store(lpPoint, x)
        self.state.memory.store(lpPoint+4, y)

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

        if lpBuffer.args[0] != 0:  # not NULL
            size_ptr = lpnSize.args[0]
            size = self.state.mem[size_ptr].int.concrete  # assuming lpcbData is not null
            user_str = "AngryPafish"[:size-1] + '\0'
            user = self.state.se.BVV(user_str)
            self.state.memory.store(lpBuffer.args[0], user)
            self.state.memory.store(size_ptr, self.state.se.BVV(len(user_str), 32))

        self.return_type = simuvex.s_type.SimTypeInt()
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

        if hModule.args[0] == 0:  # NULL, retrieve path of the exe of the current process
            size = nSize.args[0]  # assuming nSize is concrete
            path_str = "//AngryPafish"[:size-1] + '\0'
            path = self.state.se.BVV(path_str)
            self.state.memory.store(lpFilename.args[0], path)
            ret_expr = len(path_str)
        else:
            self.state.memory.store(lpFilename.args[0],
                                    self.state.se.BVS("unconstrained_filename_GetModuleFileName", 32))
            ret_expr = self.state.se.BVS("unconstrained_ret_GetModuleFileName", 32)

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

        drives_str = "C:\\"

        if nBufferLength.args[0] >= len(drives_str):
            data = self.state.se.BVV(drives_str + '\0')
            self.state.memory.store(lpBuffer.args[0], data)

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

        file_name = self.state.mem[lpFileName.args[0]].string.concrete
        if file_name == '\\\\.\\PhysicalDrive0':
            ret_expr = -1  # INVALID_HANDLE_VALUE
        else:
            ret_expr = self.state.se.BVS("unconstrained_ret_CreateFile", 32)
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
        import IPython; IPython.embed()

        memstatus_struct = self.state.se.BVS('MEMORYSTATUSEX', 68*8)  # dwLength is concrete
        self.state.memory.store(lpBuffer+4, memstatus_struct)
        ullTotalPhys = memstatus_struct.get_bytes(8, 8)
        self.state.se.add(claripy.UGE(ullTotalPhys, 2**30))  # ullTotalPhys >= 1 GB
        self.state.memory.store(lpBuffer+8, ullTotalPhys)
        import IPython; IPython.embed()
        ret_expr = 1
        print "GlobalMemoryStatusEx: " + str(lpBuffer) + " " + "=> " + str(ret_expr)
        return ret_expr


# Auxiliary functions #

def rdtsc_monkey_patch():
    vex_dirtyhelpers.amd64g_dirtyhelper_RDTSC = rdtsc_hook
    vex_dirtyhelpers.x86g_dirtyhelper_RDTSC = rdtsc_hook


def hook_all(proj):
    # Utilities
    proj.hook_symbol("SetLastError", angr.Hook(SetLastError))
    proj.hook_symbol("GetLastError", angr.Hook(GetLastError))
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
