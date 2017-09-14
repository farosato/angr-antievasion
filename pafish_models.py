import copy

import angr
import angr.engines.vex.dirty as vex_dirtyhelpers
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from random import randint, getrandbits
import logging

l = logging.getLogger('AngryPafish')

TICKS_PER_MS = 10000  # Windows TicksPerMillisecond = 10000
MALWARE_STRINGS = ['malware', 'sample', 'virus']
VM_STRINGS = ['vm', 'hgfs', 'vbox', 'virtualbox', 'sandboxie', 'sboxie', 'wine', 'qemu', 'bochs']
API_HOOK_CHECKS = ['DeleteFileW', 'ShellExecuteExW', 'CreateProcessA']
WHITELISTED_MODULES = ['kernel32.dll']
BLACKLISTED_MODULES = ['sbiedll.dll', 'dbghelp.dll', 'api_log.dll', 'dir_watch.dll', 'pstorec.dll', 'vmcheck.dll',
                       'wpespy.dll']
BLACKLISTED_SYMBOLS = ['IsWow64Process', 'IsNativeVhdBoot', 'wine_get_unix_file_name']
SENSITIVE_KEYS = {
    'HARDWARE\DESCRIPTION\SYSTEM': {'SYSTEMBIOSVERSION': '1',
                                    'VIDEOBIOSVERSION': '1',
                                    'SYSTEMBIOSDATE': '01/01/2018'},
    'HARDWARE\DEVICEMAP\SCSI\SCSI PORT 0\SCSI BUS 0\TARGET ID 0\LOGICAL UNIT ID 0': {'IDENTIFIER': 'INTEL'},
    'HARDWARE\DEVICEMAP\SCSI\SCSI PORT 1\SCSI BUS 0\TARGET ID 0\LOGICAL UNIT ID 0': {'IDENTIFIER': 'INTEL'},
    'HARDWARE\DEVICEMAP\SCSI\SCSI PORT 2\SCSI BUS 0\TARGET ID 0\LOGICAL UNIT ID 0': {'IDENTIFIER': 'INTEL'},
}

VERBOSE = True


# PLUGINS #

class SimStateParanoid(SimStatePlugin):
    """
        This state plugin keeps track of various paranoid stuff:
    """

    def __init__(self):
        SimStatePlugin.__init__(self)
        self.tsc = 50 * 1000 * 60 * TICKS_PER_MS  # init tick count ~= 50 minutes
        self.last_error = 0  # should be thread-local, but angr does NOT currently support threads
        self.open_regkeys = {}  # handle -> string id

    def copy(self):
        c = SimStateParanoid()
        c.tsc = self.tsc
        c.last_error = self.last_error
        c.open_regkeys = self.open_regkeys.copy()  # shallow copy should be enough (handles don't change target)
        return c


# API HOOKS #

# Utilities

class lstrcmpiA(angr.SimProcedure):
    def run(self, lpString1, lpString2):
        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()),
                               1: self.ty_ptr(angr.sim_type.SimTypeString())}
        self.return_type = angr.sim_type.SimTypeInt(32, True)

        assert not self.state.solver.symbolic(lpString1)
        assert not self.state.solver.symbolic(lpString2)

        str1 = self.state.mem[self.state.solver.eval(lpString1)].string.concrete
        str_l1 = str1.lower()
        str2 = self.state.mem[self.state.solver.eval(lpString2)].string.concrete
        str_l2 = str2.lower()
        ret_expr = -1 if str_l1 < str_l2 else 1 if str_l1 > str_l2 else 0

        l.info('{} @ {}: {} ({}), {} ({}) => {}'.format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            lpString1, str1, lpString2, str2, ret_expr))
        return ret_expr


class SetLastError(angr.SimProcedure):
    def run(self, dwErrCode):
        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
        }

        self.state.paranoid.last_error = dwErrCode.args[0]

        self.return_type = angr.sim_type.SimTypeInt()

        l.info('{} @ {}: {} => void'.format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(dwErrCode)))
        return


class GetLastError(angr.SimProcedure):
    def run(self):
        self.argument_types = {}

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = self.state.paranoid.last_error
        l.info('{} @ {}: => {}'.format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(ret_expr)))
        return ret_expr


class GetModuleHandleA(angr.SimProcedure):
    def run(self, lpModuleName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.solver.symbolic(lpModuleName)
        module_name = self.state.mem[self.state.solver.eval(lpModuleName)].string.concrete

        if module_name.lower() in BLACKLISTED_MODULES:
            ret_expr = 0  # NULL, i.e. module not found
        else:
            ret_expr = self.state.solver.BVS("retval_{}_{}".format(self.__class__.__name__, module_name), 32)
            if module_name.lower() in WHITELISTED_MODULES:
                self.state.solver.add(ret_expr != 0)

        l.info("{} @ {}: {} ({}) => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpModuleName), module_name, str(ret_expr)))
        return ret_expr


class GetProcAddress(angr.SimProcedure):
    def run(self, hModule, lpProcName):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString())
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.solver.symbolic(lpProcName)

        lpProcName_int_high = self.state.solver.eval(lpProcName) & 0xFFFF0000

        if lpProcName_int_high == 0:  # ordinal import
            assert False  # TODO: add support ordinal value
        else:
            sym_name = self.state.mem[self.state.solver.eval(lpProcName)].string.concrete
            if sym_name in BLACKLISTED_SYMBOLS:
                ret_expr = 0  # NULL, i.e. symbol not found
            else:
                ret_expr = self.state.solver.BVS("retval_{}_{}".format(self.__class__.__name__, sym_name), 32)

        l.info("{} @ {}: {}, {} ({}) => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hModule), str(lpProcName), sym_name, str(ret_expr)))
        return ret_expr


class IsWow64Process(angr.SimProcedure):
    def run(self, hProcess, Wow64Process):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeInt()),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(Wow64Process)
        self.state.memory.store(Wow64Process, self.state.solver.BVV(0, 32))  # always return FALSE
        ret_expr = 1  # success
        l.info("{} @ {}: {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hProcess), str(Wow64Process), str(ret_expr)))
        return ret_expr


class LocalAlloc(angr.SimProcedure):
    def run(self, uFlags, uBytes):
        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
            1: angr.sim_type.SimTypeLength(),
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.solver.symbolic(uBytes)
        # use malloc's simprocedure (copied and pasted)
        if self.state.solver.symbolic(uBytes):  # dead code for now (bc of the previous assert)
            size = self.state.solver.max_int(uBytes)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.solver.eval(uBytes)
        size = self.state.solver.eval(uBytes)

        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size

        # now handle flags
        if not self.state.solver.symbolic(uFlags):
            flags = self.state.solver.eval(uFlags)
            if flags & 0x0040:  # LMEM_ZEROINIT
                self.state.memory.store(addr, self.state.solver.BVV(0, size * 8))

        ret_expr = addr
        l.info("{} @ {}: {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(uFlags), str(uBytes), hex(ret_expr)))
        return ret_expr


class GlobalAlloc(LocalAlloc):
    pass


class LocalFree(angr.SimProcedure):
    def run(self, hMem):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        # just a stub, don't really need to free anything in the libc plugin
        ret_expr = self.state.solver.BVS("retval_{}".format(self.__class__.__name__), 32)
        l.info("{} @ {}: {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hMem), str(ret_expr)))
        return ret_expr


class GlobalFree(LocalFree):
    pass


class GetFileAttributesA(angr.SimProcedure):
    def run(self, lpFileName):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(lpFileName)
        file_name = self.state.mem[self.state.solver.eval(lpFileName)].string.concrete

        malware_related = any(mal_str in file_name.lower() for mal_str in MALWARE_STRINGS)
        vm_related = any(vm_str in file_name.lower() for vm_str in VM_STRINGS)

        if malware_related or vm_related:
            ret_expr = -1  # INVALID_FILE_ATTRIBUTES, i.e. file not found
            self.state.paranoid.last_error = 0x2  # ERROR_FILE_NOT_FOUND
        else:
            ret_expr = self.state.solver.BVS("retval_{}_{}".format(self.__class__.__name__, file_name), 32)

        l.info("{} @ {}: {} () => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpFileName), file_name, str(ret_expr)))
        return ret_expr


class RegOpenKeyExA(angr.SimProcedure):
    #
    def run(self, hKey, lpSubKey, ulOptions, samDesired, phkResult):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = angr.sim_type.SimTypeLong()

        assert not self.state.solver.symbolic(lpSubKey)
        assert not self.state.solver.symbolic(phkResult)

        regkey_name = self.state.mem[self.state.solver.eval(lpSubKey)].string.concrete.upper()

        vm_related = any(vm_str in regkey_name.lower() for vm_str in VM_STRINGS)

        if vm_related:
            ret_expr = 2  # ERROR_FILE_NOT_FOUND
        else:
            handle = self.state.solver.BVS("handle_{}_{}".format(self.__class__.__name__, regkey_name), 32)
            if regkey_name in SENSITIVE_KEYS:
                # common key, so we always succeed in opening it
                self.state.memory.store(phkResult, handle, endness=self.arch.memory_endness)
                self.state.paranoid.open_regkeys[handle] = regkey_name
                ret_expr = 0  # ERROR_SUCCESS
            else:
                # state forking (hackish way of doing it): we either...
                old_state = self.state

                # succeed in opening the key
                success_state = old_state.copy()
                self.state = success_state
                self.state.paranoid.open_regkeys[handle] = regkey_name
                self.state.memory.store(phkResult, handle, endness=self.arch.memory_endness)
                l.info("{} @ {}: {}, {} ({}), {}, {}, {} => {}".format(
                    self.__class__.__name__,
                    self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
                    str(hKey), str(lpSubKey), regkey_name, str(ulOptions), str(samDesired), str(phkResult), 0))
                self.ret(0)  # ERROR_SUCCESS

                # or fail
                fail_state = old_state.copy()
                self.state = fail_state
                ret_expr = self.state.solver.BVS("retval_{}_{}".format(self.__class__.__name__, regkey_name), 32)
                self.state.solver.add(ret_expr != 0)
                l.info("{} @ {}: {}, {} ({}), {}, {}, {} => {}".format(
                    self.__class__.__name__,
                    self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
                    str(hKey), str(lpSubKey), regkey_name, str(ulOptions), str(samDesired), str(phkResult), 0))
                self.ret(ret_expr)

                # N.B. we can't just return the alternative ret_expr because of the way ret is implemented,
                # do NOT "optimize", we need to invoke ret explicitly for both states
                return

        l.info("{} @ {}: {}, {} ({}), {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hKey), str(lpSubKey), regkey_name, str(ulOptions), str(samDesired), str(phkResult), str(ret_expr)))
        return ret_expr


class RegCloseKey(angr.SimProcedure):
    def run(self, hKey):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = angr.sim_type.SimTypeLong()

        assert hKey in self.state.paranoid.open_regkeys

        self.state.paranoid.open_regkeys.pop(hKey, None)
        ret_expr = 1  # success

        l.info('{} @ {}: {} => {}'.format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hKey), ret_expr))
        return ret_expr


class RegQueryValueExA(angr.SimProcedure):
    def run(self, hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: self.ty_ptr(angr.sim_type.SimTypeInt()),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            5: self.ty_ptr(angr.sim_type.SimTypeInt()),
        }

        self.return_type = angr.sim_type.SimTypeLong()


        assert not self.state.solver.symbolic(lpValueName)
        assert not self.state.solver.symbolic(lpData)
        assert not self.state.solver.symbolic(lpcbData)
        assert hKey in self.state.paranoid.open_regkeys

        regkey_name = self.state.paranoid.open_regkeys[hKey]
        value_name = self.state.mem[self.state.solver.eval(lpValueName)].string.concrete.upper()
        buffer_size = self.state.mem[self.state.solver.eval(lpcbData)].int.concrete
        data_str = None

        if regkey_name in SENSITIVE_KEYS and value_name in SENSITIVE_KEYS[regkey_name]:
            if self.state.solver.eval(lpData) != 0:  # i.e. not NULL
                data_str = SENSITIVE_KEYS[regkey_name][value_name][:buffer_size - 1] + '\0'
                data = self.state.solver.BVV(data_str)
                self.state.memory.store(lpData, data)
                self.state.memory.store(lpcbData, self.state.solver.BVV(len(data_str), 32),
                                        endness=self.arch.memory_endness)
            ret_expr = 1
        else:
            if self.state.solver.eval(lpData) != 0:  # i.e. not NULL
                data = self.state.solver.BVS('value_{}_{}_{}'.format(
                    self.__class__.__name__, regkey_name, value_name), buffer_size*8)
                self.state.memory.store(lpData, data)
                size = self.state.solver.BVS('size_{}_{}_{}'.format(
                    self.__class__.__name__, regkey_name, value_name), 32)
                self.state.memory.store(lpcbData, size, endness=self.arch.memory_endness)
            ret_expr = self.state.solver.BVS('retval_{}_{}_{}'.format(
                self.__class__.__name__, regkey_name, value_name), 32)
        l.info("{} @ {}: {}, {}, {}, {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hKey), str(lpValueName), str(lpReserved), str(lpType),
            str(lpData) + (" ({})".format(data_str) if data_str else ""), str(lpcbData), str(ret_expr)))
        return ret_expr


class GetCurrentProcess(angr.SimProcedure):
    def run(self, ):
        self.argument_types = {
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = -1  # special constant that is interpreted as the current process handle
        l.info("{} @ {}: => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(ret_expr)))
        return ret_expr


# Debuggers detection

class IsDebuggerPresent(angr.SimProcedure):
    def run(self):
        self.argument_types = {}

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0  # always return false
        l.info("{} @ {}: => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(ret_expr)))
        return ret_expr


class OutputDebugStringA(angr.SimProcedure):
    def run(self, lpOutputString):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
        }

        self.state.paranoid.last_error = 1284  # Update last error since debugger is not present

        self.return_type = angr.sim_type.SimTypeInt()

        l.info("{} @ {}: {} => void".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpOutputString)))
        return


class CheckRemoteDebuggerPresent(angr.SimProcedure):
    def run(self, hProcess, pbDebuggerPresent):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeInt()),
        }

        self.return_type = angr.sim_type.SimTypeInt()
        assert not self.state.solver.symbolic(pbDebuggerPresent)
        self.state.memory.store(pbDebuggerPresent, self.state.solver.BVV(0, 32))  # always return FALSE
        ret_expr = 1  # success
        l.info("{} @ {}: {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hProcess), str(pbDebuggerPresent), str(ret_expr)))
        return ret_expr


# CPU information based detection

def rdtsc_hook(state):
    state.paranoid.tsc += 500  # magic number (pafish detects if consecutive runs diff is between 0 and 750)
    return state.solver.BVV(state.paranoid.tsc, 64), []


# CPUID based detection tricks don't need any handling (angr.dirty helper emulates a real cpu info)


# Generic sandbox detection

class GetCursorPos(angr.SimProcedure):
    def run(self, lpPoint):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        x = self.state.solver.BVV(randint(0, 300), 32)
        y = self.state.solver.BVV(randint(0, 300), 32)

        self.state.memory.store(lpPoint, x, endness=self.arch.memory_endness)
        self.state.memory.store(lpPoint + 4, y, endness=self.arch.memory_endness)

        self.return_type = angr.sim_type.SimTypeInt()
        ret_expr = 1
        l.info("{} @ {}: {} ({}, {}) => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpPoint), x, y, str(ret_expr)))
        return ret_expr


class GetUserNameA(angr.SimProcedure):
    def run(self, lpBuffer, lpnSize):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeInt()),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(lpBuffer)
        if self.state.solver.eval(lpBuffer) != 0:  # not NULL
            assert not self.state.solver.symbolic(lpnSize)
            size_ptr = self.state.solver.eval(lpnSize)
            size = self.state.mem[size_ptr].int.concrete  # assuming lpcbData is not null
            user_str = "AngryPafish"[:size - 1] + '\0'
            user = self.state.solver.BVV(user_str)
            self.state.memory.store(lpBuffer, user)
            self.state.memory.store(lpnSize, self.state.solver.BVV(len(user_str), 32), endness=self.arch.memory_endness)

        ret_expr = 1
        l.info("{} @ {}: {} ({}), {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpBuffer), user_str, str(lpnSize), str(ret_expr)))
        return ret_expr


class GetModuleFileNameA(angr.SimProcedure):
    def run(self, hModule, lpFilename, nSize):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: angr.sim_type.SimTypeInt(),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(hModule)
        assert not self.state.solver.symbolic(lpFilename)
        assert not self.state.solver.symbolic(nSize)
        size = self.state.solver.eval(nSize)
        path_str = None
        if self.state.solver.eval(hModule) == 0:  # NULL, retrieve path of the exe of the current process
            path_str = "C:\\AngryPafish"[:size - 1] + '\0'
            path = self.state.solver.BVV(path_str)
            self.state.memory.store(lpFilename, path)
            ret_expr = len(path_str)
        else:
            self.state.memory.store(lpFilename,
                                    self.state.solver.BVS("filename_{}".format(self.__class__.__name__), size * 8))
            ret_expr = self.state.solver.BVS("retval_{}".format(self.__class__.__name__), 32)

        l.info("{} @ {}: {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hModule), str(lpFilename) + (" ({})".format(path_str) if path_str else ""),
            str(nSize), str(ret_expr)))
        return ret_expr


class GetLogicalDriveStringsA(angr.SimProcedure):
    def run(self, nBufferLength, lpBuffer):

        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(lpBuffer)
        assert not self.state.solver.symbolic(nBufferLength)
        drives_str = "C:\\"

        data = None
        if self.state.solver.eval(nBufferLength) >= len(drives_str):  # nBufferLength does NOT include terminating null
            data = self.state.solver.BVV(drives_str + '\0')
            self.state.memory.store(lpBuffer, data)
        else:
            pass  # return the required buffer size to store it all

        ret_expr = len(drives_str)
        l.info("{} @ {}: {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(nBufferLength), str(lpBuffer) + (" ({})".format(data) if data else ""), str(ret_expr)))
        return ret_expr


class CreateFileA(angr.SimProcedure):
    def run(self, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
            dwFlagsAndAttributes, hTemplateFile):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: angr.sim_type.SimTypeInt(),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: angr.sim_type.SimTypeInt(),
            5: angr.sim_type.SimTypeInt(),
            6: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.solver.symbolic(lpFileName)
        assert not self.state.solver.symbolic(dwDesiredAccess)
        file_name = self.state.mem[self.state.solver.eval(lpFileName)].string.concrete
        ret_expr = self.state.solver.BVS("retval_{}_{}".format(self.__class__.__name__, file_name), 32)

        access = self.state.solver.eval(dwDesiredAccess)
        if access & 0x80000000:  # GENERIC_READ
            vm_related = any(vm_str in file_name.lower() for vm_str in VM_STRINGS)
            if vm_related:
                ret_expr = -1  # INVALID_HANDLE_VALUE
                self.state.paranoid.last_error = 0x2  # ERROR_FILE_NOT_FOUND
            elif file_name == '\\\\.\\PhysicalDrive0':
                self.state.solver.add(ret_expr != -1)  # valid handle

        l.info("{} @ {}: {} ({}), {}, {}, {}, {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpFileName), file_name, str(dwDesiredAccess), str(dwShareMode), str(lpSecurityAttributes),
            str(dwCreationDisposition), str(dwFlagsAndAttributes), str(hTemplateFile), str(ret_expr)))
        return ret_expr


class DeviceIoControl(angr.SimProcedure):
    def run(self, hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned,
            lpOverlapped):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeInt(),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: angr.sim_type.SimTypeInt(),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            5: angr.sim_type.SimTypeInt(),
            6: self.ty_ptr(angr.sim_type.SimTypeInt()),
            7: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(dwIoControlCode)
        ret_expr = self.state.solver.BVS("retval_{}".format(self.__class__.__name__), 32)
        control_code = self.state.solver.eval(dwIoControlCode)
        if self.state.solver.symbolic(hDevice) and 'PhysicalDrive0' in hDevice.args[0] and control_code == 0x7405c:
            # IOCTL_DISK_GET_LENGTH_INFO on PhysicalDrive0: return properly configured data
            assert not self.state.solver.symbolic(lpOutBuffer)
            assert not self.state.solver.symbolic(nOutBufferSize)
            assert self.state.solver.eval(nOutBufferSize) >= 8  # the buffer can fit the GET_LENGTH_INFO struct
            getlengthinfo_struct = self.state.solver.BVV(128 * 2 ** 30, 8 * 8)  # drive size = 128 GB
            self.state.memory.store(lpOutBuffer, getlengthinfo_struct, endness=self.arch.memory_endness)
            ret_expr = 1  # success

        l.info("{} @ {}: {}, {}, {}, {}, {}, {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(hDevice), str(dwIoControlCode), str(lpInBuffer), str(nInBufferSize), str(lpOutBuffer),
            str(nOutBufferSize), str(lpBytesReturned), str(lpOverlapped), str(ret_expr)))
        return ret_expr


class GetDiskFreeSpaceExA(angr.SimProcedure):
    def run(self, lpDirectoryName, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeInt()),
            2: self.ty_ptr(angr.sim_type.SimTypeInt()),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(lpTotalNumberOfBytes)
        ret_expr = self.state.solver.BVS("retval_{}".format(self.__class__.__name__), 32)
        if self.state.solver.eval(lpTotalNumberOfBytes) != 0:  # not NULL
            getlengthinfo_struct = self.state.solver.BVV(128 * 2 ** 30, 8 * 8)  # drive size = 128 GB
            self.state.memory.store(lpTotalNumberOfBytes, getlengthinfo_struct, endness=self.arch.memory_endness)
            ret_expr = 1  # success

        l.info("{} @ {}: {}, {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpDirectoryName), str(lpFreeBytesAvailable), str(lpTotalNumberOfBytes),
            str(lpTotalNumberOfFreeBytes), str(ret_expr)))
        return ret_expr


class Sleep(angr.SimProcedure):
    def run(self, dwMilliseconds):
        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        self.state.paranoid.tsc += dwMilliseconds.args[0] * TICKS_PER_MS

        l.info("{} @ {}: {} => void".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(dwMilliseconds)))
        return


class GetTickCount(angr.SimProcedure):
    def run(self, ):
        self.argument_types = {}

        self.return_type = angr.sim_type.SimTypeInt()

        self.state.paranoid.tsc += TICKS_PER_MS  # increase it just to be on the safe side

        ret_expr = self.state.paranoid.tsc // TICKS_PER_MS
        l.info("{} @ {}: => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(ret_expr)))
        return ret_expr


class GetSystemInfo(angr.SimProcedure):
    def run(self, lpSystemInfo):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        sysinfo_struct = self.state.solver.BVS('SYSTEM_INFO', 36 * 8)
        self.state.memory.store(lpSystemInfo, sysinfo_struct)
        dwNumberOfProcessors = self.state.solver.BVS('dwNumberOfProcessors', 4 * 8)
        self.state.solver.add(claripy.UGE(dwNumberOfProcessors, 2))  # dwNumberOfProcessors >= 2
        self.state.memory.store(lpSystemInfo + 20, dwNumberOfProcessors)
        # Note: the value is correctly constrained, still angr doesn't seem to be aware of it.
        # This is because angr only checks satisfiability for branches that affect control flow.
        # Because of the particular structure of the gensandbox_one_cpu_GetSystemInfo check,
        # i.e. return siSysInfo.dwNumberOfProcessors < 2 ? TRUE : FALSE;
        # the branch does not affect control flow and thus the return value remains conditional.

        l.info("{} @ {}: {} => void".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpSystemInfo)))
        return


class GlobalMemoryStatusEx(angr.SimProcedure):
    def run(self, lpBuffer):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        memstatus_struct = self.state.solver.BVS('MEMORYSTATUSEX', 68 * 8)  # dwLength is concrete
        self.state.memory.store(lpBuffer + 4, memstatus_struct)  # ignore dwLength field
        ullTotalPhys = self.state.solver.BVV(8 * 2 ** 30, 8 * 8)
        self.state.memory.store(lpBuffer + 8, ullTotalPhys, endness=self.arch.memory_endness)

        ret_expr = 1
        l.info("{} @ {}: {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpBuffer), str(ret_expr)))
        return ret_expr


# Sandboxie detection tricks


# Wine detection tricks


# VirtualBox detection tricks

class GetAdaptersAddresses(angr.SimProcedure):
    def run(self, Family, Flags, Reserved, AdapterAddresses, SizePointer):

        self.argument_types = {
            0: angr.sim_type.SimTypeLong(),
            1: angr.sim_type.SimTypeLong(),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: self.ty_ptr(angr.sim_type.SimTypeLong()),
        }

        self.return_type = angr.sim_type.SimTypeLong()

        assert not self.state.solver.symbolic(AdapterAddresses) and not self.state.solver.symbolic(SizePointer)
        if self.state.solver.eval(AdapterAddresses) == 0:  # NULL, insert required buffer size in SizePointer
            # insert 0x90 (i.e. sizeof(IP_ADAPTER_ADDRESSES)) in SizePointer
            self.state.memory.store(SizePointer, self.state.solver.BVV(0x90, 32), endness=self.arch.memory_endness)
            ret_expr = 0x6F  # return 0x6F (i.e. ERROR_BUFFER_OVERFLOW)
        else:
            # return a single random address (assuming function has been correctly invoked and space allocated)
            adapter_struct = self.state.solver.BVS('IP_ADAPTER_ADDRESSES', 0x90 * 8)
            self.state.memory.store(AdapterAddresses, adapter_struct)
            # concretize relevant fields
            PhysicalAddressLength = AdapterAddresses + 52
            self.state.memory.store(PhysicalAddressLength, self.state.solver.BVV(6, 32),
                                    endness=self.arch.memory_endness)
            PhysicalAddress = AdapterAddresses + 44
            for i in range(6):  # generate random mac
                self.state.memory.store(PhysicalAddress + i, self.state.solver.BVV(getrandbits(8), 8))
            Next = AdapterAddresses + 8
            self.state.memory.store(Next, self.state.solver.BVV(0, 32))
            Description = AdapterAddresses + 36
            lp_description = self.inline_call(LocalAlloc, 0x0040, 128).ret_expr  # allocate space for the wstring
            description = self.state.solver.BVV('Intel(R) Gigabit Network Connection\0'.encode('utf-16'))  # wchar string
            self.state.memory.store(lp_description, description)
            self.state.memory.store(Description, lp_description, endness=self.arch.memory_endness)
            ret_expr = 0  # NO_ERROR

        l.info("{} @ {}: {}, {}, {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(Family), str(Flags), str(Reserved), str(AdapterAddresses), str(SizePointer), str(ret_expr)))
        return ret_expr


class FindWindowA(angr.SimProcedure):
    def run(self, lpClassName, lpWindowName):
        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.solver.symbolic(lpClassName)
        assert not self.state.solver.symbolic(lpWindowName)
        class_name_ptr = self.state.solver.eval(lpClassName)
        class_name = ''
        if class_name_ptr != 0:
            class_name = self.state.mem[class_name_ptr].string.concrete
        win_name_ptr = self.state.solver.eval(lpWindowName)
        win_name = ''
        if win_name_ptr != 0:
            win_name = self.state.mem[win_name_ptr].string.concrete
        vm_related_class_name = any(vm_str in class_name.lower() for vm_str in VM_STRINGS)
        vm_related_win_name = any(vm_str in win_name.lower() for vm_str in VM_STRINGS)
        if vm_related_class_name or vm_related_win_name:
            ret_expr = 0  # NULL, i.e. not found
        else:
            ret_expr = self.state.solver.BVS("retval_{}_{}_{}".format(self.__class__.__name__, class_name, win_name),
                                             32)

        l.info("{} @ {}: {} ({}), {} ({}) => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(lpClassName), class_name, str(lpWindowName), win_name, str(ret_expr)))
        return ret_expr


class WNetGetProviderNameA(angr.SimProcedure):
    def run(self, dwNetType, lpProviderName, lpBufferSize):
        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: self.ty_ptr(angr.sim_type.SimTypeInt()),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(dwNetType)
        assert not self.state.solver.symbolic(lpProviderName)
        assert not self.state.solver.symbolic(lpBufferSize)
        size = self.state.solver.eval(lpBufferSize)
        if self.state.solver.eval(dwNetType) == 0x00250000:  # WNNC_NET_RDR2SAMPLE, for vbox shared folders
            name_str = "AngryPafish"[:size - 1] + '\0'
            name = self.state.solver.BVV(name_str)
            self.state.memory.store(lpProviderName, name)
            ret_expr = 0  # NO_ERROR
        else:
            self.state.memory.store(lpProviderName,
                                    self.state.solver.BVS("provider_name_{}".format(self.__class__.__name__), size * 8))
            ret_expr = self.state.solver.BVS("retval_{}".format(self.__class__.__name__), 32)

        l.info("{} @ {}: {}, {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(dwNetType), str(lpProviderName), str(lpBufferSize), str(ret_expr)))
        return ret_expr


class CreateToolhelp32Snapshot(angr.SimProcedure):
    def run(self, dwFlags, th32ProcessID):
        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
            1: angr.sim_type.SimTypeInt(),
        }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.solver.symbolic(dwFlags)
        flags = self.state.solver.eval(dwFlags)
        if flags & 0x00000002:  # TH32CS_SNAPPROCESS, to enumerate processes
            ret_expr = -1  # INVALID_HANDLE_VALUE
        else:
            ret_expr = self.state.solver.BVS("retval_{}".format(self.__class__.__name__), 32)

        l.info("{} @ {}: {}, {} => {}".format(
            self.__class__.__name__, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            str(dwFlags), str(th32ProcessID), str(ret_expr)))
        return ret_expr


# Auxiliary functions #

def rdtsc_monkey_patch():
    vex_dirtyhelpers.amd64g_dirtyhelper_RDTSC = rdtsc_hook
    vex_dirtyhelpers.x86g_dirtyhelper_RDTSC = rdtsc_hook


def hook_all(proj):
    api_hooks = [
        lstrcmpiA,
        SetLastError,
        GetLastError,
        IsWow64Process,
        LocalAlloc,
        LocalFree,
        GlobalAlloc,
        GlobalFree,
        GetFileAttributesA,
        RegOpenKeyExA,
        RegCloseKey,
        RegQueryValueExA,
        GetCurrentProcess,
        IsDebuggerPresent,
        OutputDebugStringA,
        CheckRemoteDebuggerPresent,
        GetCursorPos,
        GetUserNameA,
        GetModuleFileNameA,
        GetLogicalDriveStringsA,
        CreateFileA,
        DeviceIoControl,
        GetDiskFreeSpaceExA,
        GetTickCount,
        Sleep,
        GetSystemInfo,
        GlobalMemoryStatusEx,
        GetModuleHandleA,
        GetProcAddress,
        GetAdaptersAddresses,
        FindWindowA,
        WNetGetProviderNameA,
        CreateToolhelp32Snapshot,
    ]

    from angr.calling_conventions import SimCCStdcall
    for sim_proc in api_hooks:
        proj.hook_symbol(sim_proc.__name__, sim_proc(cc=SimCCStdcall(proj.arch)))

    rdtsc_monkey_patch()


def patch_memory(state):
    # patch memory to pass number of processors checks - STUB
    # check uses the info contained in the Win32 Thread Information Block (TIB)
    # DON'T THINK WE CAN ACTUALLY DO THIS - SYMBOLIC INDIRECTION

    # patch memory to pass hook evasion checks
    for api in API_HOOK_CHECKS:
        try:
            api_code_addr = state.project.loader.find_symbol(api).rebased_addr
            # since the memory is somehow concrete, we need to actually store a concrete value
            # rather than constraint a symbolic one
            state.memory.store(api_code_addr, state.solver.BVV(0x8bff, 16))
        except (KeyError, AttributeError):  # api not imported or not resolved
            pass
