import angr
import simuvex
import simuvex.engines.vex.dirty as vex_dirtyhelpers
from simuvex.plugins.plugin import SimStatePlugin

from random import randint

TICKS_PER_MS = 10000  # Windows TicksPerMillisecond = 10000
VM_STRINGS = ['vm', 'vbox', 'virtualbox']
API_HOOK_CHECKS = ['DeleteFileW', 'ShellExecuteExW', 'CreateProcessA']


# PLUGINS #

class SimStateParanoid(SimStatePlugin):
    """
        This state plugin keeps track of various paranoid stuff:
    """

    def __init__(self):
        SimStatePlugin.__init__(self)

        self.tsc = 10**9  # random init tick count

    def copy(self):
        c = SimStateParanoid()
        c.tsc = self.tsc

        return c


# HOOKS #

def rdtsc_hook(state):
    # print "GOTCHA!"
    state.paranoid.tsc += 1  # increase it just to be on the safe side
    return state.se.BVV(state.paranoid.tsc, 64), []


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

        # print "Sleep: " + str(dwMilliseconds) + " " + "=> " + "void"


class GetTickCount(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetTickCount, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self, ):

        self.argument_types = {}

        self.return_type = simuvex.s_type.SimTypeInt()

        self.state.paranoid.tsc += TICKS_PER_MS  # increase it just to be on the safe side

        ret_expr = self.state.paranoid.tsc // TICKS_PER_MS
        # print "GetTickCount: " + "=> " + str(ret_expr)
        return ret_expr


class GetCursorPos(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetCursorPos, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpPoint):

        self.argument_types = {
            0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = simuvex.s_type.SimTypeInt()

        x = self.state.se.BVV(randint(0, 300), 32)
        y = self.state.se.BVV(randint(0, 300), 32)

        self.state.memory.store(lpPoint, x)
        self.state.memory.store(lpPoint+4, y)

        ret_expr = 1
        # print "GetCursorPos: " + str(lpPoint) + " " + "=> " + str(ret_expr)
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

        vm_related = any(vm_str in file_name.lower() for vm_str in VM_STRINGS)

        # print file_name
        # print 'VM related: {}'.format(vm_related)

        if vm_related:
            ret_expr = -1  # INVALID_FILE_ATTRIBUTES
        else:
            ret_expr = self.state.se.Unconstrained("unconstrained_ret_GetFileAttributes", 32)

        # print "GetFileAttributes: " + str(lpFileName) + " " + "=> " + str(ret_expr)
        return ret_expr


# Auxiliary functions #

def rdtsc_monkey_patch():
    vex_dirtyhelpers.amd64g_dirtyhelper_RDTSC = rdtsc_hook
    vex_dirtyhelpers.x86g_dirtyhelper_RDTSC = rdtsc_hook


def hook_all(proj):
    rdtsc_monkey_patch()
    proj.hook_symbol("GetTickCount", angr.Hook(GetTickCount))
    proj.hook_symbol("Sleep", angr.Hook(Sleep))
    proj.hook_symbol("GetCursorPos", angr.Hook(GetCursorPos))
    proj.hook_symbol("GetFileAttributesA", angr.Hook(GetFileAttributes))


def patch_memory(proj, state):
    # patches memory to pass hook evasion checks
    for api in API_HOOK_CHECKS:
        try:
            api_code_addr = proj.loader.main_bin.imports[api].resolvedby.rebased_addr
            state.memory.store(api_code_addr, state.se.BVV(0x8bff, 16))
        except (KeyError, AttributeError):  # api not imported or not resolved
            pass
