import angr
import angr.engines.vex.dirty as vex_dirtyhelpers
import inspect
import cpu_instr_patches
import win32_patches
from angr.calling_conventions import SimCCStdcall

default_rdtsc_helper = vex_dirtyhelpers.amd64g_dirtyhelper_RDTSC


# Auxiliary functions #

def rdtsc_monkey_patch():
    vex_dirtyhelpers.amd64g_dirtyhelper_RDTSC = cpu_instr_patches.rdtsc_patch
    vex_dirtyhelpers.x86g_dirtyhelper_RDTSC = cpu_instr_patches.rdtsc_patch


def rdtsc_monkey_unpatch():
    vex_dirtyhelpers.amd64g_dirtyhelper_RDTSC = default_rdtsc_helper
    vex_dirtyhelpers.x86g_dirtyhelper_RDTSC = default_rdtsc_helper


def hook_all(proj):
    sim_procs = [x for x in win32_patches.__dict__.values() if inspect.isclass(x) and issubclass(x, angr.SimProcedure)]

    for sp in sim_procs:
        if issubclass(sp, win32_patches.StdcallSimProcedure):
            proj.hook_symbol(sp.__name__, sp(cc=SimCCStdcall(proj.arch)))
        else:
            # use default cc for the arch (for x86 it's Cdecl)
            proj.hook_symbol(sp.__name__, sp())

    rdtsc_monkey_patch()