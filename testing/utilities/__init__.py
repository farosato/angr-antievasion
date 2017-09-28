from aux_simprocs import *
from angr.calling_conventions import SimCCCdecl, SimCCStdcall
from angr.procedures.stubs.ReturnUnconstrained import ReturnUnconstrained
import inspect


def _hook_all_aux(proj):
    sim_procs = [x for x in globals().values() if inspect.isclass(x) and issubclass(x, angr.SimProcedure)]

    for sp in sim_procs:
        if issubclass(sp, StdcallSimProcedure):
            proj.hook_symbol(sp.__name__, sp(cc=SimCCStdcall(proj.arch)))
        else:
            # use default cc for the arch (for x86 it's Cdecl)
            proj.hook_symbol(sp.__name__, sp())


def setup(proj, aux_hooks=True, unhook=[], cdecl_stub=[], stdcall_stub=[]):
    if aux_hooks:
        _hook_all_aux(proj)

    for sym in unhook:
        proj.unhook_symbol(sym)

    for sym in cdecl_stub:
        proj.hook_symbol(sym, ReturnUnconstrained(cc=SimCCCdecl(proj.arch), is_stub=True))

    for sym in stdcall_stub:
        proj.hook_symbol(sym, ReturnUnconstrained(cc=SimCCStdcall(proj.arch), is_stub=True))
