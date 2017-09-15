#!/usr/bin/python

import angr
import antievasion_win32api
import logging
import json
from termcolor import colored

# CHECK_TABLE = [
#     ('username', 0x403858),
# ]


def test():
    logging.getLogger('antievasion_win32api').setLevel(logging.INFO)
    logging.getLogger('angr.procedures').setLevel(logging.DEBUG)
    # logging.getLogger('angr.procedures.win32').setLevel(logging.INFO)
    # logging.getLogger().setLevel(logging.WARNING)
    # logging.getLogger('angr.project').setLevel(logging.DEBUG)
    # logging.getLogger('angr.analyses.callee_cleanup_finder').setLevel(logging.INFO)
    # logging.getLogger("cle.loader").setLevel(logging.DEBUG)
    # logging.getLogger("angr.procedures.libc.memcmp").setLevel(logging.DEBUG)

    proj = angr.Project('./pafish.exe', load_options={
            'auto_load_libs': True,
            'use_system_libs': False,
            'case_insensitive': True,
            'custom_ld_path': './windows_dlls',
            'except_missing_libs': True,
        }
    )

    # stub out imports
    proj.analyses.CalleeCleanupFinder(hook_all=True)

    # Alternative, expensive but exhaustive way to stub out all imports
    # for obj in proj.loader.all_pe_objects:
    #     # stub out all imports (by stubbing out each module exports)
    #     export_addrs = [x.rebased_addr for x in obj._exports.values() if x.forwarder is None]
    #     proj.analyses.CalleeCleanupFinder(starts=export_addrs, hook_all=True)

    # anti-evasion hooks
    antievasion_win32api.hook_all(proj)

    # import IPython; IPython.embed()

    if 'CHECK_TABLE' not in globals():
        # load it from json file
        with open('pafish.exe_checks.json', 'r') as jfile:
            global CHECK_TABLE
            CHECK_TABLE = json.load(jfile)

    for check_name, check_addr in CHECK_TABLE:
        print '\n### {} check @ {} ###'.format(check_name, hex(check_addr))

        check_call_state = proj.factory.call_state(check_addr)
        check_call_state.register_plugin("paranoid", antievasion_win32api.ParanoidPlugin())

        simgr = proj.factory.simulation_manager(check_call_state)

        ret_addr = check_call_state.mem[check_call_state.regs.esp].int.concrete

        while len(simgr.active) > 0:
            # print 'ACTIVE before:', simgr.active
            simgr.explore(find=ret_addr)
            # print 'ACTIVE after:', simgr.active
            # print 'FOUND:', simgr.found
            # import IPython; IPython.embed()

        print simgr

        for err in simgr.errored:
            print err.error
            # import IPython; IPython.embed()

        for sim in simgr.found:
            ret = sim.state.regs.eax
            ret_str = colored(ret, 'red')
            if not sim.state.solver.symbolic(ret) and sim.state.solver.eval(ret) == 0:
                ret_str = colored(ret, 'cyan')
            print sim, "returned {}".format(ret_str)
            import IPython; IPython.embed()


if __name__ == '__main__':
    test()
