#!/usr/bin/python

import angr
# python path hack to import package angr_antievasion in sibling directory
import os
rootdir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.sys.path.insert(0, rootdir)
import angr_antievasion
import testing.utilities
import logging
import json
from termcolor import colored

CHECK_TABLE = [
    ('vbox_regkey9', 4209898),
]

UNAIDED_SKIP = ['vbox_mac', 'vbox_processes', 'vmware_mac', 'vmware_adapter_name',
                'vbox_reg_key9', 'vbox_sysfile2', 'vmware_reg_key1']


def test():
    logging.getLogger('angr_antievasion').setLevel(logging.INFO)
    logging.getLogger('testing.utilities').setLevel(logging.INFO)
    logging.getLogger('angr.procedures').setLevel(logging.DEBUG)

    proj_unaided = angr.Project('./pafish.exe', load_options={
        'auto_load_libs': True,
        'use_system_libs': False,
        'case_insensitive': True,
        'custom_ld_path': '../../windows_dlls',
        'except_missing_libs': True,
    })

    proj_extended = angr.Project('./pafish.exe', load_options={
        'auto_load_libs': True,
        'use_system_libs': False,
        'case_insensitive': True,
        'custom_ld_path': '../../windows_dlls',
        'except_missing_libs': True,
    })

    # stub out imports
    proj_unaided.analyses.CalleeCleanupFinder(hook_all=True)
    proj_extended.analyses.CalleeCleanupFinder(hook_all=True)

    # Alternative, expensive but exhaustive way to stub out all imports
    # for obj in proj.loader.all_pe_objects:
    #     # stub out all imports (by stubbing out each module exports)
    #     export_addrs = [x.rebased_addr for x in obj._exports.values() if x.forwarder is None]
    #     proj.analyses.CalleeCleanupFinder(starts=export_addrs, hook_all=True)

    # setup testing utilities
    # symbols for which no SimProcedure is available and/or is better to use the actual implementation
    no_sim_syms = ['_vsnprintf', 'mbstowcs', 'wcsstr', 'toupper', 'tolower', 'lstrcmpiA', 'lstrcmpiW']
    # snprintf is (ab)used by pafish: angr stub returns an empty string so it's useless
    # we use the concrete implementation for the extended, and an unconstrained stub for the unaided
    testing.setup(proj_unaided, cdecl_stub=['_vsnprintf'], stdcall_stub=['IsWow64Process'])
    testing.setup(proj_extended, unhook=no_sim_syms)

    # anti-evasion hooks
    angr_antievasion.hook_all(proj_extended)

    # return addresses for the check call state configuration
    ret_addr_unaided = proj_unaided.loader.extern_object.allocate()
    ret_addr_extended = proj_extended.loader.extern_object.allocate()

    # import IPython; IPython.embed()

    if 'CHECK_TABLE' not in globals():
        # load it from json file
        with open('pafish.exe_checks.json', 'r') as jfile:
            global CHECK_TABLE
            CHECK_TABLE = json.load(jfile)

    latex_table = []

    for check_name, check_addr in CHECK_TABLE:
        print '\n### {} check @ {} ###'.format(check_name, hex(check_addr))

        call_state_unaided = proj_unaided.factory.call_state(check_addr, ret_addr=ret_addr_unaided)
        call_state_extended = proj_extended.factory.call_state(check_addr, ret_addr=ret_addr_extended)

        simgr_unaided = proj_unaided.factory.simulation_manager(call_state_unaided, save_unconstrained=True)
        simgr_extended = proj_extended.factory.simulation_manager(call_state_extended, save_unconstrained=True)

        print '! Unaided exploration !'
        unaided_total = 0
        unaided_false = 0
        unaided_true = 0

        if check_name in UNAIDED_SKIP:
            print 'SKIPPED'
        else:
            angr_antievasion.rdtsc_monkey_unpatch()  # monkey patch is global so we need to patch and unpatch for each check
            while len(simgr_unaided.active) > 0:
                if check_name in UNAIDED_SKIP:
                    break
                simgr_unaided.explore(find=ret_addr_unaided)

            print simgr_unaided

            for sim in simgr_unaided.found:
                ret = sim.state.regs.eax
                ret_str = colored(ret, 'red')
                if not sim.state.solver.symbolic(ret) and sim.state.solver.eval(ret) == 0:
                    ret_str = colored(ret, 'cyan')
                    unaided_false += 1
                else:
                    if sim.state.solver.symbolic(ret):
                        unaided_false += 1  # symbolic means undetermined so add to false too
                        unaided_total += 1
                    unaided_true += 1
                print sim, "returned {}".format(ret_str)
                # import IPython; IPython.embed()
            unaided_total += len(simgr_unaided.found)

        print '\n! Instrumented exploration !'
        extended_total = 0
        extended_false = 0
        extended_true = 0
        angr_antievasion.rdtsc_monkey_patch()  # monkey patch is global so we need to patch and unpatch for each check

        while len(simgr_extended.active) > 0:
            simgr_extended.explore(find=ret_addr_extended)

        print simgr_extended

        for sim in simgr_extended.found:
            ret = sim.state.regs.eax
            ret_str = colored(ret, 'red')
            if not sim.state.solver.symbolic(ret) and sim.state.solver.eval(ret) == 0:
                ret_str = colored(ret, 'cyan')
                extended_false += 1
            else:
                if sim.state.solver.symbolic(ret):
                    extended_false += 1  # symbolic means undetermined so add to false too
                    extended_total += 1
                extended_true += 1
            print sim, "returned {}".format(ret_str)
            # import IPython; IPython.embed()
        extended_total += len(simgr_extended.found)

        import IPython; IPython.embed()

        latex_table.append("{} & {} & {} & {} && {} & {} & {}".format(
            check_name,
            unaided_total, unaided_true, unaided_false,
            extended_total, extended_true, extended_false
        ))

    for line in latex_table:
        print line


if __name__ == '__main__':
    test()
