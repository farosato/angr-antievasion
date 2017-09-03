#!/usr/bin/python

import angr
import pafish_models
import logging
import json
from termcolor import colored
# import msvcrt

# CHECK_TABLE = [
#     ('wine_reg_key1', 4210237),
# ]


def test():
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('angr.project').setLevel(logging.DEBUG)
    # logging.getLogger('simuvex.procedures').setLevel(logging.DEBUG)
    # logging.getLogger("cle.loader").setLevel(logging.DEBUG)
    # logging.getLogger("simuvex.procedures.libc.memcmp").setLevel(logging.DEBUG)

    # msvcrt.msvcrt_sim_procedures_monkey_patch()

    proj = angr.Project('./pafish.exe', load_options={'auto_load_libs': True, 'case_insensitive': True})

    # import IPython; IPython.embed()

    pafish_models.hook_all(proj)

    # import IPython; IPython.embed()

    if 'CHECK_TABLE' not in globals():
        # load it from json file
        with open('pafish.exe_checks.json', 'r') as jfile:
            global CHECK_TABLE
            CHECK_TABLE = json.load(jfile)

    for check_name, check_addr in CHECK_TABLE:
        print '\n### {} check ###'.format(check_name)

        check_call_state = proj.factory.call_state(check_addr)
        check_call_state.register_plugin("paranoid", pafish_models.SimStateParanoid())

        pafish_models.patch_memory(check_call_state)

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
