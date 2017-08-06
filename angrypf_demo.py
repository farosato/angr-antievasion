#!/usr/bin/python

import angr
import pafish_models
import logging
import json
import msvcrt

# CHECK_TABLE = [
#     ('cpu_rdtsc', 0x40472b),
# ]


def test():
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('angr.project').setLevel(logging.DEBUG)
    # logging.getLogger('simuvex.procedures').setLevel(logging.DEBUG)
    # logging.getLogger("cle.loader").setLevel(logging.DEBUG)

    msvcrt.msvcrt_sim_procedures_monkey_patch()

    proj = angr.Project('./pafish.exe', load_options={'auto_load_libs': True})

    pafish_models.hook_all(proj)

    if 'CHECK_TABLE' not in globals():
        # load it from json file
        with open('pafish.exe_checks.json', 'r') as jfile:
            global CHECK_TABLE
            CHECK_TABLE = json.load(jfile)

    for check_name, check_addr in CHECK_TABLE:
        print '\n### {} check ###'.format(check_name)

        check_call_state = proj.factory.call_state(check_addr)
        check_call_state.register_plugin("paranoid", pafish_models.SimStateParanoid())

        pafish_models.patch_memory(proj, check_call_state)

        path_group = proj.factory.path_group(check_call_state)

        ret_addr = check_call_state.mem[check_call_state.regs.esp].int.concrete

        while len(path_group.active) > 0:
            path_group.explore(find=ret_addr)
            # import IPython; IPython.embed()
            # print path_group.active

        print path_group

        for err in path_group.errored:
            print err.error
            # import IPython; IPython.embed()

        for path in path_group.found:
            ret = path.state.regs.eax
            print path, "returned {}".format(ret)
            # import IPython; IPython.embed()


if __name__ == '__main__':
    test()
