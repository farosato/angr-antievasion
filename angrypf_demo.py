#!/usr/bin/python

import angr
import pafish_models

CHECKS = [('cpu_rdtsc', 0x40472b, 0x4047d7),
          ('gensandbox_mouse_act', 0x4037ff, 0x403857),
          ('gensandbox_sleep_patched', 0x403caa, 0x403ce9),
          ('vmware_sysfile1', 0x403f3b, 0x403f4e),
          ('vmware_sysfile2', 0x403f4f, 0x403f62),
          ('vbox_sysfile1', 0x403104, 0x403209),
          ('vbox_sysfile2', 0x40320a, 0x403373)]


def test():
    proj = angr.Project('./pafish.exe', load_options={'auto_load_libs': False})

    pafish_models.hook_all(proj)

    for check_name, check_addr, check_ret_addr in CHECKS:
        print '\n### {} check ###'.format(check_name)

        check_call_state = proj.factory.call_state(check_addr)
        check_call_state.register_plugin("paranoid", pafish_models.SimStateParanoid())

        path_group = proj.factory.path_group(check_call_state)

        while len(path_group.active) > 0:
            path_group.explore(find=check_ret_addr)

        for path in path_group.found:
            ret = path.state.regs.eax
            print path, "returned {}".format(ret)

        # import IPython; IPython.embed()


if __name__ == '__main__':
    test()
