#!/usr/bin/python

import angr
import pafish_models
import logging

CHECKS = [
    ('cpu_rdtsc', 0x40472b, 0x4047d7),
    ('gensandbox_mouse_act', 0x4037ff, 0x403857),
    ('gensandbox_sleep_patched', 0x403caa, 0x403ce9),
    ('vmware_sysfile1', 0x403f3b, 0x403f4e),
    ('vmware_sysfile2', 0x403f4f, 0x403f62),
    ('vbox_sysfile1', 0x403104, 0x403209),
    ('vbox_sysfile2', 0x40320a, 0x403373),
    ('check_hook_DeleteFileW_m1', 0x4042bd, 0x4042d1),
    ('check_hook_ShellExecuteExW_m1', 0x4042d2, 0x4042e6),
    ('check_hook_CreateProcessA_m1', 0x4042e7, 0x4042fb),
    ('wine_reg_key1', 0x403e3d, 0x403e58),
    ('vbox_reg_key3', 0x402f2b, 0x402f46),
    ('vmware_reg_key2', 0x403f1f, 0x403f3a),
    # Need library models for the following commented out tests
    # ('qemu_reg_key1', 0x4041fc, 0x404227),
    # ('qemu_reg_key2', 0x404228, 0x404253)
]


def test():
    logging.getLogger().setLevel(logging.WARNING)

    proj = angr.Project('./pafish.exe', load_options={'auto_load_libs': True})

    pafish_models.hook_all(proj)

    for check_name, check_addr, check_ret_addr in CHECKS:
        print '\n### {} check ###'.format(check_name)

        check_call_state = proj.factory.call_state(check_addr)
        check_call_state.register_plugin("paranoid", pafish_models.SimStateParanoid())

        pafish_models.patch_memory(proj, check_call_state)

        path_group = proj.factory.path_group(check_call_state)

        while len(path_group.active) > 0:
            path_group.explore(find=check_ret_addr)
            # print path_group.active
            # print len(path_group.active)

        for path in path_group.found:
            ret = path.state.regs.eax
            print path, "returned {}".format(ret)

        # import IPython; IPython.embed()


if __name__ == '__main__':
    test()
