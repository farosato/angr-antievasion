import logging

l = logging.getLogger('angr_antievasion.cpu_instr_patches')


# Custom VEX dirty helpers for anti-evasion

def rdtsc_patch(state):
    state.paranoid.tsc += 500  # magic number (pafish detects if consecutive runs diff is between 0 and 750)
    return state.solver.BVV(state.paranoid.tsc, 64), []

# CPUID based detection tricks don't need any handling (angr dirty helper emulates a real cpu info)
