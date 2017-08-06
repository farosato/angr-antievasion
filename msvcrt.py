# Monkey patch to use libc SimProcedures for msvcrt.dll exported functions

import cle
import simuvex
from angr.project import l, Hook, Project


def lstrip_under(str):
    i = 0
    while str[i] == '_':
        i += 1
    return str[i:]


def patched_use_sim_procedures(self):
    """
    This is all the automatic simprocedure related initialization work
    It's too big to just get pasted into the initializer.
    """

    # Step 1: Get the appropriate libraries of SimProcedures from simuvex
    libs = []
    for lib_name in self.loader.requested_objects:
        if isinstance(self.loader.main_bin, cle.backends.pe.PE):
            # File names are case-insensitive on Windows. Make them all lowercase
            lib_name = lib_name.lower()

        # Hack that should go somewhere else:
        if lib_name in ['libc.so.0', 'libc.so', 'libc.musl-x86_64.so.1', 'msvcrt.dll']:
            lib_name = 'libc.so.6'
        if lib_name == 'ld-uClibc.so.0':
            lib_name = 'ld-uClibc.so.6'

        if lib_name not in simuvex.procedures.SimProcedures:
            l.debug("There are no simprocedures for library %s :(", lib_name)
        else:
            libs.append(lib_name)

    # Step 2: Categorize every "import" symbol in each object.
    # If it's IGNORED, mark it for stubbing
    # If it's blacklisted, don't process it
    # If it matches a simprocedure we have, replace it
    already_resolved = set()
    pending_hooks = {}
    unresolved = set()

    for obj in self.loader.all_objects:
        for reloc in obj.imports.itervalues():
            func = reloc.symbol
            if func.name in already_resolved:
                continue
            if not func.is_function:
                continue
            elif func.name in self._ignore_functions:
                unresolved.add(func)
                continue
            elif self._should_exclude_sim_procedure(func.name):
                continue

            elif self._should_use_sim_procedures:
                libc_corresponding = {}
                for lib in libs:
                    simfuncs = simuvex.procedures.SimProcedures[lib]
                    if func.name in simfuncs:
                        l.info("Providing %s from %s with SimProcedure", func.name, lib)
                        pending_hooks[func.name] = Hook(simfuncs[func.name])
                        already_resolved.add(func.name)
                        break
                    elif lstrip_under(func.name) in simfuncs:
                        libc_corresponding[func.name] = simfuncs[lstrip_under(func.name)]
                else:  # we could not find a simprocedure for this function
                    if not func.resolved:  # the loader couldn't find one either
                        if func.name in libc_corresponding:  # got a libc corresponding guess, use that
                            l.info("Providing %s from %s with SimProcedure for %s", func.name, lib, lstrip_under(func.name))
                            pending_hooks[func.name] = Hook(libc_corresponding[func.name])
                            already_resolved.add(func.name)
                        else:
                            unresolved.add(func)
                    else:
                        # mark it as resolved
                        already_resolved.add(func.name)
            # in the case that simprocedures are off and an object in the PLT goes
            # unresolved, we still want to replace it with a ReturnUnconstrained.
            elif not func.resolved and func.name in obj.jmprel:
                unresolved.add(func)

    # Step 3: Stub out unresolved symbols
    # This is in the form of a SimProcedure that either doesn't return
    # or returns an unconstrained value
    for func in unresolved:
        if func.name in already_resolved:
            continue
        # Don't touch weakly bound symbols, they are allowed to go unresolved
        if func.is_weak:
            continue
        l.info("[U] %s", func.name)
        procedure = simuvex.SimProcedures['stubs']['NoReturnUnconstrained']
        if func.name not in procedure.use_cases:
            procedure = simuvex.SimProcedures['stubs']['ReturnUnconstrained']
        pending_hooks[func.name] = Hook(procedure, resolves=func.name)

    self.hook_symbol_batch(pending_hooks)


def msvcrt_sim_procedures_monkey_patch():
    Project._use_sim_procedures = patched_use_sim_procedures
