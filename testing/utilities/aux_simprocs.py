import angr
from angr_antievasion import StdcallSimProcedure
import logging

l = logging.getLogger("testing.utilities")


# Auxiliary SimProcedures to perform tests
# (without them checks could fail for "accessory" reasons, e.g. string handling functions not working or not "present")
# Practically all of them assert we are handling concrete input, so they are not suitable for purely symbolic tests.

class toupper(angr.SimProcedure):
    def run(self, c):
        self.argument_types = {0: angr.sim_type.SimTypeInt(self.state.arch, True)}
        self.return_type = angr.sim_type.SimTypeInt(self.state.arch, True)

        ret_expr = self.state.solver.If(
            self.state.solver.And(c >= 97, c <= 122),  # a - z
            c - 32, c)
        l.info('{} @ {}: {} => {}'.format(
            self.display_name, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            c, ret_expr))
        return ret_expr


class tolower(angr.SimProcedure):
    def run(self, c):
        self.argument_types = {0: angr.sim_type.SimTypeInt(self.state.arch, True)}
        self.return_type = angr.sim_type.SimTypeInt(self.state.arch, True)

        ret_expr = self.state.solver.If(
            self.state.solver.And(c >= 65, c <= 90),  # A - Z
            c + 32, c)
        l.info('{} @ {}: {} => {}'.format(
            self.display_name, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            c, ret_expr))
        return ret_expr


class lstrcmpiA(StdcallSimProcedure):
    def extract_string(self, addr):
        return self.state.mem[addr].string.concrete

    def run(self, lpString1, lpString2):
        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()),
                               1: self.ty_ptr(angr.sim_type.SimTypeString())}
        self.return_type = angr.sim_type.SimTypeInt(32, True)

        assert not self.state.solver.symbolic(lpString1)
        assert not self.state.solver.symbolic(lpString2)

        str1 = self.extract_string(lpString1)
        str_l1 = str1.lower()
        str2 = self.extract_string(lpString2)
        str_l2 = str2.lower()
        ret_expr = -1 if str_l1 < str_l2 else 1 if str_l1 > str_l2 else 0

        l.info('{} @ {}: {} ({}), {} ({}) => {}'.format(
            self.display_name, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            lpString1, str1, lpString2, str2, ret_expr))
        return ret_expr


class lstrcmpiW(lstrcmpiA):
    def extract_string(self, addr):
        return self.state.mem[addr].wstring.concrete