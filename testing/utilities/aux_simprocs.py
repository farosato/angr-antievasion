import angr
from angr_antievasion import StdcallSimProcedure
import logging

l = logging.getLogger("testing.utilities")


# Auxiliary SimProcedures to perform tests
# (without them checks could fail for "accessory" reasons, e.g. string handling functions not working or not "present")
# Practically all of them assert we are handling concrete input, so they are not suitable for purely symbolic tests.

class toupper(angr.SimProcedure):
    def run(self, c):
        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(c)

        char_ord = self.state.solver.eval(c)
        char = chr(char_ord)
        ret_expr = ord(char.upper())
        l.info('{} @ {}: {} ({}) => {} ({})'.format(
            self.display_name, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            char_ord, char, ret_expr, chr(ret_expr)))
        return ret_expr


class tolower(angr.SimProcedure):
    def run(self, c):
        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.solver.symbolic(c)

        char_ord = self.state.solver.eval(c)
        char = chr(char_ord)
        ret_expr = ord(char.lower())
        l.info('{} @ {}: {} ({}) => {} ({})'.format(
            self.display_name, self.state.memory.load(self.state.regs.esp, 4, endness=self.arch.memory_endness),
            char_ord, char, ret_expr, chr(ret_expr)))
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