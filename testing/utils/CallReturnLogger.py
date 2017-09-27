import angr
import logging

l = logging.getLogger('angr.procedures.stubs.CallReturn')


class CallReturnLogger(angr.SimProcedure):
    NO_RET = True

    def run(self):
        l.info("Factory.call_state-created path returned {}".format(self.state.regs.eax))
        return