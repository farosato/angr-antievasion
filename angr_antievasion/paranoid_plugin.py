from angr.state_plugins.plugin import SimStatePlugin
from win32_simprocs import TICKS_PER_MS


class ParanoidPlugin(SimStatePlugin):
    """
        This state plugin keeps track of various paranoid stuff that may be checked during malware evasion
    """

    def __init__(self):
        SimStatePlugin.__init__(self)
        self.tsc = 50 * 1000 * 60 * TICKS_PER_MS  # init tick count ~= 50 minutes
        self.last_error = 0  # should be thread-local, but angr does NOT currently support threads
        self.open_regkeys = {}  # handle -> string id

    def copy(self):
        c = ParanoidPlugin()
        c.tsc = self.tsc
        c.last_error = self.last_error
        c.open_regkeys = self.open_regkeys.copy()  # shallow copy should be enough (handles don't change target)
        return c

SimStatePlugin.register_default('paranoid', ParanoidPlugin)