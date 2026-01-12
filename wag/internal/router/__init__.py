"""Router/WireGuard management stub."""
class Router:
    def __init__(self, config, db, no_iptables=False):
        self.config = config
        self.db = db
        self.no_iptables = no_iptables
    async def start(self):
        pass
    async def stop(self):
        pass
