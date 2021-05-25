from mininet.topo import Topo

class TestRerouteTopo(Topo):
    def __init__(self, hosts=2):
        Topo.__init__(self)
        s0 = self.addSwitch('s0')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        self.addLink(s0, s1)
        self.addLink(s0, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s3)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(h1, s0)
        self.addLink(h2, s3)

topos = {'test-reroute-topo': (lambda: TestRerouteTopo())}
