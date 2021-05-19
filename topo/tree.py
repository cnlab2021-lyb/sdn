from mininet.topo import Topo

class TreeTopo(Topo):
    def __init__(self, hosts = 5):
        Topo.__init__(self)
        root = self.addSwitch('s%d' % hosts)
        for i in range(0, hosts, 2):
            switch = self.addSwitch('s%d' % i)
            h1 = self.addHost('h%d' % i)
            self.addLink(switch, h1)
            if i + 1 < hosts:
                h2 = self.addHost('h%d' % (i + 1))
                self.addLink(switch, h2)
            self.addLink(root, switch)

topos = {'tree-topo': (lambda: TreeTopo())}
