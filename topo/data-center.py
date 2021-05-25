from mininet.topo import Topo


class DataCenterTopo(Topo):
    def __init__(self, hosts=16):
        assert hosts % 4 == 0
        Topo.__init__(self)
        clusters = hosts // 4
        cores = [self.addSwitch('s%d' % i) for i in range(clusters)]
        aggregations = [
            self.addSwitch('s%d' % (i + clusters)) for i in range(clusters * 2)
        ]
        edges = [
            self.addSwitch('s%d' % (i + clusters * 3))
            for i in range(clusters * 2)
        ]
        hosts = [self.addHost('h%d' % i) for i in range(hosts)]

        for i in range(clusters):
            for j in range(clusters):
                self.addLink(cores[i], aggregations[2 * j + (i % 2)])

            self.addLink(aggregations[2 * i], edges[2 * i])
            self.addLink(aggregations[2 * i + 1], edges[2 * i])
            self.addLink(aggregations[2 * i], edges[2 * i + 1])
            self.addLink(aggregations[2 * i + 1], edges[2 * i + 1])
            self.addLink(edges[2 * i], hosts[4 * i])
            self.addLink(edges[2 * i], hosts[4 * i + 1])
            self.addLink(edges[2 * i + 1], hosts[4 * i + 2])
            self.addLink(edges[2 * i + 1], hosts[4 * i + 3])


topos = {'data-center-topo': (lambda: DataCenterTopo())}
