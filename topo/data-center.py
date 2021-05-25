from mininet.topo import Topo


class DataCenterTopo(Topo):
    def __init__(self, n_cores, n_aggregations):
        Topo.__init__(self)
        n_hosts = n_aggregations * 4
        cores = [self.addSwitch('s%d' % i) for i in range(n_cores)]
        aggregations = [
            self.addSwitch('s%d' % (i + n_cores))
            for i in range(n_aggregations * 2)
        ]
        edges = [
            self.addSwitch('s%d' % (i + n_cores + n_aggregations * 2))
            for i in range(n_aggregations * 2)
        ]
        hosts = [self.addHost('h%d' % i) for i in range(n_hosts)]

        for i in range(n_aggregations):
            for j in range(n_cores):
                self.addLink(cores[j], aggregations[2 * i + j % 2])

            self.addLink(aggregations[2 * i], edges[2 * i])
            self.addLink(aggregations[2 * i + 1], edges[2 * i])
            self.addLink(aggregations[2 * i], edges[2 * i + 1])
            self.addLink(aggregations[2 * i + 1], edges[2 * i + 1])
            self.addLink(edges[2 * i], hosts[4 * i])
            self.addLink(edges[2 * i], hosts[4 * i + 1])
            self.addLink(edges[2 * i + 1], hosts[4 * i + 2])
            self.addLink(edges[2 * i + 1], hosts[4 * i + 3])


topos = {
    'data-center-topo':
    (lambda n_cores, n_aggregations: DataCenterTopo(n_cores, n_aggregations))
}
