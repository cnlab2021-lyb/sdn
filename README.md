# SDN with Mininet & Ryu

### Topology

Tree topology:
```sh
sudo mn --custom topo/tree.py --topo=tree-topo,n_hosts=5 --controller=remote
```

Data center topology:
```sh
sudo mn --custom topo/data-center.py --topo=data-center-topo,n_cores=4,n_aggregations=4 --controller=remote
```

### Controller
```sh
ryu-manager --observe-links controller/controller.py --config-file=action.conf
```
