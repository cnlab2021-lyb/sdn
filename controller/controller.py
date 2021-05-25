# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import itertools

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu.topology.event import EventLinkAdd
from ryu.topology.switches import Link


def reverse_link(link: Link) -> Link:
    rev = Link(link.dst, link.src)
    return rev


class SpanningTree(object):
    def __init__(self):
        self.components = {}
        self.tree_edges = collections.defaultdict(list)

    def add_vertex(self, vertex):
        if vertex not in self.components:
            self.components[vertex] = vertex

    def find_component(self, vertex):
        if self.components[vertex] == vertex:
            return vertex
        result = self.find_component(self.components[vertex])
        self.components[vertex] = result
        return result

    def merge(self, link, is_backup=False):
        self.add_vertex(link.src.dpid)
        self.add_vertex(link.dst.dpid)
        src_comp = self.find_component(link.src.dpid)
        dst_comp = self.find_component(link.dst.dpid)
        if src_comp == dst_comp:
            return False
        self.components[src_comp] = dst_comp
        self.tree_edges[link.src.dpid].append((link, is_backup))
        self.tree_edges[link.dst.dpid].append((reverse_link(link), is_backup))
        return True

    def find_path(self, src, dst):
        visited = set()
        parent_link = dict()
        parent = dict()

        def dfs(v):
            visited.add(v)
            for (link, is_backup) in self.tree_edges[v]:
                assert link.src.dpid == v
                u = link.dst.dpid
                if u in visited:
                    continue
                parent[u] = v
                parent_link[u] = (link, is_backup)
                dfs(u)

        dfs(src)
        if dst not in visited:
            return None
        path = []
        while dst != src:
            path.append(parent_link[dst])
            dst = parent[dst]
        return path[::-1]

    def get_link(self, dp, port):
        # assert dp in self.tree_edges
        for (link, is_backup) in self.tree_edges[dp]:
            assert link.src.dpid == dp
            if link.src.port_no == port:
                return link.dst.dpid
        return None


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = dict()
        self.monitor_thread = hub.spawn(self.monitor)
        self.flow_stats = collections.defaultdict(list)
        self.datapath_port_stats = collections.defaultdict(dict)
        self.prev_port_stats = {}
        self.prev_flow_stats = {}
        self.primary_spanning_tree = SpanningTree()
        self.secondary_spanning_tree = SpanningTree()
        self.to_block = collections.defaultdict(set)
        self.tree_link = collections.defaultdict(set)
        self.tree_edges = set()
        self.is_blocked = set()
        self.is_unblocked = set()
        self.rerouted_flow = set()

    @set_ev_cls(EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        link = ev.link
        if not self.primary_spanning_tree.merge(link):
            # Non-tree edge to be blocked later.
            if link.src.port_no not in self.tree_link[link.src.dpid]:
                assert link.dst.port_no not in self.tree_link[link.dst.dpid]
                self.to_block[link.src.dpid].add(link.src.port_no)
                self.to_block[link.dst.dpid].add(link.dst.port_no)
                self.secondary_spanning_tree.merge(link)
        else:
            self.tree_edges.add(link)
            self.tree_link[link.src.dpid].add(link.src.port_no)
            self.tree_link[link.dst.dpid].add(link.dst.port_no)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                   ofproto.OFPCML_NO_BUFFER)
        ]
        self.datapaths[datapath.id] = datapath
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    # Insert rule to `datapath` that drops flows matching `match`.
    def _drop_packets(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Remove the default rule of "notifying the controller" inserted in `switch_feature_handler`.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        msg = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                command=ofproto.OFPFC_MODIFY)
        datapath.send_msg(msg)

    # Block the `port_no`-th port of `datapath`.
    def _block_port(self, datapath, port_no):
        if (datapath.id,
                port_no) in self.is_blocked or (datapath.id,
                                                port_no) in self.is_unblocked:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        config = (ofproto.OFPPC_PORT_DOWN | ofproto.OFPPC_NO_RECV
                  | ofproto.OFPPC_NO_FWD | ofproto.OFPPC_NO_PACKET_IN)
        msg = parser.OFPPortMod(datapath=datapath,
                                port_no=port_no,
                                config=config,
                                mask=0b11111111,
                                hw_addr=datapath.ports[port_no].hw_addr)
        datapath.send_msg(msg)
        self.logger.info(f"Blocking port {port_no} of datapath {datapath.id}")
        self.is_blocked.add((datapath.id, port_no))

    def _unblock_port(self, datapath, port_no):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        config = ofproto.OFPPC_NO_PACKET_IN
        msg = parser.OFPPortMod(datapath=datapath,
                                port_no=port_no,
                                config=config,
                                mask=0b1100101,
                                hw_addr=datapath.ports[port_no].hw_addr)
        datapath.send_msg(msg)
        self.logger.info(
            f"Unblocking port {port_no} of datapath {datapath.id}")
        self.is_blocked.remove((datapath.id, port_no))
        self.is_unblocked.add((datapath.id, port_no))

    # Block non-tree edges incident to `datapath`.
    def _block_datapath(self, datapath):
        if datapath.id not in self.to_block:
            return
        for port_no in self.to_block[datapath.id]:
            self._block_port(datapath, port_no)
        self.to_block[datapath.id].clear()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        self._block_datapath(datapath)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        dst = eth.dst
        src = eth.src

        drop = False
        if ipv4_pkt:
            vlan_src = int(ipv4_pkt.src.split('.')[3]) % 2
            vlan_dst = int(ipv4_pkt.dst.split('.')[3]) % 2
            drop |= vlan_src != vlan_dst
        if arp_pkt:
            vlan_src = int(arp_pkt.src_ip.split('.')[3]) % 2
            vlan_dst = int(arp_pkt.dst_ip.split('.')[3]) % 2
            drop |= vlan_src != vlan_dst

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        args = {
            'in_port': in_port,
            'eth_dst': dst,
            'eth_src': src,
            'eth_type': eth.ethertype
        }
        priority = 1
        for p in pkt:
            if not isinstance(p, packet.packet_base.PacketBase):
                continue
            if p.protocol_name == 'ipv4':
                args['ip_proto'] = p.proto
                args['ipv4_src'] = p.src
                args['ipv4_dst'] = p.dst
                priority += 1
            elif p.protocol_name == 'ipv6':
                # FIXME: This is probably not correct if there are other headers
                args['ip_proto'] = p.nxt
                args['ipv6_src'] = p.src
                args['ipv6_dst'] = p.dst
                priority += 1
            elif p.protocol_name == 'arp':
                args['arp_spa'] = p.src_ip
                args['arp_tpa'] = p.dst_ip
            elif p.protocol_name == 'tcp':
                args['tcp_src'] = p.src_port
                args['tcp_dst'] = p.dst_port
                priority += 1
            elif p.protocol_name == 'udp':
                args['udp_src'] = p.src_port
                args['udp_dst'] = p.dst_port
                priority += 1
        match = parser.OFPMatch(**args)

        if not src.startswith("33:33:") and not dst.startswith("33:33:"):
            self.logger.info("packet in %s %s %s %s, matching %s", dpid, src,
                             dst, in_port, str(match))

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if drop:
                self._drop_packets(datapath, priority, match)
            else:
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, priority, match, actions,
                                  msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, priority, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        if not drop:
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            datapath.send_msg(out)

    @staticmethod
    def _get_protocol(match):
        if 'tcp_src' in match:
            return 'TCP'
        if 'udp_src' in match:
            return 'UDP'
        if match.get('ip_proto', -1) == 1:
            return 'ICMP'
        if match.get('eth_type', None) == ether_types.ETH_TYPE_ARP:
            return 'ARP'
        return 'Unknown'

    def _print_table(self, rows):
        assert len(rows) >= 1
        lens = [len(x) for x in rows[0]]
        for row in rows:
            for i, cell in enumerate(row):
                lens[i] = max(lens[i], len(str(cell)))
        row_format = ''.join('{:>' + str(x + 5) + '}' for x in lens)
        for row in rows:
            self.logger.info(row_format.format(*row))

    def _trace(self, dp, eth):
        dpid = format(dp, "d").zfill(16)
        assert eth in self.mac_to_port[dpid]
        port = self.mac_to_port[dpid][eth]
        dst = self.primary_spanning_tree.get_link(dp, port)
        if dst is None:
            return dp, port
        return self._trace(dst, eth)

    def _add_backup_edges(self):
        for link in self.tree_edges:
            self.secondary_spanning_tree.merge(link, True)

    @staticmethod
    def _get_match_fields(match):
        args = {}

        for key in [
                'eth_src', 'eth_dst', 'eth_type', 'ip_proto', 'ipv4_src', 'ipv4_dst', 'ipv6_src', 'ipv6_dst',
                'arp_spa', 'arp_tpa', 'tcp_src', 'tcp_dst', 'udp_src',
                'udp_dst'
        ]:
            if key in match:
                args[key] = match[key]
        return args

    @staticmethod
    def _copy_match(match, in_port, parser):
        args = Switch._get_match_fields(match)
        args['in_port'] = in_port
        return parser.OFPMatch(**args)

    def _reroute(self, link, match, in_port, is_tree_edge):
        assert link.src.dpid in self.datapaths
        assert link.dst.dpid in self.datapaths
        datapath = self.datapaths[link.src.dpid]

        print(f"_reroute link = {link}, match = {match}, in_port = {in_port}")

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        new_match = self._copy_match(match, in_port, parser)

        self._drop_packets(datapath=datapath, priority=50, match=new_match)

        if (link.src.dpid, link.src.port_no) in self.is_blocked:
            self._unblock_port(datapath, link.src.port_no)
        if (link.dst.dpid, link.dst.port_no) in self.is_blocked:
            self._unblock_port(self.datapaths[link.dst.dpid], link.dst.port_no)

        self.logger.info(f'Re-routing match = {new_match}')
        # print(f'Re-routing match = {new_match}')
        actions = [parser.OFPActionOutput(link.src.port_no)]
        self.add_flow(datapath=datapath,
                      priority=100,
                      match=new_match,
                      actions=actions)
        new_match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                   ofproto.OFPCML_NO_BUFFER)
        ]
        self.datapaths[datapath.id] = datapath
        self.add_flow(datapath, 0, new_match, actions)
        if not is_tree_edge:
            args = {
                'eth_dst': 'ff:ff:ff:ff:ff:ff',
                'in_port': in_port
            }
            new_match = parser.OFPMatch(**args)
            self._drop_packets(datapath=datapath, priority=100, match=match)

    def _reroute_end(self, dst_port, dpid, match, in_port):
        datapath = self.datapaths[dpid]

        # print(f"_reroute link = {link}, match = {match}, in_port = {in_port}")

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        new_match = self._copy_match(match, in_port, parser)

        self._drop_packets(datapath=datapath, priority=50, match=new_match)

        if (dpid, dst_port) in self.is_blocked:
            self._unblock_port(datapath, dst_port)

        self.logger.info(f'Re-routing match = {new_match}')
        # print(f'Re-routing match = {new_match}')
        actions = [parser.OFPActionOutput(dst_port)]
        self.add_flow(datapath=datapath,
                      priority=100,
                      match=new_match,
                      actions=actions)
        new_match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                   ofproto.OFPCML_NO_BUFFER)
        ]
        self.datapaths[datapath.id] = datapath
        self.add_flow(datapath, 0, new_match, actions)
        args = {
            'eth_dst': 'ff:ff:ff:ff:ff:ff',
            'in_port': in_port
        }
        new_match = parser.OFPMatch(**args)
        self._drop_packets(datapath=datapath, priority=100, match=match)

    @staticmethod
    def _print_path(name, path):
        print(name + " path", end="")
        for (link, is_backup) in path:
            print(link, is_backup, end=" ")
        print("")

    def on_detect_congestion(self, datapath, port, delta=None):
        # TODO: Re-route
        self.logger.info(
            f"Detect congestion: datapath = {datapath.id}, port = {port}, delta = {delta}"
        )
        if len(self.datapath_port_stats[datapath.id]) == 0:
            return
        _, (match, byte_count) = max(
            [(k, v)
             for (k, v) in self.datapath_port_stats[datapath.id].items()
             if v[0]['in_port'] == port],
            key=lambda x: x[1][1])
        # Do nothing if the flow has already be re-routed.
        key = frozenset(sorted(Switch._get_match_fields(match)))
        if key in self.rerouted_flow:
            self.logger.info(f"flow {match} has already been re-routed")
            print(f"flow {match} has already been re-routed")
            return

        src, src_port = self._trace(datapath.id, match['eth_src'])
        dst, dst_port = self._trace(datapath.id, match['eth_dst'])
        primary_path = self.primary_spanning_tree.find_path(src, dst)
        assert primary_path is not None
        self._print_path("primary", primary_path)
        self._add_backup_edges()
        secondary_path = self.secondary_spanning_tree.find_path(src, dst)
        assert secondary_path is not None
        self._print_path("secondary", secondary_path)
        drop = True
        has_alternative = False
        if not drop:
            in_port = src_port
            for link, is_backup in secondary_path:
                if not is_backup:
                    has_alternative = True
                self._reroute(link, match, in_port, is_backup)
                in_port = link.dst.port_no
            self._reroute_end(dst_port, dst, match, in_port)
        if not has_alternative or drop:
            self.logger.info(f"Drop flow: {match}")
            print(f"Drop flow: {match}")
            self._drop_packets(datapath=datapath, priority=100, match=match)
        else:
            self.logger.info(f"Reroute flow: {match}")
            print(f"Reroute flow: {match}")
            self.rerouted_flow.add(key)

    def monitor(self):
        SLEEP_SECS = 2
        CONGESTION_THRESHOLD = SLEEP_SECS * 1024 * 1024
        while True:
            for (_, datapath) in self.datapaths.items():
                parser = datapath.ofproto_parser
                datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
                datapath.send_msg(parser.OFPPortStatsRequest(datapath))
            hub.sleep(SLEEP_SECS)
            columns = [
                'datapath', 'in-port', 'src-ip', 'src-port', 'dst-ip',
                'dst-port', 'protocol', 'action', 'packets', 'bytes'
            ]
            rows = [columns]
            new_flow_stats = {}
            for datapath, datapath_stats in self.flow_stats.items():
                for stat in datapath_stats:
                    if 'in_port' not in stat.match:
                        continue
                    if len(stat.instructions[0].actions) == 0:
                        action = 'DROP'
                    else:
                        action = f'port {stat.instructions[0].actions[0].port}'
                    flow_key = str(stat.match)
                    if (datapath, flow_key) in self.prev_flow_stats:
                        delta = stat.byte_count - self.prev_flow_stats[
                            (datapath, flow_key)]
                        self.datapath_port_stats[datapath][flow_key] = (
                            stat.match, delta)
                    new_flow_stats[(datapath, flow_key)] = stat.byte_count
                    rows.append([
                        datapath, stat.match['in_port'],
                        stat.match.get(
                            'ipv4_src',
                            stat.match.get('ipv6_src',
                                           stat.match.get('arp_spa', ''))),
                        stat.match.get('tcp_src',
                                       stat.match.get('udp_src', '')),
                        stat.match.get(
                            'ipv4_dst',
                            stat.match.get('ipv6_dst',
                                           stat.match.get('arp_tpa', ''))),
                        stat.match.get('tcp_dst',
                                       stat.match.get('udp_dst', '')),
                        self._get_protocol(stat.match), action,
                        stat.packet_count, stat.byte_count
                    ])
            for (dp, match) in self.prev_flow_stats:
                if (dp, match) not in new_flow_stats:
                    if dp in self.datapath_port_stats and match in self.datapath_port_stats[
                            dp]:
                        del self.datapath_port_stats[dp][match]
            for datapath, stats in self.datapath_port_stats.items():
                for port, g in itertools.groupby(stats.items(),
                                                 lambda x: x[1][0]['in_port']):
                    delta_sum = sum(x[1][1] for x in g)
                    if delta_sum > CONGESTION_THRESHOLD:
                        datapath_obj = next(y
                                            for (x,
                                                 y) in self.datapaths.items()
                                            if x == datapath)
                        self.on_detect_congestion(datapath_obj, port,
                                                  delta_sum)
            self.prev_flow_stats = new_flow_stats
            self._print_table(rows)
            columns = [
                'datapath', 'port', 'tx-bytes', 'tx-pkts', 'rx-bytes',
                'rx-pkts', 'dropped', 'error'
            ]
            rows = [columns]
            for (datapath, port), data in self.prev_port_stats.items():
                rows.append([datapath, port] + data)
            self._print_table(rows)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.flow_stats[ev.msg.datapath.id].clear()
        for stat in [s for s in ev.msg.body if s.priority >= 1]:
            self.flow_stats[ev.msg.datapath.id].append(stat)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            key = (ev.msg.datapath.id, stat.port_no)
            self.prev_port_stats[key] = [
                stat.tx_bytes, stat.tx_packets, stat.rx_bytes, stat.rx_packets,
                stat.rx_dropped + stat.tx_dropped,
                stat.rx_errors + stat.tx_errors
            ]
