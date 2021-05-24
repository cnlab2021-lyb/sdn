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


class UnionFind(object):
    def __init__(self):
        self.components = {}

    def add_vertex(self, vertex):
        if vertex not in self.components:
            self.components[vertex] = vertex

    def find_component(self, vertex):
        if self.components[vertex] == vertex:
            return vertex
        result = self.find_component(self.components[vertex])
        self.components[vertex] = result
        return result

    def merge(self, src, dst):
        src = self.find_component(src)
        dst = self.find_component(dst)
        if src == dst:
            return False
        self.components[src] = dst
        return True


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()
        self.monitor_thread = hub.spawn(self.monitor)
        self.flow_stats = collections.defaultdict(list)
        self.datapath_port_stats = collections.defaultdict(dict)
        self.prev_port_stats = {}
        self.prev_flow_stats = {}
        self.union_find = UnionFind()
        self.to_block = collections.defaultdict(set)
        self.tree_link = collections.defaultdict(set)

    @set_ev_cls(EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        link = ev.link
        self.union_find.add_vertex(link.src.dpid)
        self.union_find.add_vertex(link.dst.dpid)
        if not self.union_find.merge(link.src.dpid, link.dst.dpid):
            if link.src.port_no not in self.tree_link[link.src.dpid]:
                self.to_block[link.src.dpid].add(link.src.port_no)
            if link.dst.port_no not in self.tree_link[link.dst.dpid]:
                self.to_block[link.dst.dpid].add(link.dst.port_no)
        else:
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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.datapaths.add(datapath)
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def drop_packets(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        msg = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst)
        datapath.send_msg(msg)

    def _block_port(self, datapath, port_no):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        config = (ofproto.OFPPC_PORT_DOWN | ofproto.OFPPC_NO_RECV |
                  ofproto.OFPPC_NO_FWD | ofproto.OFPPC_NO_PACKET_IN)
        msg = parser.OFPPortMod(
            datapath=datapath,
            port_no=port_no,
            config=config,
            mask=0b11111111,
            hw_addr=datapath.ports[port_no].hw_addr)
        datapath.send_msg(msg)

    def _block_datapath(self, datapath):
        if datapath.id not in self.to_block:
            return
        for port_no in self.to_block[datapath.id]:
            self.logger.info(
                f'Blocking port {port_no} of datapath {datapath.id}')
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

        if not src.startswith("33:33:") and not dst.startswith("33:33:"):
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            args = {
                'in_port': in_port,
                'eth_dst': dst,
                'eth_src': src,
                'eth_type': eth.ethertype
            }
            priority = 1
            for p in pkt:
                if p.protocol_name == 'ipv4':
                    args['ip_proto'] = p.proto
                    args['ipv4_src'] = p.src
                    args['ipv4_dst'] = p.dst
                    priority += 1
                elif p.protocol_name == 'ipv6':
                    args['ip_proto'] = p.proto
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
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if drop:
                self.drop_packets(datapath, priority, match)
            else:
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(
                        datapath, priority, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, priority, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        if not drop:
            out = parser.OFPPacketOut(
                datapath=datapath,
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

    def on_detect_congestion(self, datapath, port):
        # TODO: Drop or Re-route
        self.logger.info(
            f"Detect congestion: datapath = {datapath}, port = {port}")
        if len(self.datapath_port_stats[datapath.id]) == 0:
            return
        print(self.datapath_port_stats[datapath.id])
        flow = max([(k, v) for (k, v) in self.datapath_port_stats[datapath.id].items() if v[0]['in_port'] == port], key=lambda x: x[1][1])
        self.drop_packets(datapath, 100, flow[1][0])

    def monitor(self):
        while True:
            for datapath in self.datapaths:
                parser = datapath.ofproto_parser
                datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
                datapath.send_msg(parser.OFPPortStatsRequest(datapath))
            hub.sleep(10)
            columns = [
                'datapath',
                'in-port',
                'src-ip',
                'src-port',
                'dst-ip',
                'dst-port',
                'protocol',
                'action',
                'packets',
                'bytes'
            ]
            rows = [columns]
            new_flow_stats = {}
            for datapath, datapath_stats in self.flow_stats.items():
                for stat in datapath_stats:
                    if len(stat.instructions[0].actions) == 0 or 'in_port' not in stat.match:
                        continue
                    flow_key = str(stat.match)
                    if (datapath, flow_key) in self.prev_flow_stats:
                        delta = stat.byte_count - self.prev_flow_stats[(datapath, flow_key)]
                        self.datapath_port_stats[datapath][flow_key] = (stat.match, delta)
                    new_flow_stats[(datapath, flow_key)] = stat.byte_count
                    rows.append([
                        datapath,
                        stat.match['in_port'],
                        stat.match.get('ipv4_src', stat.match.get('ipv6_src', stat.match.get('arp_spa', ''))),
                        stat.match.get('tcp_src', stat.match.get('udp_src', '')),
                        stat.match.get('ipv4_dst', stat.match.get('ipv6_dst', stat.match.get('arp_tpa', ''))),
                        stat.match.get('tcp_dst', stat.match.get('udp_dst', '')),
                        self._get_protocol(stat.match),
                        stat.instructions[0].actions[0].port,
                        stat.packet_count,
                        stat.byte_count
                    ])
            for (dp, match) in self.prev_flow_stats:
                if (dp, match) not in new_flow_stats:
                    if dp in self.datapath_port_stats and match in self.datapath_port_stats[dp]:
                        del self.data_port_stats[dp][match]
            self.prev_flow_stats = new_flow_stats
            self._print_table(rows)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.flow_stats[ev.msg.datapath.id].clear()
        for stat in [s for s in ev.msg.body if s.priority >= 1]:
            self.flow_stats[ev.msg.datapath.id].append(stat)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        CONGESTION_THRESHOLD = 10 * 1024 * 1024
        for stat in ev.msg.body:
            key = (ev.msg.datapath.id, stat.port_no)
            if key in self.prev_port_stats and stat.tx_bytes - \
                    self.prev_port_stats[key] > CONGESTION_THRESHOLD:
                self.on_detect_congestion(ev.msg.datapath, stat.port_no)
            self.prev_port_stats[key] = stat.tx_bytes
