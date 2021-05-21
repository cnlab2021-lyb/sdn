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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()
        self.monitor_thread = hub.spawn(self.monitor)
        self.flow_stats = collections.defaultdict(list)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

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
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, priority, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
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

    def monitor(self):
        while True:
            for datapath in self.datapaths:
                parser = datapath.ofproto_parser
                datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
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
            for datapath, datapath_stats in self.flow_stats.items():
                for stat in datapath_stats:
                    rows.append([
                        datapath,
                        stat.match['in_port'],
                        stat.match.get('ipv4_src', stat.match.get('ipv6_src', '')),
                        stat.match.get('tcp_src', stat.match.get('udp_src', '')),
                        stat.match.get('ipv4_dst', stat.match.get('ipv6_dst', '')),
                        stat.match.get('tcp_dst', stat.match.get('udp_dst', '')),
                        self._get_protocol(stat.match),
                        stat.instructions[0].actions[0].port,
                        stat.packet_count,
                        stat.byte_count
                    ])
            self._print_table(rows)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.flow_stats[ev.msg.datapath.id].clear()
        for stat in [s for s in ev.msg.body if s.priority >= 1]:
            self.flow_stats[ev.msg.datapath.id].append(stat)
