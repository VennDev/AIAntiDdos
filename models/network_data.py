from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import time

class NetworkData:
    def __init__(self, server_ip):
        self.server_ip = server_ip
        self.data = {
            'packets': [],
            'timestamps': [],
            'source_ips': set(),
            'last_processed': time.time(),
            'inbound_counts': {'inbound': 0, 'outbound': 0},
            'tcp_flags': {
                'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0, 'ack': 0, 'urg': 0, 'ece': 0, 'cwr': 0,
                'fwd_psh': 0, 'bwd_psh': 0, 'fwd_urg': 0, 'bwd_urg': 0
            },
            'fwd_timestamps': [],
            'bwd_timestamps': [],
            'fwd_header_lengths': [],
            'bwd_header_lengths': [],
            'fwd_segment_sizes': [],
            'bwd_segment_sizes': [],
            'init_win_forward': None,
            'init_win_backward': None,
            'udp_dest_ports': set()
        }

    def packet_callback(self, packet):
        if IP in packet:
            current_time = time.time()
            self.data['packets'].append(packet)
            self.data['timestamps'].append(current_time)
            self.data['source_ips'].add(packet[IP].src)
            
            is_inbound = packet[IP].dst == self.server_ip
            if is_inbound:
                self.data['inbound_counts']['inbound'] += 1
                self.data['fwd_timestamps'].append(current_time)
            else:
                self.data['inbound_counts']['outbound'] += 1
                self.data['bwd_timestamps'].append(current_time)
            
            if TCP in packet:
                flags = packet[TCP].flags
                self.data['tcp_flags']['fin'] += bool(flags & 0x01)
                self.data['tcp_flags']['syn'] += bool(flags & 0x02)
                self.data['tcp_flags']['rst'] += bool(flags & 0x04)
                self.data['tcp_flags']['psh'] += bool(flags & 0x08)
                self.data['tcp_flags']['ack'] += bool(flags & 0x10)
                self.data['tcp_flags']['urg'] += bool(flags & 0x20)
                self.data['tcp_flags']['ece'] += bool(flags & 0x40)
                self.data['tcp_flags']['cwr'] += bool(flags & 0x80)
                
                if is_inbound:
                    self.data['tcp_flags']['fwd_psh'] += bool(flags & 0x08)
                    self.data['tcp_flags']['fwd_urg'] += bool(flags & 0x20)
                    self.data['fwd_header_lengths'].append(len(packet[TCP]))
                    self.data['fwd_segment_sizes'].append(len(packet[TCP]))
                    if self.data['init_win_forward'] is None:
                        self.data['init_win_forward'] = packet[TCP].window
                else:
                    self.data['tcp_flags']['bwd_psh'] += bool(flags & 0x08)
                    self.data['tcp_flags']['bwd_urg'] += bool(flags & 0x20)
                    self.data['bwd_header_lengths'].append(len(packet[TCP]))
                    self.data['bwd_segment_sizes'].append(len(packet[TCP]))
                    if self.data['init_win_backward'] is None:
                        self.data['init_win_backward'] = packet[TCP].window
            
            if UDP in packet:
                self.data['udp_dest_ports'].add(packet[UDP].dport)

    def process_network_data(self):
        current_time = time.time()
        if current_time - self.data['last_processed'] < 2:
            return None

        packets = self.data['packets']
        timestamps = self.data['timestamps']
        if not packets:
            return None

        total_packets = len(packets)
        time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        flow_iat_mean = np.mean(time_diffs) if time_diffs else 0
        flow_iat_std = np.std(time_diffs) if time_diffs else 0
        flow_iat_max = max(time_diffs) if time_diffs else 0
        flow_iat_min = min(time_diffs) if time_diffs else 0
        packet_lengths = [len(pkt) for pkt in packets]
        total_length = sum(packet_lengths)
        packet_length_mean = np.mean(packet_lengths) if packet_lengths else 0
        packet_length_std = np.std(packet_lengths) if packet_lengths else 0
        packet_length_variance = np.var(packet_lengths) if packet_lengths else 0
        packet_rate = total_packets / (current_time - self.data['last_processed'])
        flow_duration = (current_time - timestamps[0]) * 1000 if timestamps else 1000
        flow_bytess = total_length / (flow_duration / 1000) if flow_duration > 0 else 0

        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        udp_packets = [pkt for pkt in packets if UDP in pkt]
        total_tcp_packets = len(tcp_packets)
        total_udp_packets = len(udp_packets)
        protocol = 6 if total_tcp_packets >= total_udp_packets else 17

        total_counts = self.data['inbound_counts']['inbound'] + self.data['inbound_counts']['outbound']
        inbound = 1 if total_counts == 0 else (self.data['inbound_counts']['inbound'] / total_counts >= 0.5)
        downup_ratio = (self.data['inbound_counts']['inbound'] / self.data['inbound_counts']['outbound']) if self.data['inbound_counts']['outbound'] > 0 else 0

        fwd_time_diffs = [self.data['fwd_timestamps'][i+1] - self.data['fwd_timestamps'][i] for i in range(len(self.data['fwd_timestamps'])-1)]
        bwd_time_diffs = [self.data['bwd_timestamps'][i+1] - self.data['bwd_timestamps'][i] for i in range(len(self.data['bwd_timestamps'])-1)]
        
        fwd_iat_total = sum(fwd_time_diffs) if fwd_time_diffs else 0
        fwd_iat_mean = np.mean(fwd_time_diffs) if fwd_time_diffs else 0
        fwd_iat_std = np.std(fwd_time_diffs) if fwd_time_diffs else 0
        fwd_iat_max = max(fwd_time_diffs) if fwd_time_diffs else 0
        fwd_iat_min = min(fwd_time_diffs) if fwd_time_diffs else 0
        
        bwd_iat_total = sum(bwd_time_diffs) if bwd_time_diffs else 0
        bwd_iat_mean = np.mean(bwd_time_diffs) if bwd_time_diffs else 0
        bwd_iat_std = np.std(bwd_time_diffs) if bwd_time_diffs else 0
        bwd_iat_max = max(bwd_time_diffs) if bwd_time_diffs else 0
        bwd_iat_min = min(bwd_time_diffs) if bwd_time_diffs else 0

        fwd_header_length = sum(self.data['fwd_header_lengths']) if self.data['fwd_header_lengths'] else 0
        bwd_header_length = sum(self.data['bwd_header_lengths']) if self.data['bwd_header_lengths'] else 0
        avg_fwd_segment_size = np.mean(self.data['fwd_segment_sizes']) if self.data['fwd_segment_sizes'] else 0
        avg_bwd_segment_size = np.mean(self.data['bwd_segment_sizes']) if self.data['bwd_segment_sizes'] else 0
        min_seg_size_forward = min(self.data['fwd_segment_sizes']) if self.data['fwd_segment_sizes'] else 0

        udp_port_consistency = len(self.data['udp_dest_ports']) <= 1

        init_win_forward = self.data['init_win_forward']
        init_win_backward = self.data['init_win_backward']

        self.data['packets'] = []
        self.data['timestamps'] = []
        self.data['source_ips'] = set()
        self.data['last_processed'] = current_time
        self.data['inbound_counts'] = {'inbound': 0, 'outbound': 0}
        self.data['tcp_flags'] = {
            'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0, 'ack': 0, 'urg': 0, 'ece': 0, 'cwr': 0,
            'fwd_psh': 0, 'bwd_psh': 0, 'fwd_urg': 0, 'bwd_urg': 0
        }
        self.data['fwd_timestamps'] = []
        self.data['bwd_timestamps'] = []
        self.data['fwd_header_lengths'] = []
        self.data['bwd_header_lengths'] = []
        self.data['fwd_segment_sizes'] = []
        self.data['bwd_segment_sizes'] = []
        self.data['init_win_forward'] = None
        self.data['init_win_backward'] = None
        self.data['udp_dest_ports'] = set()

        return {
            'protocol': protocol,
            'flow_duration': flow_duration,
            'total_fwd_packets': total_packets,
            'total_backward_packets': 0,
            'total_length_of_fwd_packets': total_length,
            'total_length_of_bwd_packets': 0,
            'fwd_packet_length_max': max(packet_lengths) if packet_lengths else 0,
            'fwd_packet_length_min': min(packet_lengths) if packet_lengths else 0,
            'fwd_packet_length_mean': packet_length_mean,
            'fwd_packet_length_std': packet_length_std,
            'bwd_packet_length_max': 0,
            'bwd_packet_length_min': 0,
            'bwd_packet_length_mean': 0,
            'bwd_packet_length_std': 0,
            'flow_bytess': flow_bytess,
            'flow_packetss': packet_rate,
            'flow_iat_mean': flow_iat_mean,
            'flow_iat_std': flow_iat_std,
            'flow_iat_max': flow_iat_max,
            'flow_iat_min': flow_iat_min,
            'fwd_iat_total': fwd_iat_total,
            'fwd_iat_mean': fwd_iat_mean,
            'fwd_iat_std': fwd_iat_std,
            'fwd_iat_max': fwd_iat_max,
            'fwd_iat_min': fwd_iat_min,
            'bwd_iat_total': bwd_iat_total,
            'bwd_iat_mean': bwd_iat_mean,
            'bwd_iat_std': bwd_iat_std,
            'bwd_iat_max': bwd_iat_max,
            'bwd_iat_min': bwd_iat_min,
            'fwd_psh_flags': self.data['tcp_flags']['fwd_psh'],
            'bwd_psh_flags': self.data['tcp_flags']['bwd_psh'],
            'fwd_urg_flags': self.data['tcp_flags']['fwd_urg'],
            'bwd_urg_flags': self.data['tcp_flags']['bwd_urg'],
            'fwd_header_length': fwd_header_length,
            'bwd_header_length': bwd_header_length,
            'fwd_packetss': packet_rate,
            'bwd_packetss': 0,
            'min_packet_length': min(packet_lengths) if packet_lengths else 0,
            'max_packet_length': max(packet_lengths) if packet_lengths else 0,
            'packet_length_mean': packet_length_mean,
            'packet_length_std': packet_length_std,
            'packet_length_variance': packet_length_variance,
            'fin_flag_count': self.data['tcp_flags']['fin'],
            'syn_flag_count': self.data['tcp_flags']['syn'],
            'rst_flag_count': self.data['tcp_flags']['rst'],
            'psh_flag_count': self.data['tcp_flags']['psh'],
            'ack_flag_count': self.data['tcp_flags']['ack'],
            'urg_flag_count': self.data['tcp_flags']['urg'],
            'cwe_flag_count': self.data['tcp_flags']['cwr'],
            'ece_flag_count': self.data['tcp_flags']['ece'],
            'downup_ratio': downup_ratio,
            'average_packet_size': packet_length_mean,
            'avg_fwd_segment_size': avg_fwd_segment_size,
            'avg_bwd_segment_size': avg_bwd_segment_size,
            'init_win_bytes_forward': init_win_forward if init_win_forward is not None else 0,
            'init_win_bytes_backward': init_win_backward if init_win_backward is not None else 0,
            'inbound': inbound,
            'udp_port_consistency': udp_port_consistency
        }

    def start_sniffing(self):
        sniff(prn=self.packet_callback, store=False, filter="ip", stop_filter=lambda x: False)