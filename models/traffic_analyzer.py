import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import joblib
import logging
from collections import defaultdict
from utils.preprocess import preprocess_data
from config import Config

from utils.types_attack import TypesAttack

class TrafficAnalyzer:    
    def __init__(self):
        self.model = load_model('model.keras')
        self.scaler = joblib.load('scaler.pkl')
        self.label_encoder = joblib.load('label_encoder.pkl')
        self.traffic_samples_by_ip = defaultdict(lambda: [[] for _ in range(50)])
        self.current_stack_index = defaultdict(int)
        self.analysis_history = []
        logging.info(f"Label encoder classes: {self.label_encoder.classes_}")

    def prepare_traffic_data(self, network_features, content_length, http_request_rate):
        return {
            'flow_duration': network_features.get('flow_duration', 1000),
            'total_fwd_packets': network_features.get('total_fwd_packets', 1),
            'total_backward_packets': network_features.get('total_backward_packets', 1),
            'total_length_of_fwd_packets': network_features.get('total_length_of_fwd_packets', content_length),
            'total_length_of_bwd_packets': network_features.get('total_length_of_bwd_packets', 0),
            'fwd_packet_length_max': network_features.get('fwd_packet_length_max', content_length),
            'fwd_packet_length_min': network_features.get('fwd_packet_length_min', content_length),
            'fwd_packet_length_mean': network_features.get('fwd_packet_length_mean', content_length),
            'fwd_packet_length_std': network_features.get('fwd_packet_length_std', 0),
            'bwd_packet_length_max': network_features.get('bwd_packet_length_max', 0),
            'bwd_packet_length_min': network_features.get('bwd_packet_length_min', 0),
            'bwd_packet_length_mean': network_features.get('bwd_packet_length_mean', 0),
            'bwd_packet_length_std': network_features.get('bwd_packet_length_std', 0),
            'flow_bytess': network_features.get('flow_bytess', 0),
            'flow_packetss': network_features.get('flow_packetss', 0),
            'flow_iat_mean': network_features.get('flow_iat_mean', 0),
            'flow_iat_std': network_features.get('flow_iat_std', 0),
            'flow_iat_max': network_features.get('flow_iat_max', 0),
            'flow_iat_min': network_features.get('flow_iat_min', 0),
            'fwd_iat_total': network_features.get('fwd_iat_total', 0),
            'fwd_iat_mean': network_features.get('fwd_iat_mean', 0),
            'fwd_iat_std': network_features.get('fwd_iat_std', 0),
            'fwd_iat_max': network_features.get('fwd_iat_max', 0),
            'fwd_iat_min': network_features.get('fwd_iat_min', 0),
            'bwd_iat_total': network_features.get('bwd_iat_total', 0),
            'bwd_iat_mean': network_features.get('bwd_iat_mean', 0),
            'bwd_iat_std': network_features.get('bwd_iat_std', 0),
            'bwd_iat_max': network_features.get('bwd_iat_max', 0),
            'bwd_iat_min': network_features.get('bwd_iat_min', 0),
            'fwd_psh_flags': network_features.get('fwd_psh_flags', 0),
            'bwd_psh_flags': network_features.get('bwd_psh_flags', 0),
            'fwd_urg_flags': network_features.get('fwd_urg_flags', 0),
            'bwd_urg_flags': network_features.get('bwd_urg_flags', 0),
            'fwd_header_length': network_features.get('fwd_header_length', 0),
            'bwd_header_length': network_features.get('bwd_header_length', 0),
            'fwd_packetss': network_features.get('fwd_packetss', 0),
            'bwd_packetss': network_features.get('bwd_packetss', 0),
            'min_packet_length': network_features.get('min_packet_length', content_length),
            'max_packet_length': network_features.get('max_packet_length', content_length),
            'packet_length_mean': network_features.get('packet_length_mean', content_length),
            'packet_length_std': network_features.get('packet_length_std', 0),
            'packet_length_variance': network_features.get('packet_length_variance', 0),
            'fin_flag_count': network_features.get('fin_flag_count', 0),
            'syn_flag_count': network_features.get('syn_flag_count', 0),
            'rst_flag_count': network_features.get('rst_flag_count', 0),
            'psh_flag_count': network_features.get('psh_flag_count', 0),
            'ack_flag_count': network_features.get('ack_flag_count', 0),
            'urg_flag_count': network_features.get('urg_flag_count', 0),
            'cwe_flag_count': network_features.get('cwe_flag_count', 0),
            'ece_flag_count': network_features.get('ece_flag_count', 0),
            'downup_ratio': network_features.get('downup_ratio', 0),
            'average_packet_size': network_features.get('average_packet_size', content_length),
            'avg_fwd_segment_size': network_features.get('avg_fwd_segment_size', content_length),
            'avg_bwd_segment_size': network_features.get('avg_bwd_segment_size', 0),
            'fwd_header_length1': network_features.get('fwd_header_length', 0),
            'fwd_avg_bytesbulk': 0,
            'fwd_avg_packetsbulk': 0,
            'fwd_avg_bulk_rate': 0,
            'bwd_avg_bytesbulk': 0,
            'bwd_avg_packetsbulk': 0,
            'bwd_avg_bulk_rate': 0,
            'subflow_fwd_packets': network_features.get('total_fwd_packets', 1),
            'subflow_fwd_bytes': network_features.get('total_length_of_fwd_packets', content_length),
            'subflow_bwd_packets': network_features.get('total_backward_packets', 1),
            'subflow_bwd_bytes': network_features.get('total_length_of_bwd_packets', 0),
            'init_win_bytes_forward': network_features.get('init_win_bytes_forward', 0),
            'init_win_bytes_backward': network_features.get('init_win_bytes_backward', 0),
            'act_data_pkt_fwd': network_features.get('total_fwd_packets', 1),
            'min_seg_size_forward': network_features.get('min_seg_size_forward', 0),
            'active_mean': 0,
            'active_std': 0,
            'active_max': 0,
            'active_min': 0,
            'idle_mean': 0,
            'idle_std': 0,
            'idle_max': 0,
            'idle_min': 0,
            'inbound': network_features.get('inbound', 1)
        }

    def store_traffic_data(self, ip_address, traffic_data):
        current_stack = self.traffic_samples_by_ip[ip_address][self.current_stack_index[ip_address]]
        current_stack.append(traffic_data)
        if len(current_stack) > Config.SAMPLES_PER_IP:
            current_stack.pop(0)

    def is_stack_full(self, ip_address):
        return len(self.traffic_samples_by_ip[ip_address][self.current_stack_index[ip_address]]) == Config.SAMPLES_PER_IP

    def get_traffic_dataframe(self, ip_address):
        return pd.DataFrame(self.traffic_samples_by_ip[ip_address][self.current_stack_index[ip_address]])

    def analyze_traffic(self, data_df, http_request_rate, network_features):
        try:
            aggregated_data = data_df.select_dtypes(include=['int64', 'float64']).mean().to_dict()
            aggregated_df = pd.DataFrame([aggregated_data])
            processed_data = preprocess_data(aggregated_df, self.scaler, Config.FEATURES, Config.DROP_COLS)
            prediction = self.model.predict(processed_data)
            predicted_class = self.label_encoder.inverse_transform([np.argmax(prediction[0])])[0]
            confidence = np.max(prediction[0])
            is_attack = predicted_class != TypesAttack.BENIGN 

            avg_flow_packetss = data_df['flow_packetss'].mean()
            avg_packet_length_std = data_df['packet_length_std'].mean()
            protocol = 6 if data_df['total_fwd_packets'].sum() >= data_df['total_length_of_bwd_packets'].sum() else 17
            udp_port_consistency = network_features.get('udp_port_consistency', False)

            if (protocol == 17 and avg_flow_packetss > 50 and avg_packet_length_std < 10 and udp_port_consistency):
                predicted_class = TypesAttack.LOIC_UDP_FLOOD
                confidence = 0.95
                is_attack = True
                logging.info(f"Detected LOIC UDP Flood: avg_flow_packetss={avg_flow_packetss}, avg_packet_length_std={avg_packet_length_std}, udp_port_consistency={udp_port_consistency}")
            elif protocol == 6 and http_request_rate > 50:
                predicted_class = TypesAttack.HOIC_HTTP_FLOOD
                confidence = 0.95
                is_attack = True
                logging.info(f"Detected HOIC HTTP Flood: http_request_rate={http_request_rate}")

            return predicted_class, confidence, is_attack
        except Exception as e:
            logging.error(f"Error in traffic analysis: {e}")
            return "Error", 0.0, False

    def store_analysis_history(self, ip_address, current_time, result, confidence, is_attack):
        self.analysis_history.append({
            'ip_address': ip_address,
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'result': result,
            'confidence': f"{confidence:.2%}",
            'is_attack': is_attack
        })
        if len(self.analysis_history) > 100:
            self.analysis_history.pop(0)

    def clear_current_stack(self, ip_address):
        self.traffic_samples_by_ip[ip_address][self.current_stack_index[ip_address]] = []
        self.current_stack_index[ip_address] = (self.current_stack_index[ip_address] + 1) % 50