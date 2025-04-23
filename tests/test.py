import pandas as pd
import numpy as np
from flask import Flask, request, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP
from tensorflow.keras.models import load_model
import joblib
import threading
import time
from collections import defaultdict
from datetime import datetime
import socket
import struct

app = Flask(__name__)

# Load the trained model and preprocessing objects
# Updated to load .keras model
model = load_model('model.keras')  # Load .keras model
scaler = joblib.load('scaler.pkl')
label_encoder = joblib.load('label_encoder.pkl')

# Define the expected features (88 columns from the dataset)
FEATURES = [
    'unnamed_0', 'flow_id', 'source_ip', 'source_port', 'destination_ip', 'destination_port',
    'protocol', 'timestamp', 'flow_duration', 'total_fwd_packets', 'total_backward_packets',
    'total_length_of_fwd_packets', 'total_length_of_bwd_packets', 'fwd_packet_length_max',
    'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean',
    'bwd_packet_length_std', 'flow_bytess', 'flow_packetss', 'flow_iat_mean',
    'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_total', 'fwd_iat_mean',
    'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'bwd_iat_total', 'bwd_iat_mean',
    'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags',
    'fwd_urg_flags', 'bwd_urg_flags', 'fwd_header_length', 'bwd_header_length',
    'fwd_packetss', 'bwd_packetss', 'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance',
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count',
    'ack_flag_count', 'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
    'downup_ratio', 'average_packet_size', 'avg_fwd_segment_size',
    'avg_bwd_segment_size', 'fwd_header_length1', 'fwd_avg_bytesbulk',
    'fwd_avg_packetsbulk', 'fwd_avg_bulk_rate', 'bwd_avg_bytesbulk',
    'bwd_avg_packetsbulk', 'bwd_avg_bulk_rate', 'subflow_fwd_packets',
    'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
    'init_win_bytes_forward', 'init_win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'active_mean', 'active_std', 'active_max',
    'active_min', 'idle_mean', 'idle_std', 'idle_max', 'idle_min',
    'simillarhttp', 'inbound', 'label'
]

# Global variables for packet capture
captured_packets = []
capture_active = False
capture_lock = threading.Lock()

# Convert IP to integer
def ip_to_int(ip):
    try:
        return int(socket.inet_aton(ip).hex(), 16)
    except:
        return 0

# Packet callback for Scapy
def packet_callback(packet):
    global captured_packets
    if capture_active and (IP in packet):
        with capture_lock:
            captured_packets.append(packet)

# Start packet capture in a separate thread
def start_packet_capture(interface='eth0', duration=10):
    global captured_packets, capture_active
    captured_packets = []
    capture_active = True
    sniff(iface=interface, prn=packet_callback, timeout=duration, store=False)
    capture_active = False

# Extract features from captured packets
def extract_features(packets, client_ip):
    flows = defaultdict(lambda: {
        'timestamps': [], 'fwd_packets': [], 'bwd_packets': [],
        'fwd_lengths': [], 'bwd_lengths': [], 'flags': defaultdict(int)
    })
    
    for pkt in packets:
        if IP not in pkt:
            continue
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        is_inbound = src_ip == client_ip
        
        flow_key = (src_ip, dst_ip, pkt.sport if TCP in pkt or UDP in pkt else 0,
                    pkt.dport if TCP in pkt or UDP in pkt else 0,
                    pkt.proto)
        
        flow = flows[flow_key]
        flow['timestamps'].append(pkt.time)
        pkt_len = len(pkt)
        
        if is_inbound:
            flow['fwd_packets'].append(pkt)
            flow['fwd_lengths'].append(pkt_len)
            if TCP in pkt:
                tcp = pkt[TCP]
                flow['flags']['fwd_psh'] += 1 if 'P' in tcp.flags else 0
                flow['flags']['fwd_urg'] += 1 if 'U' in tcp.flags else 0
                flow['flags']['fin'] += 1 if 'F' in tcp.flags else 0
                flow['flags']['syn'] += 1 if 'S' in tcp.flags else 0
                flow['flags']['rst'] += 1 if 'R' in tcp.flags else 0
                flow['flags']['ack'] += 1 if 'A' in tcp.flags else 0
        else:
            flow['bwd_packets'].append(pkt)
            flow['bwd_lengths'].append(pkt_len)
            if TCP in pkt:
                tcp = pkt[TCP]
                flow['flags']['bwd_psh'] += 1 if 'P' in tcp.flags else 0
                flow['flags']['bwd_urg'] += 1 if 'U' in tcp.flags else 0
    
    # Create DataFrame for features
    data = []
    for flow_key, flow in flows.items():
        src_ip, dst_ip, src_port, dst_port, proto = flow_key
        timestamps = sorted(flow['timestamps'])
        flow_duration = (max(timestamps) - min(timestamps)) * 1e6 if timestamps else 0
        
        fwd_lengths = flow['fwd_lengths']
        bwd_lengths = flow['bwd_lengths']
        total_fwd_packets = len(flow['fwd_packets'])
        total_bwd_packets = len(flow['bwd_packets'])
        
        iat = np.diff(timestamps) * 1e6 if len(timestamps) > 1 else [0]
        
        row = {
            'unnamed_0': 0,
            'flow_id': f'{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}',
            'source_ip': ip_to_int(src_ip),
            'source_port': src_port,
            'destination_ip': ip_to_int(dst_ip),
            'destination_port': dst_port,
            'protocol': proto,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'flow_duration': flow_duration,
            'total_fwd_packets': total_fwd_packets,
            'total_backward_packets': total_bwd_packets,
            'total_length_of_fwd_packets': sum(fwd_lengths),
            'total_length_of_bwd_packets': sum(bwd_lengths),
            'fwd_packet_length_max': max(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_min': min(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_mean': np.mean(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_std': np.std(fwd_lengths) if fwd_lengths else 0,
            'bwd_packet_length_max': max(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_min': min(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_mean': np.mean(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_std': np.std(bwd_lengths) if bwd_lengths else 0,
            'flow_bytess': (sum(fwd_lengths) + sum(bwd_lengths)) / (flow_duration / 1e6) if flow_duration else 0,
            'flow_packetss': (total_fwd_packets + total_bwd_packets) / (flow_duration / 1e6) if flow_duration else 0,
            'flow_iat_mean': np.mean(iat) if iat else 0,
            'flow_iat_std': np.std(iat) if iat else 0,
            'flow_iat_max': max(iat) if iat else 0,
            'flow_iat_min': min(iat) if iat else 0,
            'fwd_iat_total': sum(iat) if iat else 0,
            'fwd_iat_mean': np.mean(iat) if iat else 0,
            'fwd_iat_std': np.std(iat) if iat else 0,
            'fwd_iat_max': max(iat) if iat else 0,
            'fwd_iat_min': min(iat) if iat else 0,
            'bwd_iat_total': sum(iat) if iat else 0,
            'bwd_iat_mean': np.mean(iat) if iat else 0,
            'bwd_iat_std': np.std(iat) if iat else 0,
            'bwd_iat_max': max(iat) if iat else 0,
            'bwd_iat_min': min(iat) if iat else 0,
            'fwd_psh_flags': flow['flags']['fwd_psh'],
            'bwd_psh_flags': flow['flags']['bwd_psh'],
            'fwd_urg_flags': flow['flags']['fwd_urg'],
            'bwd_urg_flags': flow['flags']['bwd_urg'],
            'fwd_header_length': sum(pkt[IP].ihl * 4 for pkt in flow['fwd_packets'] if IP in pkt),
            'bwd_header_length': sum(pkt[IP].ihl * 4 for pkt in flow['bwd_packets'] if IP in pkt),
            'fwd_packetss': total_fwd_packets / (flow_duration / 1e6) if flow_duration else 0,
            'bwd_packetss': total_bwd_packets / (flow_duration / 1e6) if flow_duration else 0,
            'min_packet_length': min(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'max_packet_length': max(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'packet_length_mean': np.mean(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'packet_length_std': np.std(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'packet_length_variance': np.var(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'fin_flag_count': flow['flags']['fin'],
            'syn_flag_count': flow['flags']['syn'],
            'rst_flag_count': flow['flags']['rst'],
            'psh_flag_count': flow['flags']['fwd_psh'] + flow['flags']['bwd_psh'],
            'ack_flag_count': flow['flags']['ack'],
            'urg_flag_count': flow['flags']['fwd_urg'] + flow['flags']['bwd_urg'],
            'cwe_flag_count': 0,
            'ece_flag_count': 0,
            'downup_ratio': total_bwd_packets / total_fwd_packets if total_fwd_packets else 0,
            'average_packet_size': np.mean(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'avg_fwd_segment_size': np.mean(fwd_lengths) if fwd_lengths else 0,
            'avg_bwd_segment_size': np.mean(bwd_lengths) if bwd_lengths else 0,
            'fwd_header_length1': sum(pkt[IP].ihl * 4 for pkt in flow['fwd_packets'] if IP in pkt),
            'fwd_avg_bytesbulk': 0,
            'fwd_avg_packetsbulk': 0,
            'fwd_avg_bulk_rate': 0,
            'bwd_avg_bytesbulk': 0,
            'bwd_avg_packetsbulk': 0,
            'bwd_avg_bulk_rate': 0,
            'subflow_fwd_packets': total_fwd_packets,
            'subflow_fwd_bytes': sum(fwd_lengths),
            'subflow_bwd_packets': total_bwd_packets,
            'subflow_bwd_bytes': sum(bwd_lengths),
            'init_win_bytes_forward': flow['fwd_packets'][0][TCP].window if flow['fwd_packets'] and TCP in flow['fwd_packets'][0] else 0,
            'init_win_bytes_backward': flow['bwd_packets'][0][TCP].window if flow['bwd_packets'] and TCP in flow['bwd_packets'][0] else 0,
            'act_data_pkt_fwd': total_fwd_packets,
            'min_seg_size_forward': min(pkt[IP].ihl * 4 for pkt in flow['fwd_packets'] if IP in pkt) if flow['fwd_packets'] else 0,
            'active_mean': 0,
            'active_std': 0,
            'active_max': 0,
            'active_min': 0,
            'idle_mean': 0,
            'idle_std': 0,
            'idle_max': 0,
            'idle_min': 0,
            'simillarhttp': 0,
            'inbound': 1 if src_ip == client_ip else 0
        }
        data.append(row)
    
    df = pd.DataFrame(data)
    return df

# Preprocess input data
def preprocess_data(df):
    # Clean column names
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace(r'[^\\w]', '', regex=True)
    
    # Ensure all expected features are present
    for col in FEATURES[:-1]:  # Exclude 'label'
        if col not in df.columns:
            df[col] = 0
    
    # Select only the expected features (excluding 'label')
    df = df[[col for col in FEATURES if col != 'label']]
    
    # Handle non-numeric columns
    non_numeric_cols = ['flow_id', 'source_ip', 'destination_ip', 'timestamp', 'simillarhttp']
    for col in non_numeric_cols:
        if col in df.columns:
            df[col] = df[col].astype(str).str.extract(r'(\d+)').fillna(0).astype(float)
    
    # Handle missing values
    df = df.fillna(0)
    
    # Convert to numeric
    df = df.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # Scale the features
    X = scaler.transform(df)
    
    return X

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    try:
        client_ip = request.remote_addr
        interface = 'eth0'  # Replace with your network interface (e.g., 'wlan0')
        capture_thread = threading.Thread(target=start_packet_capture, args=(interface, 10))
        capture_thread.start()
        
        # Wait for capture to complete
        capture_thread.join()
        
        # Extract features
        with capture_lock:
            df = extract_features(captured_packets, client_ip)
        
        if df.empty:
            return jsonify({'status': 'error', 'message': 'No packets captured'})
        
        # Preprocess data
        X = preprocess_data(df)
        
        # Make predictions
        y_pred = model.predict(X)
        y_pred_classes = y_pred.argmax(axis=1)
        predictions = label_encoder.inverse_transform(y_pred_classes)
        
        # Prepare results
        results = []
        for i, pred in enumerate(predictions):
            results.append({
                'source_ip': socket.inet_ntoa(struct.pack('>I', int(df.iloc[i]['source_ip']))),
                'prediction': pred,
                'confidence': float(y_pred[i].max())
            })
        
        return jsonify({'status': 'success', 'results': results})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)