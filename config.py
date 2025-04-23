class Config:
    BANNED_IPS_FILE = 'banned_ips.json'
    BAN_DURATION = 3600 # 1 hour in seconds
    SAMPLES_PER_IP = 100 # Number of samples to store per IP
    GOAL_POINTS = 100 # The number of points that the user places may be banned
    FEATURES = [
        'flow_duration', 'total_fwd_packets', 'total_backward_packets',
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
        'inbound'
    ]
    DROP_COLS = [
        'unnamed_0', 'flow_id', 'source_ip', 'destination_ip',
        'source_port', 'destination_port', 'timestamp', 'protocol',
        'label', 'attack_type'
    ]