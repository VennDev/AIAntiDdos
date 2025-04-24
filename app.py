from flask import Flask, request, render_template
import threading
from datetime import datetime
import time
import logging
from models.network_data import NetworkData
from models.traffic_analyzer import TrafficAnalyzer
from models.ip_manager import IPManager
from utils.logging_config import configure_logging
from utils.network_utils import get_server_ip
from handlers.user_data_manager import UserDataManager
from middlewares.check_ip_ban import check_ip_ban
from config import Config

app = Flask(__name__)
configure_logging()

try:
    SERVER_IP = get_server_ip()
    network_data = NetworkData(SERVER_IP)
    traffic_analyzer = TrafficAnalyzer()
    ip_manager = IPManager()
    user_data_manager = UserDataManager()
except Exception as e:
    logging.error(f"Initialization failed: {e}")
    raise

@app.before_request
@check_ip_ban
def log_request_info():
    ip_address = request.remote_addr
    current_time = datetime.now()
    logging.info(f"Request from IP: {ip_address} at {current_time}")

@app.route('/')
@check_ip_ban
def index():
    try:
        ip_address = request.remote_addr
        current_time = datetime.now()
        current_timestamp = time.time()

        ip_manager.update_request_timestamps(ip_address, current_timestamp)

        network_features = network_data.process_network_data() or {}
        http_request_rate = ip_manager.calculate_request_rate(ip_address)
        content_length = int(request.headers.get('Content-Length', 0))
        traffic_data = traffic_analyzer.prepare_traffic_data(network_features, content_length, http_request_rate)
        traffic_analyzer.store_traffic_data(ip_address, traffic_data)

        render_vars = {
            'ip_address': ip_address,
            'is_attack': False
        }

        if traffic_analyzer.is_stack_full(ip_address):
            traffic_df = traffic_analyzer.get_traffic_dataframe(ip_address)
            result, confidence, is_attack = traffic_analyzer.analyze_traffic(traffic_df, http_request_rate, network_features)
            
            if is_attack:
                user_data_manager.add_user_data_if_not_exists(ip_address)
                user_data_manager.get_user_data(ip_address).handle_checks(traffic_df)

            traffic_analyzer.store_analysis_history(ip_address, current_time, result, confidence, is_attack)
            traffic_analyzer.clear_current_stack(ip_address)

            render_vars.update({
                'result': result,
                'confidence': f"{confidence:.2%}",
                'is_attack': is_attack
            })

            is_existing_user = user_data_manager.is_ip_in_user_data(ip_address)
            if is_existing_user and user_data_manager.get_user_data(ip_address).is_full_violation():
                violation = user_data_manager.get_user_data(ip_address).violation
                ip_manager.ban_ip(ip_address, current_timestamp, Config.BAN_DURATION, violation)
                logging.info(f"IP {ip_address} banned for {Config.BAN_DURATION} seconds due to full violation.")

        # Custom your HTML rendering logic here
        return render_template('index.html', **render_vars)
    except Exception as e:
        logging.error(f"Error in index route: {e}")
        return render_template('error.html', error=str(e))

@app.route('/dashboard')
@check_ip_ban
def dashboard():
    return render_template('dashboard.html', history=traffic_analyzer.analysis_history)

if __name__ == '__main__':
    sniff_thread = threading.Thread(target=network_data.start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(host='0.0.0.0', port=5000, debug=True)