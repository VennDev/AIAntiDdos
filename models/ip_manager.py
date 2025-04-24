import json
import os
from collections import defaultdict
import logging
from config import Config

class IPManager:
    def __init__(self):
        self.request_timestamps = defaultdict(list)
        self.banned_ips = self.load_banned_ips()

    def load_banned_ips(self):
        if os.path.exists(Config.BANNED_IPS_FILE):
            with open(Config.BANNED_IPS_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_banned_ips(self, reason: str):
        with open(Config.BANNED_IPS_FILE, 'w') as f:
            json.dump(self.banned_ips, f)

    def is_ip_banned(self, ip_address, current_timestamp):
        if ip_address in self.banned_ips:
            if current_timestamp < self.banned_ips[ip_address]:
                return True
            else:
                del self.banned_ips[ip_address]
                self.save_banned_ips()
                logging.info(f"IP {ip_address} ban has expired. Removed from banned list.")
        return False

    def ban_ip(self, ip_address, current_timestamp, ban_duration, reason):
        self.banned_ips[ip_address] = {'reason': reason, 'timestamp': current_timestamp + ban_duration, 'real_time': current_timestamp}
        self.save_banned_ips(reason)

    def update_request_timestamps(self, ip_address, current_timestamp):
        self.request_timestamps[ip_address].append(current_timestamp)
        self.request_timestamps[ip_address] = [t for t in self.request_timestamps[ip_address] if current_timestamp - t < 60]

    def calculate_request_rate(self, ip_address):
        return len(self.request_timestamps[ip_address]) / 60.0