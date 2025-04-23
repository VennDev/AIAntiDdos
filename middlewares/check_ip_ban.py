from functools import wraps
import time

from flask import request

from models import ip_manager

def check_ip_ban(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = request.remote_addr
        current_timestamp = time.time()
        if ip_manager.is_ip_banned(ip_address, current_timestamp):
            remaining_time = int(ip_manager.banned_ips[ip_address] - current_timestamp)
            return f"IP {ip_address} is banned. Try again in {remaining_time} seconds.", 403
        return f(*args, **kwargs)
    return decorated_function
