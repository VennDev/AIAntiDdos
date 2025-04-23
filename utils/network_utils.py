import socket
import logging

def get_server_ip():
    try:
        server_ip = socket.gethostbyname(socket.gethostname())
        logging.info(f"Server IP address: {server_ip}")
        return server_ip
    except Exception as e:
        logging.error(f"Failed to get server IP: {e}")
        return '127.0.0.1'