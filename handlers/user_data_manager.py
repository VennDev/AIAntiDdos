from handlers.user_data import UserData


class UserDataManager:
    def __init__(self):
        self.user_data = {}

    def is_ip_in_user_data(self, ip: str) -> bool:
        return ip in self.user_data

    def add_user_data_if_not_exists(self, ip: str):
        if ip not in self.user_data:
            self.user_data[ip] = UserData(ip, self)
            return True
        return False

    def get_user_data(self, ip: str) -> UserData | None:
        return self.user_data.get(ip)