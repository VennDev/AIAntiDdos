from checks.check_a import CheckA
from .violation import ViolationManager 
from config import Config

class UserData:
    def __init__(self, ip: str):
        self.checks = {
            CheckA()
        }

        self.ip = ip
        self.violation = ViolationManager() 

    def handle_checks(self, data):
        for check in self.checks:
            check.handle(self.ip, data)

    def is_full_violation(self) -> bool:
        return self.violation.get_total_points() >= Config.GOAL_POINTS

class UserDataManager:
    def __init__(self):
        self.user_data = {}

    def add_user_data_if_not_exists(self, ip: str):
        if ip not in self.user_data:
            self.user_data[ip] = UserData(ip)
            return True
        return False

    def get_user_data(self, ip: str) -> UserData | None:
        return self.user_data.get(ip)