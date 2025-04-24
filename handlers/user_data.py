from checks.check_a import CheckA
from handlers.user_data_manager import UserDataManager
from .violation import ViolationManager 
from config import Config

class UserData:
    def __init__(self, ip: str, user_data_manager: UserDataManager):
        self.user_data_manager = user_data_manager
        self.checks = [
            CheckA(user_data_manager),
        ]

        self.ip = ip
        self.violation = ViolationManager() 

    def handle_checks(self, data):
        for check in self.checks:
            check.handle(self.ip, data)

    def is_full_violation(self) -> bool:
        return self.violation.get_total_points() >= Config.GOAL_POINTS