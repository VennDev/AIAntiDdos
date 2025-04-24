import logging
import time
from checks.acheck import Check
from handlers import user_data
from handlers.violation import Violation


class CheckA(Check):
    last_time = 0
    
    def point(self):
        return 50
    
    def handle(self, ip: str, data):
        user_data_manager = user_data.UserDataManager()
        user_data_manager.get_user_data(ip) 

        current_time = time.time()
        diff = current_time - self.last_time

        if diff < 5:
            violation = Violation(
                "check_a", 
                "Check A triggered too frequently in a short period of time diff=" + str(diff), 
                self.point()
            )

            logging.info(f"Check A triggered for IP {ip}: {violation}")
            user_data_manager.get_user_data(ip).violation.add_violation(violation)