import logging
import time
from checks.acheck import Check
from handlers.violation import Violation


class CheckA(Check):
    
    def __init__(self, user_data_manager):
        super().__init__()
        self.last_time = 0
        self.user_data_manager = user_data_manager
    
    def point(self):
        return 50
    
    def handle(self, ip: str, data):
        self.user_data_manager.get_user_data(ip) 

        current_time = time.time()
        diff = current_time - self.last_time

        if diff < 10:
            violation = Violation(
                "check_a", 
                "Check A triggered too frequently in a short period of time diff=" + str(diff), 
                self.point()
            )

            logging.info(f"----------- Check A triggered for IP {ip}: {violation}")
            self.user_data_manager.get_user_data(ip).violation.add_violation(violation)
        self.last_time = current_time