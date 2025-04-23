from abc import ABC, abstractmethod

class Check:
    @abstractmethod
    def point(self):
        return 0
    
    @abstractmethod
    def handle(self, ip: str, data):
        pass