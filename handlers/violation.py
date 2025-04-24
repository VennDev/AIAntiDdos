class Violation:
    def __init__(self, id: str, description: str, point: int):
        self.id = id
        self.description = description
        self.point = point

    def __repr__(self):
        return f"Violation(id={self.id}, description='{self.description}', point={self.point})"

class ViolationManager:
    def __init__(self):
        self.violations = []

    def add_violation(self, violation: Violation) -> bool:
        if self.get_violation_by_id(violation.id):
            violation.point += self.get_violation_by_id(violation.id).point
            self.violations.append(violation)
            return False
        self.violations.append(violation)
        return True

    def get_violations(self) -> list:
        return self.violations

    def get_violation_by_id(self, id: str) -> Violation | None:
        for violation in self.violations:
            if violation.id == id:
                return violation
        return None

    def get_total_points(self) -> int:
        return sum(violation.point for violation in self.violations)

    def remove_violation(self, id: str) -> bool:
        violation = self.get_violation_by_id(id)
        if violation:
            self.violations.remove(violation)
            return True
        return False

    def get_violations_by_points(self, min_points: int = 0, max_points: int = float('inf')) -> list:
        return [v for v in self.violations if min_points <= v.point <= max_points]

    def clear_violations(self) -> None:
        self.violations.clear()