from dataclasses import asdict, dataclass
from typing import Dict



@dataclass
class Alert:
    id: str
    type: str
    severity: str
    description: str
    timestamp: str
    active: bool = True

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)
