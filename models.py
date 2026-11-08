from dataclasses import dataclass, asdict


@dataclass
class Finding:
    id: str
    module: str          # authentication | session | proxy
    title: str
    weight: int
    failed: bool
    detail: str
    remediation: str

    def to_dict(self):
        return asdict(self)
