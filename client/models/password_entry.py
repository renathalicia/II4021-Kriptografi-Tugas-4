import uuid
from dataclasses import dataclass, field


@dataclass
class PasswordEntry:
    nama_layanan: str
    username: str
    password: str
    catatan: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "nama_layanan": self.nama_layanan,
            "username": self.username,
            "password": self.password,
            "catatan": self.catatan,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PasswordEntry":
        return cls(
            id=d.get("id", str(uuid.uuid4())),
            nama_layanan=d["nama_layanan"],
            username=d["username"],
            password=d["password"],
            catatan=d.get("catatan", ""),
        )