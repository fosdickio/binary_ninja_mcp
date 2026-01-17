from dataclasses import dataclass
from typing import Optional


@dataclass
class ServerConfig:
    host: str = "localhost"
    port: int = 9009
    debug: bool = False


@dataclass
class BinaryNinjaConfig:
    api_version: Optional[str] = None
    log_level: str = "INFO"


class Config:
    def __init__(self):
        self.server = ServerConfig()
        self.binary_ninja = BinaryNinjaConfig()
