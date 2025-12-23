from dataclasses import dataclass


@dataclass
class ServerConfig:
    host: str = "localhost"
    port: int = 9009
    debug: bool = False


@dataclass
class BinaryNinjaConfig:
    api_version: str | None = None
    log_level: str = "INFO"


class Config:
    def __init__(self):
        self.server = ServerConfig()
        self.binary_ninja = BinaryNinjaConfig()
