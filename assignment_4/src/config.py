import os
from pathlib import Path
from dataclasses import dataclass

from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv(".env"))


@dataclass
class Config:
    base_directory: Path
    ghidra_directory: str


def get_config() -> Config:
    config = Config(
        ghidra_directory=os.getenv("GHIDRA_INSTALL_DIR"),
        base_directory=Path(__file__).parent.parent,
    )
    return config
