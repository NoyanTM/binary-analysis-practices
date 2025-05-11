import os
from dataclasses import dataclass
from dotenv import load_dotenv, find_dotenv


@dataclass
class Config:
    HOST: str
    PORT: int
    

def load_config():
    load_dotenv(find_dotenv())
    config = Config(
        HOST=os.environ.get("HOST"),
        PORT=int(os.environ.get("PORT")),
    )
    return config
