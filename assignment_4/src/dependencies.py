from typing import Annotated
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import Depends
import pyghidra

from src.analyzer import Analyzer

if TYPE_CHECKING:
    import ghidra
    from ghidra.builtins import *


@contextmanager
def get_analyzer_session(binary_file_path: str, base_directory: Path): # config: dict
    try:
        with pyghidra.open_program(
            binary_path=base_directory / binary_file_path, # binary_file_path=config.base_directory / "data/a.out"
            # project_location=None,
            # project_name=None,
            # analyze=None,
            # language=None,
            # compiler=None,
            # loader=None,
        ) as flat_api:
            yield flat_api # ???
    except Exception as e: # TODO: specify exact exceptions here
        # TODO: log here
        return None

# GhidraDep = Annotated["FlatProgramAPI", Depends(get_analyzer_session)]


# def get_analyzer(session: GhidraDep):
#     return Analyzer(session=session)


# AnalyzerDep = Annotated[Analyzer, get_analyzer]

