from typing import Annotated

from fastapi import APIRouter, UploadFile

# from src.dependencies import GhidraDep, AnalyzerDep

analyzer_router = APIRouter()


@analyzer_router.get("/file/{id}/functions")
def get_functions() -> int: # session: GhidraDep, analyzer: AnalyzerDep
    return id
    # analyzer = Analyzer(session=session)
    # functions = analyzer.list_functions()

@analyzer_router.post("/file/upload")
def upload_file(file: UploadFile) -> dict:
    file_data = file.read
    
    return {"response": "file uploaded"}