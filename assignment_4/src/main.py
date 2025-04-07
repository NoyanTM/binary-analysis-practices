from src.config import get_config
from src.dependencies import get_analyzer_session
from src.analyzer import GhidraAnalyzer


def main() -> None:
    config = get_config()
    with get_analyzer_session(binary_file_path="data/example.o", base_directory=config.base_directory) as session:
        ghidra_analyzer = GhidraAnalyzer(session=session)
        functions_list = ghidra_analyzer.list_functions()
        calls = ghidra_analyzer.find_calls_to_function(function_name="printf")
        vulnerable_functions = ghidra_analyzer.find_dangerous_functions()
        strings = ghidra_analyzer.extract_strings()
        call_graph = ghidra_analyzer.construct_call_graph()
        call_graph.render_as_image()
        
        
if __name__ == "__main__": 
    main()
