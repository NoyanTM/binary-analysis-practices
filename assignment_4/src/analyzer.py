from abc import ABC, abstractmethod
from typing import ContextManager

from src.graph import CallGraph


class Analyzer(ABC):
    @abstractmethod
    def find_calls_to_function(self, function_name: str) -> list[dict] | None:
        raise NotImplementedError
    
    @abstractmethod
    def list_functions(self) -> list[dict] | None:
        raise NotImplementedError
    
    @abstractmethod
    def find_dangerous_functions(self) -> list[dict] | None:
        raise NotImplementedError
    
    @abstractmethod
    def extract_strings(self) -> list[dict] | None:
        raise NotImplementedError


class GhidraAnalyzer(Analyzer):
    def __init__(
        self,
        session: ContextManager["FlatProgramAPI"]
    ) -> None:
        self.session = session   
    
    def find_calls_to_function(self, function_name: str) -> list[dict] | None:
        program = self.session.getCurrentProgram()
        function_manager = program.getFunctionManager()
        reference_manager = program.getReferenceManager()
        functions = function_manager.getFunctions(True)
        if not functions:
            return None
        target_function = None
        for function in functions:
            name = function.getName()
            if name == function_name:
                target_function = function
                break
        if target_function is None:
            return None
        start_address = target_function.getEntryPoint()
        references = reference_manager.getReferencesTo(start_address)
        if not references:
            return None
        calls_to_function = []
        for reference in references:
            from ghidra.program.model.symbol import RefType
            if reference.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                call = {
                    "name": target_function.getName(),
                    "called_at": reference.getFromAddress().toString()
                }
                calls_to_function.append(call)
        return calls_to_function
    
    def list_functions(self) -> list[dict] | None:
        program = self.session.getCurrentProgram()
        function_manager = program.getFunctionManager()
        functions = function_manager.getFunctions(True)
        if not functions:
            return None
        functions_list = []
        for function in functions:
            name = function.getName()
            start_address = function.getEntryPoint().toString()
            end_address = function.getBody().getMaxAddress().toString()
            function_data = {
                "name": name,
                "start_address": start_address,
                "end_address": end_address,
                # "size_bytes": end_address - start_address
            }
            functions_list.append(function_data)
        return functions_list
    
    def find_dangerous_functions(self) -> list[dict] | None:
        program = self.session.getCurrentProgram()
        function_manager = program.getFunctionManager()
        reference_manager = program.getReferenceManager()
        functions = function_manager.getFunctions(True)
        if not functions:
            return None
        vulnerable_functions = []
        for function in functions:
            name = function.getName()
            dangerous_functions = ["strcpy", "gets", "system", "memcpy"]
            if name in dangerous_functions:
                start_address = function.getEntryPoint()
                references = reference_manager.getReferencesTo(start_address)
                calls_to_function = []
                for reference in references:
                    if reference.getReferenceType().isCall():
                        call = {"called_at": reference.getFromAddress().toString()}
                        calls_to_function.append(call)
                function_dict = {
                    "name": name,
                    "calls": calls_to_function 
                }
                vulnerable_functions.append(function_dict)
        if not vulnerable_functions:
            return None
        return vulnerable_functions
    
    def extract_strings(self) -> list[dict] | None:
        # may contain useful information (passwords, paths, encryption keys)
        program = self.session.getCurrentProgram()
        listing = program.getListing()
        defined_data = listing.getDefinedData(True)
        strings = []
        for data in defined_data:
            if data.getDataType().getDisplayName().lower() in ["string", "unicode"]:
                string = {
                    "value": data.getValue(),
                    "address": data.getAddress()
                }
                strings.append(string)
        return strings

    # analyze function dependencies
    def construct_call_graph(self) -> CallGraph | None:
        program = self.session.getCurrentProgram()
        function_manager = program.getFunctionManager()
        reference_manager = program.getReferenceManager()
        functions = function_manager.getFunctions(True)
        call_graph = {}
        for function in functions:
            name = function.getName()
            start_address = function.getEntryPoint()
            call_graph[name] = []

            references = reference_manager.getReferencesTo(start_address)
            for reference in references:
                if reference.getReferenceType().isCall():
                    calling_function = reference.getFromAddress().toString() # .getAddress().toString()
                    call_graph[name].append(calling_function)
        networkx_call_graph = CallGraph()
        for function, callers in call_graph.items():
            for caller in callers:
                networkx_call_graph.add_edge(caller, function)
        return networkx_call_graph
    