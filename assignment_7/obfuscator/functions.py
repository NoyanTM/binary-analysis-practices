from typing import Any
from dataclasses import dataclass, asdict
import random
import string

function_template = """
{return_type} {name}({parameters}){{
    {body}
}}
"""


# @dataclass
# class Parameter:
#     type: str
#     name: str


@dataclass
class Function:
    return_type: str
    name: str
    parameters: list[dict[str, Any]]  # list[Parameter]
    body: str

    def __post_init__(self) -> None:
        self._randomize_identifiers(self.name)  # TODO: randomize for other fields

    def as_string(self) -> str:
        # TODO: adaptate complex structure of Function
        return function_template.format(**asdict(self))

    def _randomize_identifiers(self, *args, **kwargs):
        # random.choice(string.ascii_letters)
        # rename and change functions / variables to meaningless
        # заменить каждый символ на случайных или полноценный случайный string
        pass


add = Function(
    return_type="int",
    name="add",
    parameters=[
        {"type": "int", "parameter": "first"},
        {"type": "int", "parameter": "second"},
    ],
    body="return first + second;",  # TODO: использовать все parameters либо часть подставлять и попробовать сложный body
)

substract = Function(
    return_type="int",
    name="substract",
    parameters=[
        {"type": "int", "parameter": "first"},
        {"type": "int", "parameter": "second"},
    ],
    body="return first - second;",
)

divide = Function(
    return_type="int",
    name="divide",
    parameters=[
        {"type": "int", "parameter": "first"},
        {"type": "int", "parameter": "second"},
    ],
    body="return first / second;",
)

multiply = Function(
    return_type="int",
    name="multiply",
    parameters=[
        {"type": "int", "parameter": "first"},
        {"type": "int", "parameter": "second"},
    ],
    body="return first * second;",
)
