from jinja2 import Environment, FileSystemLoader, select_autoescape

from obfuscator.functions import add, substract, multiply, divide
from obfuscator.unused import for_loop


def main() -> None:
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape()
    )
    template = env.get_template("obfuscated.jinja")
    rendered_template = template.render(
        functions = [add.as_string(), substract.as_string(), multiply.as_string(), divide.as_string()],
        unused_code = {"unreachables": [for_loop], "deads": [for_loop]}, # TODO: as_unreachable, as_dead
    )
    
    

if __name__ == "__main__":
    main()
