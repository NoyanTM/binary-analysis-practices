import argparse


def init_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="BinaryAnalizer",
        description="What the program does",
        epilog="Text at the bottom of help",
        # add_help=
    )
    # parser.add_argument()
    return parser
    