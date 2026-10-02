"""Command-line entry point for the direct-streaming scanner."""

from .pipeline import parse_args, run


def main():
    run(parse_args())
