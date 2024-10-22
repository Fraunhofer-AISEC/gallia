# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Commands Example."""

# Third-Party
import pydantic
import pydantic_argparse

# Typing
from typing import Optional



class BuildCommand(pydantic_argparse.BaseCommand):
    """Build Command Arguments."""

    # Required Args
    location: pydantic.FilePath = pydantic.Field(description="build location")


class ServeCommand(pydantic_argparse.BaseCommand):
    """Serve Command Arguments."""

    # Required Args
    address: pydantic.IPvAnyAddress = pydantic.Field(description="serve address")
    port: int = pydantic.Field(description="serve port")


class Arguments(pydantic_argparse.BaseCommand):
    """Command-Line Arguments."""

    # Optional Args
    verbose: bool = pydantic.Field(False, description="verbose flag")

    # Commands
    build: Optional[BuildCommand] = pydantic.Field(None, description="build command")
    serve: Optional[ServeCommand] = pydantic.Field(None, description="serve command")


def main() -> None:
    """Main Function."""
    # Create Parser and Parse Args
    parser = pydantic_argparse.ArgumentParser(
        model=Arguments,
        prog="Example Program",
        description="Example Description",
        version="0.0.1",
        epilog="Example Epilog",
    )
    args = parser.parse_typed_args()

    # Print Args
    print(args)


if __name__ == "__main__":
    main()
