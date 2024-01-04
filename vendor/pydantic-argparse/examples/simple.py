"""Simple Example."""


# Third-Party
import pydantic
import pydantic_argparse


class Arguments(pydantic.BaseModel):
    """Simple Command-Line Arguments."""
    # Required Args
    string: str = pydantic.Field(description="a required string")
    integer: int = pydantic.Field(description="a required integer")
    flag: bool = pydantic.Field(description="a required flag")

    # Optional Args
    second_flag: bool = pydantic.Field(False, description="an optional flag")
    third_flag: bool = pydantic.Field(True, description="an optional flag")


def main() -> None:
    """Simple Main Function."""
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
