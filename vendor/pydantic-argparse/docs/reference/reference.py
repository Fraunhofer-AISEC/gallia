"""Automatic Code Reference Documentation Generation."""


# Standard
import pathlib

# Third-Party
import mkdocs_gen_files


# Configuration
PACKAGE = pathlib.Path("pydantic_argparse")
DOCS = pathlib.Path("reference")

# Constants
FILENAME_NAVIGATION = "SUMMARY.md"
FILENAME_INDEX = "index.md"
PYTHON_GLOB = "**/*.py"
DUNDER = "__"
DOT_MD = ".md"
PREFIX_H1 = "# "
PREFIX_H2 = "## "
PREFIX_CODE = "::: "
ESCAPE_MD = "_", "\\_"


def generate(package: pathlib.Path, docs: pathlib.Path) -> None:
    """Generates the Code Reference Documentation.

    Args:
        package (pathlib.Path): Location of the package to generate docs.
        docs (pathlib.Path): Location to write out docs to.
    """
    # Instantiate Documentation and Navigation Generators
    files_editor = mkdocs_gen_files.FilesEditor.current()
    nav = mkdocs_gen_files.Nav()

    # Loop through regular files in the package
    for source in sorted(package.glob(PYTHON_GLOB)):
        # Generate Reference
        reference = PREFIX_CODE + ".".join(source.with_suffix("").parts)

        # Check if file is "dunder" module
        if source.stem.startswith(DUNDER) and source.stem.endswith(DUNDER):
            # Generate docs for dunder files
            path = docs / source.with_name(FILENAME_INDEX)
            heading = PREFIX_H1 + source.parent.stem
            subheading = PREFIX_H2 + source.name.replace(*ESCAPE_MD)
            titles = source.parent.parts

        else:
            # Generate docs for regular files
            path = docs / source.with_suffix(DOT_MD)
            heading = PREFIX_H1 + source.stem
            subheading = ""
            titles = source.parts

        # Docs
        with files_editor.open(str(path), "a") as file_object:
            # Check if the file is empty
            if not file_object.tell():
                # Heading
                file_object.write(heading + "\n")

            # Sub Heading
            file_object.write(subheading + "\n")

            # Code Reference
            file_object.write(reference + "\n")

        # Build Nav
        nav[titles] = str(path.relative_to(docs))

    # Nav
    with files_editor.open(str(docs / FILENAME_NAVIGATION), "w") as file_object:
        # Write Nav
        file_object.writelines(nav.build_literate_nav())


# Run
generate(PACKAGE, DOCS)
