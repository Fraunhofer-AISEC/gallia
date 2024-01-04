"""Single-Source of Truth Package Versioning and Metadata.

The `pydantic-argparse` package uses the `pyproject.toml` file as a
single-source of truth for the package metadata. As such, rather than
duplicating the metadata in code here, it is retrieved from the installed
package metadata at runtime.

The metadata exported are the `title`, `description`, `version`, `author` and
`license` of the package
"""


# Standard
import sys

# Version-Guarded
if sys.version_info < (3, 8):  # pragma: <3.8 cover
    import importlib_metadata as metadata
else:  # pragma: >=3.8 cover
    from importlib import metadata


# Retrieve Metadata from Package
__title__: str = metadata.metadata(__package__)["name"]
__description__: str = metadata.metadata(__package__)["summary"]
__version__: str = metadata.metadata(__package__)["version"]
__author__: str = metadata.metadata(__package__)["author"]
__license__: str = metadata.metadata(__package__)["license"]
