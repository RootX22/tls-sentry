# Defined before the submodule imports below: cli reads __version__ from this
# package, so assigning it afterwards makes the import circular.
__version__ = "1.0.1"

from .cli import main  # noqa: E402
from .probe import Result, Status, check  # noqa: E402

__all__ = ["check", "Result", "Status", "main", "__version__"]
