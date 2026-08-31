"""Single-source package version metadata with no runtime discovery."""

VERSION = (0, 2, 0)
__version__ = ".".join(str(part) for part in VERSION)
__version_info__ = VERSION

__all__ = ("VERSION", "__version__", "__version_info__")
