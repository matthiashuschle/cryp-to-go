""" Keep subpath handling consistent.

As files should not be written outside of CWD, this is a security issue.
Paths may be provided as absolute or relative, and they may be manipulated
inside the storage files. So the check should happen every time a path is
actually used.
"""
import os
import pathlib
from typing import TypeVar

AnyPath = TypeVar("AnyPath", str, pathlib.Path)


class SubPath:

    def __init__(self, relative_path: AnyPath):
        """ Wrapper for pathlib.Path that only allows relative paths without .. elements. """
        self.relative_path = self.to_path(relative_path)
        if self.relative_path.is_absolute():
            raise ValueError("only relative paths allowed here! (%s)" % relative_path)
        if '..' in self.relative_path.parts:
            raise ValueError("'..' not allowed in SubPath! (%s)" % relative_path)

    def __str__(self) -> str:
        """ relative string representation. """
        return str(self.relative_path)

    @staticmethod
    def to_path(path: AnyPath) -> pathlib.Path:
        """ Pure conversion of string or Path to Path. """
        print(path)
        if not isinstance(path, pathlib.Path):
            return pathlib.Path(path)
        return path

    def absolute_path(self, parent: AnyPath) -> pathlib.Path:
        """ Transform to absolute. """
        return self.to_path(parent) / self.relative_path

    @classmethod
    def from_any_path(cls, path: AnyPath, parent: AnyPath) -> "SubPath":
        """ Create from absolute or relative path. """
        abs_path = cls.to_path(os.path.abspath(path))
        abs_parent = cls.to_path(os.path.abspath(parent))
        return cls(abs_path.relative_to(abs_parent))

    @property
    def slashed_string(self) -> str:
        """ '/'-separated string representation.

        Intended for platform-independent storage.
        """
        return '/'.join(self.relative_path.parts)
