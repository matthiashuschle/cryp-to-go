import pathlib
import pytest
from cryp_to_go import path_handler


def test_init():
    inst = path_handler.SubPath('foo/bar')
    assert str(inst.relative_path) == 'foo/bar'
    inst = path_handler.SubPath(pathlib.Path('foo/bar'))
    assert str(inst.relative_path) == 'foo/bar'
    with pytest.raises(ValueError, match="only relative"):
        path_handler.SubPath('/foo/bar')
    with pytest.raises(ValueError, match="not allowed"):
        path_handler.SubPath('foo/../bar')


@pytest.mark.parametrize("input_path,target", [
    ('foo/bar', 'foo/bar'),
    (pathlib.Path('foo/bar'), 'foo/bar'),
    ('/foo/bar', '/foo/bar'),
    (pathlib.Path('/foo/bar'), '/foo/bar'),
])
def test_to_path(input_path, target):
    path = path_handler.SubPath.to_path(input_path)
    assert isinstance(path, pathlib.Path)
    assert str(path) == target


def test_str():
    path = path_handler.SubPath('foo/bar')
    assert str(path) == 'foo/bar'


@pytest.mark.parametrize("path_parent", ['/foo', pathlib.Path('/foo')])
def test_absolute_path(path_parent):
    path_rel = path_handler.SubPath('bar/bar')
    path_abs = path_rel.absolute_path(path_parent)
    assert isinstance(path_abs, pathlib.Path)
    assert str(path_abs) == '/foo/bar/bar'


@pytest.mark.parametrize("path", ['foo/bar', pathlib.Path('foo/bar')])
def test_from_any_path(path):
    subpath = path_handler.SubPath(path)
    assert isinstance(subpath, path_handler.SubPath)
    assert str(subpath) == 'foo/bar'


def test_slashed_string():
    subpath = path_handler.SubPath('foo')
    assert subpath.slashed_string == 'foo'
    # overwrite internal relative path with PurePath in different flavors
    subpath.relative_path = pathlib.PurePosixPath('foo/bar')
    assert subpath.slashed_string == 'foo/bar'
    subpath.relative_path = pathlib.PureWindowsPath(r'foo\bar')
    assert subpath.slashed_string == 'foo/bar'
