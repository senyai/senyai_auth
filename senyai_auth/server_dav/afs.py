"""
Asynchronous file functions
"""

from __future__ import annotations
from aiofiles import open, os
from pathlib import Path
from stat import S_ISDIR, S_ISREG


async def _copy_single_file(src_path: Path, dst_path: Path) -> None:
    """Copy a single file"""
    async with open(src_path, "rb") as src:
        async with open(dst_path, "wb") as dst:
            while chunk := await src.read(1 << 20):
                await dst.write(chunk)


async def delete(path: Path) -> None:
    """
    Delete `path`, no matter a file or a directory it is
    """
    stat = await os.stat(path)
    if S_ISREG(stat.st_mode):
        await os.unlink(path)
    elif S_ISDIR(stat.st_mode):
        for name in await os.listdir(path):
            await delete(path / name)
        await os.rmdir(path)
    else:
        raise ValueError("Not a file of directory")


async def copy(source: Path, destination: Path) -> None:
    """
    Copy from `source` to `destination`, no matter a file or a directory it is
    """
    stat = await os.stat(source)
    if S_ISREG(stat.st_mode):
        await _copy_single_file(source, destination)
    elif S_ISDIR(stat.st_mode):
        await os.mkdir(destination)
        for name in await os.listdir(source):
            await copy(source / name, destination / name)
    else:
        raise ValueError("Not a file of directory")
