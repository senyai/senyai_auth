from __future__ import annotations
from typing import TYPE_CHECKING
import io
from os import stat_result
from pathlib import Path
from aioftp.pathio import (
    AbstractPathIO,
    universal_exception,
    defend_file_methods,
)
from aioftp.common import AbstractAsyncLister
from collections.abc import AsyncIterable, Iterator

if TYPE_CHECKING:
    from _typeshed import OpenBinaryMode, ReadableBuffer


class ProtectedPathIO(AbstractPathIO[Path]):
    @universal_exception
    async def exists(self, path: Path) -> bool:
        return path.exists()

    @universal_exception
    async def is_dir(self, path: Path) -> bool:
        return path.is_dir()

    @universal_exception
    async def is_file(self, path: Path) -> bool:
        return path.is_file()

    @universal_exception
    async def mkdir(
        self, path: Path, *, parents: bool = False, exist_ok: bool = False
    ) -> None:
        return path.mkdir(parents=parents, exist_ok=exist_ok)

    @universal_exception
    async def rmdir(self, path: Path) -> None:
        return path.rmdir()

    @universal_exception
    async def unlink(self, path: Path) -> None:
        return path.unlink()

    def list(self, path: Path) -> AsyncIterable[Path]:
        user = self.connection.user
        permissions = user.permissions
        relative_path = path.relative_to(user.base_path)

        class Lister(AbstractAsyncLister[Path]):
            iter: Iterator[Path] | None = None

            @universal_exception
            async def __anext__(self) -> Path:
                if self.iter is None:
                    self.iter = path.glob("*")
                try:
                    return next(self.iter)
                except StopIteration:
                    raise StopAsyncIteration

        return Lister(timeout=self.timeout)

    @universal_exception
    async def stat(self, path: Path) -> stat_result:
        return path.stat()

    @universal_exception
    async def _open(  # type: ignore[override]
        self,
        path: Path,
        mode: "OpenBinaryMode" = "rb",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> io.BytesIO:
        return path.open(  # type: ignore[return-value]
            mode=mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )

    @universal_exception
    @defend_file_methods
    async def seek(
        self,
        file: io.BytesIO,
        offset: int,
        whence: int = io.SEEK_SET,
    ) -> int:
        return file.seek(offset, whence)

    @universal_exception
    @defend_file_methods
    async def write(self, file: io.BytesIO, s: "ReadableBuffer") -> int:
        return file.write(s)

    @universal_exception
    @defend_file_methods
    async def read(self, file: io.BytesIO, n: int = -1) -> bytes:
        return file.read(n)

    @universal_exception
    @defend_file_methods
    async def close(self, file: io.BytesIO) -> None:
        return file.close()

    @universal_exception
    async def rename(self, source: Path, destination: Path) -> Path:
        return source.rename(destination)
