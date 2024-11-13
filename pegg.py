"""
Extract the contents of a Project EGG .bin file.

This is a simple command-line script that takes the path to a .bin file as
an argument and writes out all the files contained within it to the current
directory.

Requires project_egg_bin.ksy to be compiled with ksc-compiler and
`pylzss` (install with `pip install git+https://github.com/yyogo/pylzss.git`).
"""
import lzss  # type: ignore
from pathlib import Path, PureWindowsPath
from sys import argv

from project_egg_bin import ProjectEggBin  # type: ignore

p = ProjectEggBin.from_file(argv[1])
for f in p.files:
    filename = Path(PureWindowsPath(f.filename).as_posix())
    filename.parent.mkdir(parents=True, exist_ok=True)
    if not f.compressed:
        filename.write_bytes(f.body.file_data)
    else:
        filename.write_bytes(
            lzss.decompress(f.body.file_data, initial_buffer_values=0)
        )
