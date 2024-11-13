# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class ProjectEggBin(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.idstring = (self._io.read_bytes(8)).decode(u"ASCII")
        self.filesize = self._io.read_u4le()
        self.data_off = self._io.read_u4le()
        self.num_files = self._io.read_u4le()
        self.filename_csv = []
        for i in range(self.num_files):
            self.filename_csv.append(ProjectEggBin.FileNames(self._io, self, self._root))

        self.files = []
        for i in range(self.num_files):
            self.files.append(ProjectEggBin.File(i, self._io, self, self._root))


    class FileNames(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.file_name = (self._io.read_bytes_term(44, False, True, True)).decode(u"Shift-JIS")
            self.file_type = (self._io.read_bytes_term(44, False, True, True)).decode(u"Shift-JIS")


    class File(KaitaiStruct):

        class FileType(Enum):
            readme = 1
            license = 2
            data = 3
            game = 11
        def __init__(self, i, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.i = i
            self._read()

        def _read(self):
            self.compressed = self._io.read_bits_int_le(1) != 0
            self._io.align_to_byte()
            self.type = KaitaiStream.resolve_enum(ProjectEggBin.File.FileType, self._io.read_u1())
            self.size = self._io.read_u4le()
            _on = self.compressed
            if _on == True:
                self.body = ProjectEggBin.CompressedData(self._io, self, self._root)
            elif _on == False:
                self.body = ProjectEggBin.UncompressedData(self._io, self, self._root)

        @property
        def filename(self):
            if hasattr(self, '_m_filename'):
                return self._m_filename

            self._m_filename = self._root.filename_csv[self.i].file_name
            return getattr(self, '_m_filename', None)


    class CompressedData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.decompressed_size = self._io.read_u4le()
            self.file_data = self._io.read_bytes((self._parent.size - 4))


    class UncompressedData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.file_data = self._io.read_bytes(self._parent.size)



