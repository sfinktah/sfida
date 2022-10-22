"""
Python>mega = load_dehasher('e:/git/GTA5Utilities/megahashes.txt')
INFO indexed 1623154 lines
INFO MegaHash::MakeIndex time_taken: 0.82 minutes to index 1623154 lines

Python>mega = load_dehasher('e:/git/GTA5Utilities/megahashes.txt')
INFO MegaHash::ReadIndex time_taken: 1.8 seconds to read 1619072 lines

Python>mega.Lookup(joaat('CVEHICLE'))
'CVehicle'

Python>mega.Lookup(joaat('test123'))
'0xc44f49a4'
"""

import os, sys, struct, time
from datetime import datetime
from GTA5 import joaat

def file_iter_line_pos(filename):
    position = 0
    with open(filename) as fr:
        line = fr.readline(256)
        while line:
            yield (line, position)
            position += len(line)
            try:
                line = fr.readline(256)
            except UnicodeDecodeError as e:
                print("{}: {} processing byte {}".format(e.__class__.__name__, str(e), position))


def replace_extension(filename, new_extension):
    r = os.path.splitext(filename)
    return os.path.extsep.join([r[0], new_extension])

def file_exists(fn):
    return os.path.exists(fn) and os.path.isfile(fn)

def file_mtime(fn):
    """ return a datetime.datetime object representing the mtime of a file, or datetime.min if non-existant """
    try:
        return datetime.fromtimestamp(os.stat(fn).st_mtime)
    except FileNotFoundError:
        return datetime.min

def is_file_newer(fn1, fn2):
    """ return True if fn1 is newer (mtime) than fn2, or fn2 does not exist """
    # datetime.today()
    fn1_mod_time = file_mtime(fn1)  # This is a datetime.datetime object!
    fn2_mod_time = file_mtime(fn2)  # This is a datetime.datetime object!
    return fn1_mod_time > fn2_mod_time

def file_size(filename):
    return os.path.getsize(filename)
    # return os.stat(filename)[6]

def log(severity, fmt, *args):
    print(severity, fmt % args)

class MegaHash:
    """Bulk joaat hasher with binary cache"""

    #    struct mega_hash_t:
    #        union:
    #            hash
    #            magic
    #        }
    #        union:
    #            offset
    #            count
    #        }
    #    }

    def __init__(self, filename):
        if not os.path.isabs(filename):
            if '__file__' in globals():
                home = os.path.dirname(__file__)
                filename = os.path.join(home, filename)
        self.m_filename = filename
        self.m_hashIndex = dict()
        self.m_lastIndexCheck = 0
        self.m_filename_txt = replace_extension(filename, "txt")
        self.m_filename_dat = replace_extension(filename, "dat")
        if is_file_newer(self.m_filename_txt, self.m_filename_dat): # or file_size(self.m_filename_txt) > file_size(self.m_filename_dat):
            self.MakeIndex()
        self.ReadIndex()

    def ReadString(self, filename, offset):
        with open(filename, 'rb') as fr:
            fr.seek(offset)
            buf = bytearray(fr.read(256))
            s = ''
            null_term = False
            invalid_char = None
            for i in range(128):
                c = buf[i]
                if c == 0:
                    null_term = True
                    break
                if c == 10 or c == 13:
                    null_term = True
                    break
                s += "%c" % c
            if null_term:
                return s
            if invalid_char:
                raise ValueError("Invalid char '%c'" % c)
            raise ValueError("String was not null terminated")

            return s

    def Contains(self, hash):
        return self.m_hashIndex.get(hash, None) is not None

    def AddHashToEnum(self, hash, s):
        try:
            id = idc.get_enum("megahash")
            if id == BADADDR:
                id = idc.add_enum(-1, "megahash", idaapi.hex_flag())
            idc.add_enum_member(id, s, hash, -1)
        except:
            pass

    # Reading
    def Lookup(self, hash):
        hash = hash & 0xffffffff
        if hash:
            if self.Contains(hash):
                offset = self.m_hashIndex.get(hash)
                s = self.ReadString(self.m_filename_dat, offset)
                if joaat(s) == hash:
                    self.AddHashToEnum(hash, s)
                    return s
                raise ValueError("dehashed value '{}' did not pass forward lookup test".format(s))

        # log('DEBUG', "m_hashIndex doesn't contain {:x}".format(hash))
        return "0x{:08x}".format(hash)

    def ReadIndex(self, filename=None):
        if filename is None:
            filename = self.m_filename_dat
        time_start = time.time()
        filesize = file_size(filename)
        indexCount = 0
        
        # log('DEBUG', "filename: {}, filesize: {}".format(filename, filesize))
        with open(filename, "rb") as file:
            sizeof_header = 8
            sizeof_record = 8
            header_magic, header_count = struct.unpack('<II', file.read(sizeof_header))

            filetype = 0
            if header_magic == joaat("MEGAHASHES_INDEX"): filetype = 1
            elif header_magic == joaat("MEGAHASHES"): filetype = 3
            else: raise IndexError("megahash invalid magic signature: 0x%08x" % header_magic)

            if (filetype & 1):
                if (filesize - sizeof_header < header_count):
                    log('WARN', "%s: %s", "MegaHash::ReadIndex", "Hash index is truncated")

                # log('DEBUG', "reserving space for %s records", header_count)
                # log('DEBUG', "header_count: {}, filesize: {}".format(header_count, filesize))

                count = header_count
                for _record in struct.iter_unpack('<II', file.read(count * 8)):
                    record_hash, record_offset = _record
                    self.m_hashIndex[_record[0]] = _record[1]
                    indexCount += 1

                # log('DEBUG', "%s: read %s index records", "MegaHash::ReadIndex", indexCount)
                
                if filetype:
                    try:
                        result = self.Lookup(joaat("CVEHICLE"))
                        if result is None:
                            raise IndexError("Couldn't lookup CVEHICLE joaat")
                        # log('DEBUG', "%s: testing index joaat(\"CVEHICLE\"): joaat: 0x%x result: %s", "MegaHash::ReadIndex", joaat("CVEHICLE"), result)
                        if not (filetype & 2):
                            s = self.ReadString(self.m_filename_txt, result)
                            # log('DEBUG', "%s: looking up value: %s", "MegaHash::ReadIndex", s)

                    except IndexError as e:
                        log('ERROR', "%s: error checking joaat(\"CVEHICLE\"): %s", "MegaHash::ReadIndex", e)

        time_taken = time.time() - time_start
        log('INFO', "MegaHash::ReadIndex time_taken: {:0.2} seconds to read {} lines".format(time_taken, indexCount))

    def MakeIndex(self):
        filename_txt = self.m_filename_txt
        filename_dat = self.m_filename_dat
        time_start = time.time()

        self.m_hashIndex.clear()
        count = 0
        for line, position in file_iter_line_pos(filename_txt):
            self.m_hashIndex[joaat(line.strip())] = position
            count += 1

        header_count = len(self.m_hashIndex)

        sizeof_header = 8
        sizeof_record = 8
        
        header_pos = sizeof_header + sizeof_record * header_count

        # log('DEBUG', "header_count: {}, header_pos: {}".format(header_count, header_pos))

        header_magic = joaat("MEGAHASHES")

        with open(filename_dat, "wb") as fw:
            fw.write(struct.pack('<II', header_magic, header_count))
            for hash in sorted(self.m_hashIndex):
                fw.write(struct.pack('<II', hash, self.m_hashIndex[hash] + header_pos))

            with open(filename_txt, "rb") as fr:
                fw.write(fr.read(file_size(filename_txt)))

        time_taken = time.time() - time_start
        log('INFO', "MegaHash::MakeIndex time_taken: {:0.2} minutes to index {} lines".format(time_taken/60, count))

def load_dehasher(filename = 'megahashes.txt'):
    return MegaHash(filename)

mega = load_dehasher()


