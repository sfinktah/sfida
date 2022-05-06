import re

def get_stripped_lines(file_name):
    result = list()

    with open(file_name, 'r') as fr:
        for line in fr:
            s = line.strip()
            if len(s) == 0:
                continue
            result.append(s)
            if False: # this is fine for DeHashing, but it screws up other functionality
                result.append(s + "POOL")
                result.append(s + "LIST")
                if s[0] == 'C':
                    result.append(s[1:len(s)])

    #  return list(map(lambda x: x.strip(), open(file_name, 'r')))
    return result




def line_to_hex_tuple(line):
    values = tuple(map(lambda x: int(x, 16), line.split(' ')))

    if len(values) == 1:
        return values[0]

    if len(values) == 2:
        return values

    return (values[0], values[1:])


def load_address_array(file_name, section_indices):
    sections = [[ ]]

    for line in get_stripped_lines(file_name):
        if line:
            sections[-1].append(line_to_hex_tuple(line))
        else:
            sections.append([ ])

    if section_indices is not None:
        sections = [ v for i, v in sorted(enumerate(filter(None, sections)), key = lambda x: section_indices[x[0]]) ]

    return sections


def load_native_diff(file_name):
    natives = { }

    for line in get_stripped_lines(file_name):
        if line:
            match = re.match('([+-]+)(0x[0-9A-F]+)', line)

            natives[int(match.group(2), 16)] = match.group(1)

    return natives


def load_hex_tuple_dict(file_name):
    return dict(map(line_to_hex_tuple, get_stripped_lines(file_name)))


def load_hex_tuple_list(file_name):
    return list(filter(None, map(line_to_hex_tuple, get_stripped_lines(file_name))))


def unsigned_to_signed(value, bit_count):
    return (value - (1 << bit_count)) if (value & (1 << bit_count - 1)) else value




class jenkins:
    def __init__(self, seed):
        self.hash = seed


    def update_bytes(self, data):
        result = self.hash

        for value in data:
            result = (result + value) * 1025 & 0xFFFFFFFF
            result = (result >> 6 ^ result)

        self.hash = result


    def update_string(self, string):
        self.update_bytes(string.encode('utf-8'))


    def update_lower(self, string):
        self.update_string(string.lower())


    def digest(self):
        result = self.hash

        result = (result * 9) & 0xFFFFFFFF
        return (result >> 11 ^ result) * 32769 & 0xFFFFFFFF


def joaat(string, seed = 0):
    hasher = jenkins(seed)
    hasher.update_lower(string)
    return hasher.digest()


def joaat_no_lower(string, seed = 0):
    hasher = jenkins(seed)
    hasher.update_string(string)
    return hasher.digest()

def joaat_memory(ea, length, hash = 0x4C11DB7):
    string = idc.get_bytes(ea, length)
    for b in string:
        hash = (hash + value) * 1025 & 0xFFFFFFFF
        hash = (hash >> 6 ^ hash)

    hash = (hash * 9) & 0xFFFFFFFF
    return (hash >> 11 ^ hash) * 32769 & 0xFFFFFFFF

section_indices_323_372 = [ 0,1,2,4,15,20,26,28,30,3,39,25,33,36,37,27,41,13,42,14,6,5,24,38,40,18,11,16,29,22,10,17,34,8,7,35,12,9,21,31,32,23,19 ]
section_indices_current = [ 0,23,33,25,38,32,41,1,28,13,5,16,26,14,19,30,29,10,3,42,20,37,35,2,22,27,17,7,9,6,36,34,31,12,4,39,18,11,40,21,24,8,15 ]

section_names = [
    'SYSTEM',
    'APP',
    'AUDIO',
    'BRAIN',
    'CAM',
    'CLOCK',
    'CUTSCENE',
    'DATAFILE',
    'DECORATOR',
    'DLC',
    'ENTITY',
    'EVENT',
    'FILES',
    'FIRE',
    'GRAPHICS',
    'HUD',
    'INTERIOR',
    'ITEMSET',
    'LOADING',
    'LOCALE',
    'MISC',
    'NETCASH',
    'MOBILE',
    'NETSHOP',
    'NETWORK',
    'OBJECT',
    'PAD',
    'PATHFIND',
    'PED',
    'PHYSICS',
    'PLAYER',
    'RECORDING',
    'RENDERING',
    'SCRIPT',
    'SHAPETEST',
    'SOCIALCLUB',
    'STATS',
    'STREAMING',
    'TASK',
    'VEHICLE',
    'WATER',
    'WEAPON',
    'ZONE',
]

def load_names_file(file):
    return dict(map(lambda x: (joaat(x), x), get_stripped_lines(file)))

def load_custom_names_file(file):

    def make_name_tuple(line):
        parts = line.split(' ')

        return (int(parts[0], 16) & 0xFFFFFFFF, '_' + parts[1])

    return dict(map(make_name_tuple, get_stripped_lines(file)))

def load_dehasher():
    strings = load_names_file('Misc/strings.txt')
    strings.update(load_custom_names_file('Misc/custom_strings.txt'))

    return strings
