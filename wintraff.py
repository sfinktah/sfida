import idaapi
import idautils
import idc
import ida_enum
import pefile   # pip install pefile
import sys
import os
import ctypes
from ctypes import wintypes

# remove these two lines if you dont have my full library
from exectools import make_refresh
refresh_wintraff = make_refresh(os.path.abspath(__file__))

def patch_pe_file(file_path, virtual_offset, patch_data):
    """
    Patches a section in a Win32 PE file with the provided bytearray.

    :param file_path: Path to the PE file (e.g., 'C:\\path\\to\\file.exe')
    :param virtual_offset: Virtual address where the patch should be applied (including base address)
    :param patch_data: Bytearray or bytes object containing the patch data
    """
    # Open the PE file
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return
    except pefile.PEFormatError as e:
        print(f"Error: PEFormatError: {e.value}")
        return

    # Get the base address (ImageBase) from the PE file
    base_address = pe.OPTIONAL_HEADER.ImageBase
    print(f"Base Address (ImageBase): 0x{base_address:08X}")

    # Calculate the Relative Virtual Address (RVA)
    rva = virtual_offset - base_address
    print(f"Relative Virtual Address (RVA): 0x{rva:08X}")

    # Find the section that contains the RVA
    section = None
    for sect in pe.sections:
        start = sect.VirtualAddress
        end = start + max(sect.Misc_VirtualSize, sect.SizeOfRawData)
        if start <= rva < end:
            section = sect
            break

    if not section:
        print(f"Error: No section contains the virtual address 0x{virtual_offset:08X}")
        return

    print(f"Target Section: {section.Name.decode().strip()}")

    # Calculate the file offset
    file_offset = section.PointerToRawData + (rva - section.VirtualAddress)

    # Check if the patch fits within the section
    max_offset = section.PointerToRawData + section.SizeOfRawData
    end_offset = file_offset + len(patch_data)
    if end_offset > max_offset:
        print("Error: Patch data exceeds the bounds of the section by {:x} bytes.".format(end_offset - max_offset))
        return

    # Apply the patch
    try:
        with open(file_path, 'r+b') as f:
            f.seek(file_offset)
            f.write(patch_data)
        print(f"Successfully patched {len(patch_data)} bytes at virtual address 0x{virtual_offset:08X}")
    except IOError as e:
        print(f"Error: Could not write to file: {e}")
        return

def read_pe_bytes(file_path, virtual_offset, length):
    """
    Reads a number of bytes from a Win32 PE file at the given virtual offset.

    :param file_path: Path to the PE file (e.g., 'C:\\path\\to\\file.exe')
    :param virtual_offset: Virtual address from which to read the data (including base address)
    :param length: Number of bytes to read
    :return: Bytes object containing the data read, or None if an error occurs
    """
    # Open the PE file
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return None
    except pefile.PEFormatError as e:
        print(f"Error: PEFormatError: {e.value}")
        return None

    # Get the base address (ImageBase) from the PE file
    base_address = pe.OPTIONAL_HEADER.ImageBase
    # print(f"Base Address (ImageBase): 0x{base_address:08X}")

    # Calculate the Relative Virtual Address (RVA)
    rva = virtual_offset - base_address
    # print(f"Relative Virtual Address (RVA): 0x{rva:08X}")

    # Find the section that contains the RVA
    section = None
    for sect in pe.sections:
        start = sect.VirtualAddress
        end = start + max(sect.Misc_VirtualSize, sect.SizeOfRawData)
        if start <= rva < end:
            section = sect
            break

    if not section:
        print(f"Error: No section contains the virtual address 0x{virtual_offset:08X}")
        return None

    # Calculate the file offset
    file_offset = section.PointerToRawData + (rva - section.VirtualAddress)

    # Check if the read fits within the section
    max_offset = section.PointerToRawData + section.SizeOfRawData
    end_offset = file_offset + length
    if end_offset > max_offset:
        print("Error: Read exceeds the bounds of the section.")
        return None

    # Read the data
    try:
        with open(file_path, 'rb') as f:
            f.seek(file_offset)
            data = f.read(length)
        print(f"Successfully read {len(data)} bytes from virtual address 0x{virtual_offset:08X}")
        return data
    except IOError as e:
        print(f"Error: Could not read from file: {e}")
        return None

#  # Example usage
#  if __name__ == "__main__":
    #  # Simple command-line interface
    #  import argparse
#  
    #  parser = argparse.ArgumentParser(description='Patch or read bytes from a PE file.')
    #  subparsers = parser.add_subparsers(dest='command', help='Available commands')
#  
    #  # Patch command
    #  parser_patch = subparsers.add_parser('patch', help='Patch bytes in the PE file')
    #  parser_patch.add_argument('file_path', help='Path to the PE file')
    #  parser_patch.add_argument('virtual_offset', help='Virtual address where the patch should be applied (hexadecimal, including base address)')
    #  parser_patch.add_argument('patch_data_hex', help='Patch data as a hex string (e.g., "90 90 90 90")')
#  
    #  # Read command
    #  parser_read = subparsers.add_parser('read', help='Read bytes from the PE file')
    #  parser_read.add_argument('file_path', help='Path to the PE file')
    #  parser_read.add_argument('virtual_offset', help='Virtual address from which to read data (hexadecimal, including base address)')
    #  parser_read.add_argument('length', type=int, help='Number of bytes to read')
#  
    #  args = parser.parse_args()
#  
    #  if args.command == 'patch':
        #  file_path = args.file_path
        #  try:
            #  virtual_offset = int(args.virtual_offset, 0)
        #  except ValueError:
            #  print("Error: Invalid virtual offset.")
            #  sys.exit(1)
#  
        #  # Convert patch data from hex string to bytes
        #  try:
            #  patch_data = bytes.fromhex(args.patch_data_hex)
        #  except ValueError:
            #  print("Error: Invalid hex string for patch data.")
            #  sys.exit(1)
#  
        #  # Call the patch function
        #  patch_pe_file(file_path, virtual_offset, patch_data)
#  
    #  elif args.command == 'read':
        #  file_path = args.file_path
        #  try:
            #  virtual_offset = int(args.virtual_offset, 0)
        #  except ValueError:
            #  print("Error: Invalid virtual offset.")
            #  sys.exit(1)
#  
        #  length = args.length
#  
        #  # Call the read function
        #  data = read_pe_bytes(file_path, virtual_offset, length)
        #  if data is not None:
            #  # Print the data in hexadecimal format
            #  hex_data = ' '.join(f'{byte:02X}' 


def get_system32_directory():
    """
    Retrieves the path to the Windows SYSTEM32 directory.
    
    :return: Absolute path to the SYSTEM32 directory.
    """
    buffer = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    if ctypes.windll.kernel32.GetSystemDirectoryW(buffer, wintypes.MAX_PATH):
        return buffer.value
    else:
        raise ctypes.WinError()

def add_default_extension(file_path, default_extension='.dll'):
    """
    Determines if the provided file path contains a file extension.
    If not, adds the default extension.

    :param file_path: The file path to check.
    :param default_extension: The default extension to add if none is present.
    :return: The file path with an extension.
    """
    # Split the file path into root and extension
    root, ext = os.path.splitext(file_path)
    if not ext:
        # No extension found; add the default extension
        return file_path + default_extension
    else:
        # Extension exists; return the original path
        return file_path


def get_absolute_dll_path(dll_path):
    """
    Returns an absolute path to a DLL.
    If the provided path is relative, it uses the Windows SYSTEM32 directory.
    
    :param dll_path: Relative or absolute path to the DLL.
    :return: Absolute path to the DLL.
    """
    if os.path.isabs(dll_path):
        return dll_path
    else:
        system32_dir = get_system32_directory()
        return os.path.join(system32_dir, dll_path)

def compute_hash(s):
    hash_value = 5
    for char in s:
        c = ord(char)
        hash_value = (c + ((hash_value << 19) & 0xFFFFFFFF) + (hash_value >> 13)) & 0xFFFFFFFF
    return hash_value

def find_export_by_hash(dll_path, target_hash):
    """
    Finds the names of exported functions in the specified DLL that match the given hash.

    :param dll_path: Path to the DLL file.
    :param target_hash: The hash value to match (computed using compute_hash).
    :return: List of matching exported function names.
    """
    import pefile

    try:
        pe = pefile.PE(add_default_extension(get_absolute_dll_path(dll_path)))
    except Exception as e:
        print(f"Error loading PE file: {e}")
        return []

    matching_functions = []

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("The DLL has no export table.")
        return matching_functions

    # Check if the enum 'HASHED_EXPORTS' exists; if not, create it
    enum_name = "HASHED_EXPORTS"
    enum_id = idaapi.get_enum(enum_name)
    if enum_id == idaapi.BADADDR:
        enum_id = idaapi.add_enum(idaapi.BADNODE, enum_name, idaapi.hex_flag())
        if enum_id == idaapi.BADADDR:
            print("Failed to create enum 'HASHED_EXPORTS'.")
            return matching_functions
        else:
            print(f"Created enum '{enum_name}'.")

    # Set enum's BFF (bitfield flag) to false to make it a regular enum
    idaapi.set_enum_bf(enum_id, False)

    # Keep track of added hashes to avoid duplicates
    existing_enum_members = {}
    # Enumerate existing members to prevent duplicates
    for i in range(idaapi.get_enum_size(enum_id)):
        member_id = idaapi.get_enum_member(enum_id, i, 0, idaapi.DEFMASK)
        member_name = idaapi.get_member_name(member_id)
        member_value = idaapi.get_enum_member_value(member_id)
        existing_enum_members[member_value] = member_name

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        func_name = exp.name.decode('utf-8', errors='ignore')
        hash_value = compute_hash(func_name)
        if hash_value == target_hash:
            matching_functions.append(func_name)

            # Check if the hash value already exists in the enum
            if hash_value in existing_enum_members:
                print(f"Enum member for hash {hash_value:#010x} already exists: {existing_enum_members[hash_value]}")
                continue

            # Generate a valid enum member name
            # Replace invalid characters with underscores
            enum_member_name = func_name
            enum_member_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in enum_member_name)

            # Ensure the enum member name is unique
            if idaapi.get_enum_member_by_name(enum_member_name) != idaapi.BADADDR:
                # Append the hash value to the name to make it unique
                enum_member_name = f"{enum_member_name}_{hash_value:08X}"

            # Add the enum member
            result = ida_enum.add_enum_member(ida_enum.get_enum('HASHED_EXPORTS'), enum_member_name, hash_value, ida_enum.DEFMASK)
            if result != 0:
                print(f"Failed to add enum member '{enum_member_name}' with value {hash_value:#010x} to {enum_id}. Error code: {result}")
            else:
                print(f"Added enum member '{enum_member_name}' with value {hash_value:#010x} to enum '{enum_name}'.")

    if matching_functions:
        dll_basename = os.path.basename(dll_path)
        print(f"\nMatching functions in {dll_basename}:")
        for func in matching_functions:
            print(f"- {func}")
    else:
        print(f"No matching functions found in {dll_path} for hash {target_hash:#010x}.")

    return matching_functions

# Example usage
#  if __name__ == "__main__":
    #  # Replace 'C:\\Windows\\System32\\kernel32.dll' with the path to your DLL
    #  dll_path = idc.AskFile(0, "*.dll", "Select the DLL file")
    #  if not dll_path:
        #  print("No DLL file selected.")
    #  else:
        #  # Replace '0x12345678' with your target hash value
        #  hash_input = idc.AskStr("0x", "Enter the target hash (e.g., 0x1A2B3C4D):")
        #  if not hash_input:
            #  print("No hash value entered.")
        #  else:
            #  try:
                #  target_hash = int(hash_input, 0)
                #  find_export_by_hash(dll_path, target_hash)
            #  except ValueError:
                #  print("Invalid hash value entered.")

