import argparse
import hashlib
import re
import struct
from pathlib import Path

import pefile


INPUT_HASH = 'b9dae255c8ed72ccb8866560dabd3af143189cc358e051c4eabf955cd55ef188'
DESCRIPTOR = 0xD5C18
KEY_STORES = 0xAEA2D
SECTION_NAMES = (
    b'.text', b'.rdata', b'.data', b'.pdata', b'.sect05',
    b'.sect06', b'.sect07', b'.sect08', b'.rsrc', b'.reloc',
)
XOR_TABLES = tuple(bytes(i ^ key for i in range(256)) for key in range(256))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unpack_lz(data, expected):
    out = bytearray()
    offset = bits = count = 0
    while offset < len(data) or count:
        if not count:
            bits = data[offset]
            offset += 1
            count = 8
        tag = bits & 1
        bits >>= 1
        count -= 1
        width = 4 if tag else 8
        if count < width:
            require(offset < len(data), 'Truncated token')
            bits |= data[offset] << count
            offset += 1
            count += 8
        value = bits & ((1 << width) - 1)
        bits >>= width
        count -= width
        if not tag:
            require(len(out) < expected, 'Literal exceeds output size')
            out.append(value)
            continue
        if value == 15:
            require(len(out) == expected, 'Wrong expanded size')
            require(not bits and not any(data[offset:]), 'Nonzero end padding')
            return out
        while count < 13:
            require(offset < len(data), 'Truncated match')
            bits |= data[offset] << count
            offset += 1
            count += 8
        distance = (bits & 8191) or 8192
        bits >>= 13
        count -= 13
        length = value + 3
        require(len(out) + length <= expected, 'Match exceeds output size')
        start = len(out) - distance
        if start >= 0 and distance >= length:
            out.extend(out[start:start + length])
        else:
            for i in range(start, start + length):
                out.append(out[i] if i >= 0 else 0)
    raise ValueError('Missing end marker')


def decode_blocks(data, section):
    raw = section.PointerToRawData
    descriptor = data[DESCRIPTOR:DESCRIPTOR + 33]
    key4 = descriptor[16:17] + descriptor[13:16]
    decoded = bytes(value ^ key4[i % 4] for i, value in enumerate(descriptor))
    kind, offset, size, unknown = struct.unpack_from('<BIII', decoded)
    require(kind == 0 and unknown == 0 and not any(decoded[13:]), 'Wrong descriptor')
    require(offset + size <= section.SizeOfRawData, 'Blob exceeds first section')
    start = raw + offset
    end = start + size

    stores = re.compile(rb'\xc6\x44\x24(.)(.)', re.S)
    matches = list(stores.finditer(data, KEY_STORES, KEY_STORES + 0x4000))[:48]
    displacements = [int.from_bytes(m[1], 'little', signed=True) for m in matches]
    require(len(matches) == 48 and all(b == a + 1 for a, b in zip(displacements, displacements[1:])),
            'Wrong key store sequence')
    key = bytes(m[2][0] for m in matches)

    pos = start
    while pos < end - 4:
        require(pos + 12 <= end - 4, 'Truncated block header')
        phase = (pos - start) % 48
        header = bytes(value ^ key[(phase + i) % 48] for i, value in enumerate(data[pos:pos + 12]))
        compressed, expanded, seed = struct.unpack('<III', header)
        pos += 12
        require(compressed and expanded and pos + compressed <= end - 4, 'Invalid block size')
        require(expanded <= 0x10000000, 'Expanded block exceeds limit')
        seed = (seed ^ compressed ^ expanded).to_bytes(4, 'little')
        phase = (pos - start) % 48
        source = data[pos:pos + compressed]
        clear = bytearray(compressed)
        for i in range(48):
            mask = key[(phase + i) % 48] ^ seed[i % 4]
            clear[i::48] = source[i::48].translate(XOR_TABLES[mask])
        yield unpack_lz(clear, expanded)
        pos += compressed
    trailer = bytes(value ^ key[(pos - start + i) % 48] for i, value in enumerate(data[pos:end]))
    require(trailer == b'\xff' * 4, 'Missing blob trailer')


def rebuild(data):
    require(hashlib.sha256(data).hexdigest() == INPUT_HASH, 'Unexpected input build')
    packed = pefile.PE(data=data, fast_load=True)
    blocks = decode_blocks(data, packed.sections[0])
    metadata = next(blocks)
    require(len(metadata) == 0x9E, 'Wrong PE metadata size')
    count, flags, dll_flags, entry, size, headers, alignment, base = struct.unpack_from('<HHHIIIIQ', metadata)
    require(count == len(SECTION_NAMES), 'Wrong section count')
    dirs = list(struct.iter_unpack('<II', metadata[30:]))
    require(not any(dirs[4]), 'Unexpected certificate table')
    opt = packed.OPTIONAL_HEADER.get_file_offset()
    table = opt + packed.FILE_HEADER.SizeOfOptionalHeader
    file_align = packed.OPTIONAL_HEADER.FileAlignment
    require(table + count * 40 <= headers and headers % file_align == 0, 'Section table does not fit')

    image = bytearray(data[:headers])
    image[table:] = bytes(headers - table)
    struct.pack_into('<H', image, packed.FILE_HEADER.get_file_offset() + 2, count)
    struct.pack_into('<H', image, packed.FILE_HEADER.get_file_offset() + 18, flags)
    struct.pack_into('<I', image, opt + 16, entry)
    struct.pack_into('<QI', image, opt + 24, base, alignment)
    struct.pack_into('<III', image, opt + 56, size, headers, 0)
    struct.pack_into('<H', image, opt + 70, dll_flags)
    image[opt + 112:opt + 240] = metadata[30:]

    code = initialized = uninitialized = first_code = 0
    prev_end = headers
    sections = []
    for index, (name, record) in enumerate(zip(SECTION_NAMES, blocks, strict=True)):
        rva, virtual, characteristics = struct.unpack_from('<III', record)
        raw_size = len(record) - 12
        require(rva % alignment == 0 and raw_size % file_align == 0, 'Misaligned section')
        require(prev_end <= rva and rva + max(raw_size, virtual) <= size, 'Invalid section range')
        prev_end = rva + max(raw_size, virtual)
        raw_offset = len(image) if raw_size else 0
        struct.pack_into('<8sIIIIIIHHI', image, table + 40 * index, name, virtual, rva,
                         raw_size, raw_offset, 0, 0, 0, 0, characteristics)
        image.extend(memoryview(record)[12:])
        sections.append((rva, virtual, raw_size, hashlib.sha256(memoryview(record)[12:]).hexdigest()))
        if characteristics & 0x20:
            first_code = first_code or rva
            code += raw_size
        if characteristics & 0x40:
            initialized += raw_size
        if characteristics & 0x80:
            uninitialized += virtual
    struct.pack_into('<III', image, opt + 4, code, initialized, uninitialized)
    struct.pack_into('<I', image, opt + 20, first_code)

    result = pefile.PE(data=bytes(image), fast_load=True)
    result.parse_data_directories(directories=[1, 9, 13])
    require(len(result.sections) == count, 'Rebuilt section table is incomplete')
    for section, (rva, virtual, raw_size, digest) in zip(result.sections, sections, strict=True):
        require((section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData) == (rva, virtual, raw_size),
                'Section header changed during rebuild')
        require(hashlib.sha256(section.get_data()).hexdigest() == digest, 'Section data changed during rebuild')
    start = result.get_section_by_rva(entry)
    require(start is not None and start.Characteristics & 0x20000000 and len(result.get_data(entry, 32)) == 32,
            'Entry is not in file-backed executable code')
    imports = getattr(result, 'DIRECTORY_ENTRY_IMPORT', ())
    require(imports and all(dll.imports for dll in imports), 'Invalid import table')
    relocations = result.get_data(*dirs[5])
    require(len(relocations) == dirs[5][1] and len(relocations) >= 8, 'Invalid relocation directory')
    pos = 0
    while pos < len(relocations):
        require(pos + 8 <= len(relocations), 'Truncated relocation header')
        page, length = struct.unpack_from('<II', relocations, pos)
        require(page % 0x1000 == 0 and page < size, 'Invalid relocation page')
        require(8 <= length <= len(relocations) - pos and length % 4 == 0, 'Invalid relocation block')
        pos += length
    packed_pdata = packed.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    require(packed.get_data(packed_pdata.VirtualAddress, packed_pdata.Size) == result.get_data(*dirs[3]),
            'Exception data does not match the packed copy')
    return image


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    image = rebuild(args.input.read_bytes())
    with args.output.open('xb') as output:
        output.write(image)
    print(f'SHA-256 {hashlib.sha256(image).hexdigest()}')


if __name__ == '__main__':
    main()
