# Static recovery of an NCPacker x64 PE

This case study reconstructs a Windows PE from one NCPacker build. The [rebuild script](rebuild_original.py) reads the packed file as data. It does not execute the file, patch the loader, or change its timing checks. This repository contains no client executables or DLLs.

The starting point was [k0mkc’s NCPacker write-up](https://k0mkc.hatenablog.com/entry/2026/09/17/233205). The descriptor and the repeating XOR key fit that description. Two details needed a different interpretation in this build: the PE metadata is itself compressed, and the stored block seed is not the final block key.

## Reproduce the rebuild

Use Python 3.10 or later. Supply a local copy of the exact input build. The script checks its SHA-256 before it starts decoding.

```bash
python -m pip install -r requirements.txt
```

```bash
python -I rebuild_original.py /path/to/BNSR_packed.exe bnsrunpacked.exe
```

The output path must not exist. The script opens it only after validation passes. The rebuilt file still needs the client’s runtime DLLs and assets.

| File | SHA-256 |
| --- | --- |
| Input | `b9dae255c8ed72ccb8866560dabd3af143189cc358e051c4eabf955cd55ef188` |
| Rebuilt PE | `a6aabad59702ad250279886531a08ea9905906d633119462c3cfb56c9dbb0098` |

## 1. Identify the format without assuming the variant

The packed x64 image has seven sections, `.ncg0` through `.ncg6`. Its entry RVA is `0xd5a89`. Both the entry and the TLS callback at VA `0x140042427` point into `.ncg0`. The exception directory points into `.ncg4`, not a section named `.pdata`.

An earlier Unicorn run reached the loader’s timing check. The check compared 88,167 ms to a 3,000 ms limit and the process terminated. The entry RVA and the main code pages still belonged to the packed image. This was not a successful unpack. The static route did not need to pass that check.

## 2. Locate the main-image descriptor

The descriptor is a packed 33-byte record. Its fields are little-endian. For the main image, the last 20 bytes decode to zero. Their on-disk bytes therefore show five copies of one four-byte word. This pattern identifies candidates, not confirmed records.

| Record offset | Field | Decoded value in this build |
| --- | --- | --- |
| `0x00` | Kind, `u8` | `0` |
| `0x01` | Blob offset, `u32` | `0xd5d77` |
| `0x05` | Blob size, `u32` | `0x3c849a7` |
| `0x09` | Unknown, `u32` | `0` |
| `0x0d` | Name, 20 bytes | All zero |

The matching record starts at file offset `0xd5c18`. The name starts one byte into the four-byte XOR cycle. Rotate the observed name word right by one byte to get the record key. Decode the entire record with that key.

The descriptor offset is relative to the raw start of `.ncg0`, not to the start of the file. The section starts at file offset `0x600`. Thus the blob starts at file offset `0xd6377`. A separate `bbt` descriptor uses the same offset base. Its decoded block boundaries also match the earlier emulator trace. The rebuild uses only the main-image descriptor.

## 3. Recover the blob key and check the block chain

The x64 byte-store pattern `C6 44 24 <disp8> <imm8>` stores an immediate byte at a stack displacement. A run of 48 stores with consecutive displacements starts at file offset `0xaea2d`. Read the immediate bytes in displacement order. The bytes give the repeating blob key. A pattern hit is not enough: the key must produce a valid chain of bounded blocks.

The first scan assumed that the blob started with plaintext PE metadata after the outer XOR. No candidate passed that test. The trace of the separate `bbt` stream showed the missing detail: the first block expands to `0x9e` bytes. At the main blob’s start, the key decodes a block with compressed size `0x79` and expanded size `0x9e`. The next ten blocks each decode to one section record. A four-byte `ff ff ff ff` trailer ends the blob.

Apply the 48-byte XOR continuously from blob offset zero. Do not reset its phase at block boundaries. Read a 12-byte block header as three `u32` values:

| Header offset | Field |
| --- | --- |
| `0x00` | Compressed size |
| `0x04` | Expanded size |
| `0x08` | Stored seed |

For the payload only, compute `block_key = stored_seed ^ compressed_size ^ expanded_size`. Convert that value to four little-endian bytes. Apply the four-byte XOR from payload offset zero. On two blocks from the `bbt` trace, this formula reproduced the key bytes that the loader used. The standalone script combines both XOR passes on each payload.

## 4. Expand the bitstream

The decoder at VA `0x14001fa36` uses a zero-filled history window of `0x2000` bytes. The reader at VA `0x14001f773` consumes bits least-significant bit first. The token format matches the relevant parts of [Rich Geldreich’s LZ77 example](https://gist.github.com/richgel999/c0be2894b918d0244129).

| Tag | Remaining fields | Meaning |
| --- | --- | --- |
| `0` | 8 bits | Copy one literal byte. |
| `1` | 4-bit length code, then 13-bit distance | Copy `length_code + 3` bytes. Use a forward copy so source and destination can overlap. |
| `1` | Length code `15` | End the stream. Do not read a distance. |

The guest masks history indices with `0x1fff`. A distance of zero reads the current ring slot, which is equivalent to reading `0x2000` bytes back. Before the window fills, unread slots contain zero. The Python decoder checks the output bounds, the exact expanded size, the end marker, and zero padding.

## 5. Rebuild the PE

The first expanded block contains the original section count, COFF and DLL flags, entry RVA, image size, header size, section alignment, image base, and 16 directory pairs. Each following record starts with three little-endian `u32` fields: destination RVA, virtual size, and section characteristics. Its remaining bytes are the file-backed section data. Use the payload length for the raw size, not the virtual size. The difference matters for `.data`.

Use the packed headers as a template. Replace the fields from the recovered metadata and build a new section table. Write the original raw section data at offsets aligned to `0x200`. Keep the original RVAs, including those for imports, delay imports, resources, and relocations. Do not copy the packed overlay or its certificate. The four `.sectNN` names are placeholders because the records do not contain the original names.

| Section | RVA | Virtual size | Raw size |
| --- | --- | --- | --- |
| `.text` | `0x1000` | `0x554f8db` | `0x554fa00` |
| `.rdata` | `0x5551000` | `0x1dcee3e` | `0x1dcf000` |
| `.data` | `0x7320000` | `0xa26e94` | `0x38ac00` |
| `.pdata` | `0x7d47000` | `0x368e38` | `0x369000` |
| `.sect05` | `0x80b0000` | `0x5d` | `0x200` |
| `.sect06` | `0x80b1000` | `0x1130` | `0x1200` |
| `.sect07` | `0x80b3000` | `0x27210` | `0x27400` |
| `.sect08` | `0x80db000` | `0x20` | `0x200` |
| `.rsrc` | `0x80dc000` | `0x55050` | `0x55200` |
| `.reloc` | `0x8132000` | `0x1fcc40` | `0x1fce00` |

## 6. Verify what the output proves

- All 11 blocks expanded to their declared sizes. Each rebuilt section matched the hash of its decoded payload.
- The rebuilt exception data matched the clear exception table in the packed input byte for byte. This check used a copy independent of the compressed blocks.
- `pefile` reopened the saved x64 PE with no warnings. It found 1,354 normal imports in 51 DLLs and 317 delay imports in 22 DLLs.
- The recovered entry RVA is `0x535dd90`, in `.text`. Capstone decoded this startup sequence at image base `0x140000000`:

```asm
14535dd90  sub rsp, 0x28
14535dd94  call 0x1453624ec
14535dd99  add rsp, 0x28
14535dd9d  jmp 0x14535dc1c
```

A smoke test under Wine 10.0 reached import resolution. It stopped with `0xc0000135` (`STATUS_DLL_NOT_FOUND`) because the isolated test did not include `python37.dll`, `GCloudVoice.dll`, `libiconv2017_cl64.dll`, or `game_presence-64-vc_v80-MD.dll`. The game entry point did not run. The result confirms a reconstructed PE file, not a successful game launch or a byte-identical copy of the original signed file.
