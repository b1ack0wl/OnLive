#!/usr/bin/env python3
"""
OnLive Microconsole NAND analyzer.

Stages:
  strip-oob   : Drop 64-byte OOB after every 2048-byte page -> onlive.bin + onlive.oob.bin
  scan        : Hunt for filesystem / executable signatures in the clean image
  map         : Map data/zero/0xFF/ASCII regions per 64 KB block
  parts       : Decode the 12-byte-record header at offset 0 as a partition table
  dump-env    : Pretty-print U-Boot environment variables
  carve       : Carve out everything we can identify into ./out/

Usage:
  py analyze.py <stage> [args]
"""
import os
import sys
import struct
import zlib
from pathlib import Path

ROOT     = Path(r'F:\development\steam\emulator_bot\OnLive\Microconsole')
RAW_DMP  = ROOT / 'onlive.dmp'
CLEAN    = ROOT / 'onlive.bin'
OOB      = ROOT / 'onlive.oob.bin'
OUTDIR   = ROOT / 'out'

PAGE_SIZE = 2048
OOB_SIZE  = 64
PAGE_TOTAL = PAGE_SIZE + OOB_SIZE  # 2112


def strip_oob(src=RAW_DMP, dst=CLEAN, oob=OOB):
    size = src.stat().st_size
    if size % PAGE_TOTAL != 0:
        raise SystemExit(f'size {size} not divisible by {PAGE_TOTAL}')
    pages = size // PAGE_TOTAL
    print(f'strip: {src.name} ({size} B, {pages} pages)')
    print(f'  -> {dst.name} ({pages*PAGE_SIZE} B data)')
    print(f'  -> {oob.name} ({pages*OOB_SIZE} B OOB)')
    with open(src,'rb') as fi, open(dst,'wb') as fo, open(oob,'wb') as fb:
        for i in range(pages):
            buf = fi.read(PAGE_TOTAL)
            fo.write(buf[:PAGE_SIZE])
            fb.write(buf[PAGE_SIZE:])
            if i and i % 16384 == 0:
                print(f'    {i}/{pages}')
    print('  done.')


# Magic table for signature scan.
# Entries: (label, magic_bytes, validator(buf_at_match) -> bool|None  optional)
SIGS = [
    ('ELF',          b'\x7fELF',                            None),
    ('SQFS-hsqs',    b'hsqs',                               None),
    ('SQFS-sqsh',    b'sqsh',                               None),
    ('GZIP',         b'\x1f\x8b\x08',                       None),
    ('UBI#',         b'UBI#',                               None),
    ('UBI!',         b'UBI!',                               None),
    ('UBIfsSB',      b'\x31\x18\x10\x06',                   None),
    ('JFFS2-LE',     b'\x85\x19\x01\xe0',                   None),
    ('JFFS2-BE',     b'\xe0\x01\x19\x85',                   None),
    ('uImage',       b'\x27\x05\x19\x56',                   None),
    ('FIT/DTB',      b'\xd0\x0d\xfe\xed',                   None),
    ('cramfs-LE',    b'\x45\x3d\xcd\x28',  lambda b: b[16:32].startswith(b'Compressed ROMFS')),
    ('cramfs-BE',    b'\x28\xcd\x3d\x45',  lambda b: b[16:32].startswith(b'Compressed ROMFS')),
    ('YAFFS2',       b'YAFF',                               None),
    ('LZMA',         b'\x5d\x00\x00\x80\x00',               None),
    ('LZ4-frame',    b'\x04\x22\x4d\x18',                   None),
    ('XZ',           b'\xfd7zXZ\x00',                       None),
    ('BZ2',          b'BZh91AY&SY',                         None),
    ('TAR-ustar',    b'ustar',                              None),
    ('ZIP',          b'PK\x03\x04',                         None),
    ('ROMFS',        b'-rom1fs-',                           None),
    ('Marvell-BHR',  b'\xb8\xff\xff\xff',                   None),  # branch instr
    ('U-Boot env',   b'bootcmd=',                           None),
    ('Uboot-stack',  b'baudrate=',                          None),
    ('CRAMFS-Galois',b'-Galois-',                           None),
    ('TPL-MBR',      b'\x55\xaa',                           None),  # noisy
    ('PE-MZ',        b'MZ\x90',                             None),
    ('initrd-cpio',  b'070701',                             None),
]


def scan(path=CLEAN, max_per_sig=20, skip_noisy=True):
    """Scan with mmap for signatures."""
    import mmap
    noisy = {'TPL-MBR'} if skip_noisy else set()
    print(f'scan: {path.name} ({path.stat().st_size} B)')
    with open(path,'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for label, magic, validator in SIGS:
                if label in noisy:
                    continue
                hits = []
                start = 0
                while True:
                    i = mm.find(magic, start)
                    if i < 0:
                        break
                    if validator is None or validator(mm[i:i+64]):
                        hits.append(i)
                    start = i + 1
                    if len(hits) >= 100000:
                        break
                if hits:
                    sample = ', '.join(f'0x{h:X}' for h in hits[:max_per_sig])
                    print(f'  {label:<14} count={len(hits):<6} first: {sample}')
        finally:
            mm.close()


def map_data(path=CLEAN, block=65536):
    """Print a block-classification map."""
    print(f'map: {path.name} ({path.stat().st_size} B), block={block} ({block//1024} KB)')
    print(f'  Legend: 0=all-zero  F=all-0xFF  .=mostly-zero  ~=mostly-0xFF  A=mostly-ASCII  #=binary')
    with open(path,'rb') as f:
        run_char = None
        run_start = 0
        pos = 0
        while True:
            buf = f.read(block)
            if not buf:
                break
            zeros = buf.count(b'\x00')
            ffs   = buf.count(b'\xff')
            ascii_ct = sum(1 for b in buf if 0x20 <= b < 0x7f)
            n = len(buf)
            if zeros == n:                  c = '0'
            elif ffs == n:                  c = 'F'
            elif zeros > n*0.95:            c = '.'
            elif ffs   > n*0.95:            c = '~'
            elif ascii_ct > n*0.6:          c = 'A'
            else:                           c = '#'
            if c != run_char:
                if run_char is not None:
                    print(f'  0x{run_start:08X} - 0x{pos-1:08X}  {run_char}  ({(pos-run_start)//block} blocks)')
                run_char = c
                run_start = pos
            pos += n
        print(f'  0x{run_start:08X} - 0x{pos-1:08X}  {run_char}  ({(pos-run_start)//block} blocks)')


def parse_parts(path=CLEAN):
    """Decode the 12-byte records at the head of the dump."""
    print(f'parts: {path.name}')
    with open(path,'rb') as f:
        data = f.read(0x200)
    # Each entry is 12 bytes: u32 magic, u16 ?, u16 ?, u8x4
    entries = []
    for off in range(0, 0x200, 12):
        if data[off:off+4] == b'\xf1\xa3\xad\xd2':
            magic, w1, w2, b0,b1,b2,b3 = struct.unpack('<IHHBBBB', data[off:off+12])
            entries.append((off, magic, w1, w2, b0, b1, b2, b3))
        elif data[off:off+12] == b'\x00'*12:
            break
    print(f'  found {len(entries)} entries')
    print(f'  off    magic       w1     w2     b0 b1 b2 b3')
    for e in entries:
        off,m,w1,w2,b0,b1,b2,b3 = e
        print(f'  0x{off:03X}  0x{m:08X}  0x{w1:04X} 0x{w2:04X}  {b0:02X} {b1:02X} {b2:02X} {b3:02X}')


def dump_env(path=CLEAN, env_off=0x3C00000, env_size=0x20000):
    """Pretty print U-Boot environment block."""
    print(f'env: {path.name} @ 0x{env_off:X} ({env_size} B)')
    with open(path,'rb') as f:
        f.seek(env_off)
        block = f.read(env_size)
    crc_stored = struct.unpack('<I', block[:4])[0]
    flags = block[4]
    body  = block[5:]
    crc_calc = zlib.crc32(body) & 0xFFFFFFFF
    print(f'  CRC stored : 0x{crc_stored:08X}')
    print(f'  CRC calc   : 0x{crc_calc:08X}  ({"OK" if crc_calc==crc_stored else "MISMATCH"})')
    print(f'  flags      : 0x{flags:02X}')
    end = body.find(b'\x00\x00')
    env_bytes = body[:end] if end>0 else body
    vars_ = env_bytes.split(b'\x00')
    print(f'  variables  : {len(vars_)}')
    for v in vars_:
        try:
            print(f'    {v.decode("ascii", errors="replace")}')
        except Exception:
            pass


SLOT_REGIONS = [
    ('slotA', 0x04000000, 0x056B0000),
    ('slotB', 0x08800000, 0x09E50000),
]
PAGE = 0x800

def _looks_like_header(buf):
    """Decide if a 0x800-aligned page begins with our package entry header.
       Layout: u32 type=0x00000001, u32 attr=0x00000105, u16=0xFFFF, asciiz name."""
    if len(buf) < 32:
        return None
    if buf[0:4] != b'\x01\x00\x00\x00':
        return None
    if buf[8:10] != b'\xff\xff':
        return None
    name = bytearray()
    for b in buf[10:0x80]:
        if b == 0:
            break
        if not (32 <= b < 127):
            return None
        name.append(b)
    if not name:
        return None
    return (struct.unpack('<I', buf[4:8])[0], bytes(name).decode('ascii'))


def parse_slot(path, start, end):
    """Walk a slot region, emit (offset, attr, name, content_len) for each entry."""
    entries = []
    with open(path, 'rb') as f:
        # find first header
        page = start
        # locate first header (slot starts with a 1-page directory at start)
        first_header_off = None
        while page < end:
            f.seek(page)
            hdr_buf = f.read(PAGE)
            hdr = _looks_like_header(hdr_buf)
            if hdr is not None:
                first_header_off = page
                break
            page += PAGE
        if first_header_off is None:
            return entries
        # collect all header offsets, terminate when we hit a long all-FF stretch
        header_offs = []
        page = first_header_off
        empty_run = 0
        while page < end:
            f.seek(page)
            hdr_buf = f.read(PAGE)
            hdr = _looks_like_header(hdr_buf)
            if hdr is not None:
                header_offs.append((page, hdr))
                empty_run = 0
            else:
                # Treat fully blank pages as filler — but a single blank page in the
                # middle could just be content; only stop when we've seen 64 KB of FFs
                if hdr_buf == b'\xff' * PAGE:
                    empty_run += 1
                    if empty_run > 32:    # 64 KB of erased pages -> end of slot
                        break
                else:
                    empty_run = 0
            page += PAGE
        # build entries
        for i, (off, (attr, name)) in enumerate(header_offs):
            content_start = off + PAGE
            if i + 1 < len(header_offs):
                content_end = header_offs[i+1][0]
            else:
                content_end = page          # up to last scanned page
            entries.append((off, attr, name, content_start, content_end - content_start))
    return entries


def extract_slot(path=CLEAN, slot_name='slotA', outdir=OUTDIR):
    region = next((r for r in SLOT_REGIONS if r[0] == slot_name), None)
    if region is None:
        raise SystemExit(f'unknown slot {slot_name}')
    _, start, end = region
    print(f'extract {slot_name}: scanning 0x{start:X}..0x{end:X}')
    entries = parse_slot(path, start, end)
    print(f'  found {len(entries)} entries')
    dest = outdir / slot_name
    dest.mkdir(parents=True, exist_ok=True)
    manifest = []
    with open(path,'rb') as f:
        for off, attr, name, cstart, clen in entries:
            f.seek(cstart)
            data = f.read(clen)
            # trim trailing 0xFF padding (NAND erased state)
            stripped = data.rstrip(b'\xff')
            # but keep at least 1 byte if file is intentionally short
            if not stripped:
                stripped = data
            safe = name.replace('/', '_').replace('\\', '_')
            (dest / safe).write_bytes(stripped)
            manifest.append(f'0x{off:08X}  attr=0x{attr:08X}  raw={clen:>10}  trimmed={len(stripped):>10}  {name}')
    (dest / '_manifest.txt').write_text('\n'.join(manifest))
    print(f'  wrote {len(entries)} files -> {dest}')
    print(f'  manifest -> {dest/"_manifest.txt"}')


def find_secrets(path=CLEAN, outdir=OUTDIR):
    """Hunt for PEM, OpenSSH, ASN.1 cert sequences, and config-text headers."""
    import mmap, re
    outdir.mkdir(exist_ok=True)
    secrets_dir = outdir / 'secrets'
    secrets_dir.mkdir(exist_ok=True)
    print(f'find-secrets: {path.name}')
    pem_re = re.compile(rb'-----BEGIN ([A-Z0-9 ]{1,40})-----.*?-----END \1-----', re.DOTALL)
    config_markers = [
        b'<?xml', b'<config', b'<configuration', b'<settings',
        b'BEGIN OPENSSH', b'ssh-rsa ', b'ssh-dss ', b'ssh-ed25519',
        b'AKIA', b'AWSAccessKeyId',
        b'PRIVATE KEY', b'PUBLIC KEY',
        b'.onlive', b'onlive.com', b'olserver',
        b'wpa_supplicant', b'iwconfig', b'iptables',
    ]
    with open(path,'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            # PEM hits
            pems = list(pem_re.finditer(mm))
            print(f'  PEM blocks: {len(pems)}')
            for i, m in enumerate(pems):
                tag = m.group(1).decode().lower().replace(' ','_')
                fn = secrets_dir / f'pem_{i:03d}_{tag}_0x{m.start():X}.pem'
                fn.write_bytes(m.group(0))
                print(f'    [{i:03d}] 0x{m.start():08X} {len(m.group(0)):>8} bytes  {m.group(1).decode()}')
            # ASN.1 DER cert candidates: 30 82 XX XX 30 82 (SEQUENCE { SEQUENCE { ... } })
            der_re = re.compile(rb'\x30\x82(.{2})\x30\x82', re.DOTALL)
            ders = []
            for m in der_re.finditer(mm):
                outer = struct.unpack('>H', m.group(1))[0]
                # plausible cert size: 200 .. 8192
                if 200 < outer < 8192:
                    ders.append((m.start(), outer))
            print(f'  DER SEQUENCE candidates (200<size<8192): {len(ders)}')
            for i,(off,sz) in enumerate(ders[:50]):
                blob = mm[off:off+sz+4]
                fn = secrets_dir / f'der_{i:03d}_0x{off:X}_sz{sz}.bin'
                fn.write_bytes(blob)
            if len(ders) > 50:
                print(f'    (truncated to first 50; total {len(ders)})')
            # plain-text markers
            print(f'  Config / app markers:')
            for marker in config_markers:
                pos = 0
                hits = []
                while True:
                    p = mm.find(marker, pos)
                    if p < 0: break
                    hits.append(p)
                    pos = p + 1
                    if len(hits) >= 50:
                        break
                if hits:
                    sample = ', '.join(f'0x{h:X}' for h in hits[:8])
                    print(f'    {marker.decode("ascii","replace"):<30} hits={len(hits):<4} first: {sample}')
        finally:
            mm.close()


def carve(path=CLEAN, outdir=OUTDIR):
    """Carve out the recognised regions into ./out/"""
    outdir.mkdir(exist_ok=True)
    with open(path,'rb') as f:
        # Partition header
        f.seek(0)
        (outdir/'00_partition_header.bin').write_bytes(f.read(0x1000))

        # U-Boot env (4 redundant copies, 0x20000 each)
        for i, off in enumerate([0x3C00000, 0x3C20000, 0x3C40000, 0x3C60000]):
            f.seek(off)
            (outdir/f'01_uboot_env_{i}.bin').write_bytes(f.read(0x20000))

        # First ELF region
        f.seek(0x4001800)
        (outdir/'02_first_elf_8MB.bin').write_bytes(f.read(8*1024*1024))

        # Pair A application region (0x4000000 - 0x8800000) -- 72 MB
        f.seek(0x4000000)
        (outdir/'03_appA_72MB.bin').write_bytes(f.read(0x4800000))

        # Pair B application region (0x8800000 - 0xD000000) -- 72 MB
        f.seek(0x8800000)
        (outdir/'04_appB_72MB.bin').write_bytes(f.read(0x4800000))

        # Tail (0xD000000 - end)
        f.seek(0xD000000)
        (outdir/'05_tail.bin').write_bytes(f.read())
    print(f'carved into {outdir}')


def usage():
    print(__doc__)
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1]
    if cmd == 'strip-oob':  strip_oob()
    elif cmd == 'scan':     scan()
    elif cmd == 'map':      map_data()
    elif cmd == 'parts':    parse_parts()
    elif cmd == 'dump-env': dump_env()
    elif cmd == 'carve':    carve()
    elif cmd == 'extract': extract_slot(slot_name=sys.argv[2] if len(sys.argv)>2 else 'slotA')
    elif cmd == 'find-secrets': find_secrets()
    elif cmd == 'all':
        if not CLEAN.exists():
            strip_oob()
        parse_parts(); print()
        dump_env();    print()
        scan();        print()
        map_data();    print()
    else:
        usage()


if __name__ == '__main__':
    main()
