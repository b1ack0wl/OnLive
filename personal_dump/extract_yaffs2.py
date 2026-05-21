#!/usr/bin/env python3
"""
YAFFS2 inband-tags extractor for Marvell BERLIN-A0 OnLive NAND.
- Each NAND page = 2048 bytes. Last 16 bytes are packed_tags2 (inband).
- Chunk size for data = 2032 bytes.
- Header chunks have chunk_id top bit set (EXTRA_HEADER_INFO_FLAG).
- obj_id high 4 bits encode obj_type on header chunks; mask 0x0FFFFFFF for real obj_id.
"""
import os, sys, struct, stat, errno

PAGE = 2048
TAG_SIZE = 16
CHUNK_DATA_SIZE = PAGE - TAG_SIZE  # 2032

# yaffs object types
T_UNKNOWN, T_FILE, T_SYMLINK, T_DIRECTORY, T_HARDLINK, T_SPECIAL = 0, 1, 2, 3, 4, 5
TYPE_NAMES = {T_UNKNOWN:'?', T_FILE:'file', T_SYMLINK:'symlink', T_DIRECTORY:'dir', T_HARDLINK:'hardlink', T_SPECIAL:'special'}

OBJ_ID_MASK = 0x0FFFFFFF
HEADER_FLAG = 0x80000000

def parse_tags(buf16):
    seq, oid, cid, nbytes = struct.unpack('<IIII', buf16)
    return seq, oid, cid, nbytes

def parse_obj_header(data):
    """Parse the YAFFS object header at start of a header-chunk page."""
    # struct yaffs_obj_hdr:
    #   u32 type, u32 parent_obj_id, u16 sum_no_longer_used, char name[256],
    #   u32 yst_mode, u32 yst_uid, u32 yst_gid, u32 yst_atime, u32 yst_mtime, u32 yst_ctime,
    #   u32 file_size_low, u32 equiv_id, char alias[160], u32 yst_rdev,
    #   u32 win_ctime[2], u32 win_atime[2], u32 win_mtime[2],
    #   u32 inband_shadowed_obj_id, u32 inband_is_shrink, u32 file_size_high, u32 reserved[1],
    #   s32 shadows_obj, u32 is_shrink
    typ, parent = struct.unpack('<II', data[0:8])
    name = data[10:10+256].split(b'\x00',1)[0].decode('utf-8','replace')
    off = 10 + 256
    yst_mode, yst_uid, yst_gid, yst_atime, yst_mtime, yst_ctime, fsl, equiv = \
        struct.unpack('<IIIIIIII', data[off:off+32])
    off += 32
    alias = data[off:off+160].split(b'\x00',1)[0].decode('utf-8','replace')
    off += 160
    yst_rdev = struct.unpack('<I', data[off:off+4])[0]
    return {
        'type': typ,
        'parent': parent,
        'name': name,
        'mode': yst_mode,
        'uid': yst_uid,
        'gid': yst_gid,
        'atime': yst_atime,
        'mtime': yst_mtime,
        'ctime': yst_ctime,
        'file_size_low': fsl,
        'equiv_id': equiv,
        'alias': alias,
        'rdev': yst_rdev,
    }

def extract(partition_path, out_root, label='', verbose=False):
    print(f'\n=== extracting {partition_path} -> {out_root} ===')
    os.makedirs(out_root, exist_ok=True)
    with open(partition_path, 'rb') as f:
        blob = f.read()
    n_pages = len(blob) // PAGE
    print(f'pages: {n_pages}')

    # Best version per (obj_id, chunk_id) by seq_number.
    # obj_id 0 / 0xFFFFFFFF means erased
    headers = {}     # obj_id -> (seq, hdr_dict)
    data_chunks = {} # (obj_id, chunk_id) -> (seq, bytes)

    stats = {'erased': 0, 'header': 0, 'data': 0, 'unknown': 0}

    for i in range(n_pages):
        off = i * PAGE
        page = blob[off:off+PAGE]
        tags = page[CHUNK_DATA_SIZE:PAGE]
        if tags == b'\xff'*TAG_SIZE:
            stats['erased'] += 1
            continue
        seq, oid_raw, cid_raw, nbytes = parse_tags(tags)
        if seq == 0xFFFFFFFF or oid_raw == 0xFFFFFFFF:
            stats['erased'] += 1
            continue
        obj_id = oid_raw & OBJ_ID_MASK
        if cid_raw & HEADER_FLAG:
            # header chunk
            parent_obj_id = cid_raw & 0x7FFFFFFF
            obj_type = (oid_raw >> 28) & 0xF
            file_size = nbytes
            # Some YAFFS2 streams may use chunk_id=0 with no top bit set; handle either.
            hdr = parse_obj_header(page[:CHUNK_DATA_SIZE])
            # Header's own type/parent are authoritative; tag-encoded extras are a hint only.
            # (yaffs2 sometimes only fills extras, but in this dump header is filled.)
            if hdr['type'] == 0 and obj_type and obj_type in TYPE_NAMES:
                hdr['type'] = obj_type
            if hdr['parent'] == 0 and parent_obj_id:
                hdr['parent'] = parent_obj_id
            if hdr['type'] == T_FILE:
                # use tags' file size if header didn't set it
                if file_size and file_size != 0xFFFFFFFF:
                    hdr['file_size_low'] = file_size
            old = headers.get(obj_id)
            if old is None or seq >= old[0]:
                headers[obj_id] = (seq, hdr)
            stats['header'] += 1
        else:
            # data chunk
            cid = cid_raw
            if nbytes == 0 or nbytes > CHUNK_DATA_SIZE:
                # corrupt or strange; skip
                stats['unknown'] += 1
                continue
            key = (obj_id, cid)
            old = data_chunks.get(key)
            if old is None or seq >= old[0]:
                data_chunks[key] = (seq, page[:nbytes])
            stats['data'] += 1

    print('page stats:', stats)
    print(f'headers={len(headers)} data_chunks={len(data_chunks)}')

    # Resolve tree: walk from root (obj_id 1).
    children = {}  # parent -> [child_obj_id]
    for oid, (seq, hdr) in headers.items():
        if oid == 1:
            continue
        children.setdefault(hdr['parent'], []).append(oid)

    # Sanity: root header is obj_id == 1 (might or might not exist in dumped subset).
    root_path = out_root
    # Build path for every obj.
    path_of = {1: root_path}

    def safe_name(n):
        # Disallow path separators and bad chars on Windows
        bad = '<>:"/\\|?*'
        out = ''.join(('_' if c in bad or ord(c) < 0x20 else c) for c in n)
        if not out:
            out = '_unnamed'
        # Windows reserved names
        reserved = {'CON','PRN','AUX','NUL'} | {f'COM{i}' for i in range(1,10)} | {f'LPT{i}' for i in range(1,10)}
        base = out.split('.')[0].upper()
        if base in reserved:
            out = '_' + out
        return out

    deferred_links = []  # (path, target) for symlinks/hardlinks
    deferred_specials = []  # specials

    # BFS by parent so paths resolve in dependency order
    queue = [1]
    seen = set()
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        for child in children.get(pid, []):
            seq, hdr = headers[child]
            parent_hdr = headers.get(pid)
            parent_is_dir = (pid == 1) or (parent_hdr and parent_hdr[1]['type'] == T_DIRECTORY)
            parent_path = path_of.get(pid) if parent_is_dir else None
            if not parent_path:
                # Orphan: stash under __orphans__/parent_<pid>/
                parent_path = os.path.join(out_root, '__orphans__', f'parent_{pid}')
                os.makedirs(parent_path, exist_ok=True)
            name = safe_name(hdr['name'])
            full = os.path.join(parent_path, name)
            t = hdr['type']
            if t == T_DIRECTORY:
                os.makedirs(full, exist_ok=True)
                path_of[child] = full
            elif t == T_FILE:
                size = hdr.get('file_size_low', 0) or 0
                chunks = []
                cid = 1
                got = 0
                while True:
                    rec = data_chunks.get((child, cid))
                    if rec is None:
                        break
                    chunks.append(rec[1])
                    got += len(rec[1])
                    cid += 1
                    if got >= size and size > 0:
                        break
                content = b''.join(chunks)
                if size and size <= len(content):
                    content = content[:size]
                try:
                    with open(full, 'wb') as wf:
                        wf.write(content)
                except OSError as e:
                    print(f'! cannot write {full}: {e}')
                path_of[child] = full
            elif t == T_SYMLINK:
                deferred_links.append(('symlink', full, hdr.get('alias',''), hdr))
                path_of[child] = full
            elif t == T_HARDLINK:
                deferred_links.append(('hardlink', full, hdr.get('equiv_id',0), hdr))
                path_of[child] = full
            elif t == T_SPECIAL:
                deferred_specials.append((full, hdr))
                path_of[child] = full
            else:
                # Unknown — write a placeholder.
                with open(full + '.unknown', 'wb') as wf:
                    pass
                path_of[child] = full + '.unknown'
            queue.append(child)
            if verbose:
                print(f'  obj {child:5d} type={TYPE_NAMES.get(t,"?"):<8} parent={pid:5d} mode=0{hdr["mode"]&0o7777:o} {name}')

    # Write a manifest with mode/uid/gid/symlink/etc.
    manifest_path = os.path.join(out_root, '__manifest__.tsv')
    with open(manifest_path, 'w', encoding='utf-8') as m:
        m.write('obj_id\ttype\tparent\tmode\tuid\tgid\tsize\tmtime\trdev\tequiv\talias\tpath\n')
        for oid, (seq, hdr) in sorted(headers.items()):
            t = TYPE_NAMES.get(hdr['type'],'?')
            p = path_of.get(oid, '')
            rel = os.path.relpath(p, out_root) if p else ''
            m.write(f'{oid}\t{t}\t{hdr["parent"]}\t0{hdr["mode"]&0o7777:o}\t'
                    f'{hdr["uid"]}\t{hdr["gid"]}\t{hdr["file_size_low"]}\t'
                    f'{hdr["mtime"]}\t{hdr["rdev"]}\t{hdr["equiv_id"]}\t'
                    f'{hdr["alias"]}\t{rel}\n')

    # Write deferred link/special info to a text file (can't materialize on Windows generally).
    links_path = os.path.join(out_root, '__links_and_specials__.tsv')
    with open(links_path, 'w', encoding='utf-8') as m:
        m.write('kind\tpath\ttarget_or_rdev\tnote\n')
        for kind, path, target, hdr in deferred_links:
            try:
                rel = os.path.relpath(path, out_root)
            except ValueError:
                rel = path
            if kind == 'symlink':
                m.write(f'symlink\t{rel}\t{target}\t-> {target}\n')
                # also write a *.symlink file with the target
                try:
                    with open(path + '.symlink', 'w', encoding='utf-8') as sf:
                        sf.write(target)
                except OSError:
                    pass
            else:
                m.write(f'hardlink\t{rel}\t{target}\thardlink to obj {target}\n')
        for path, hdr in deferred_specials:
            try:
                rel = os.path.relpath(path, out_root)
            except ValueError:
                rel = path
            rdev = hdr.get('rdev', 0)
            m.write(f'special\t{rel}\t{rdev}\tmode=0{hdr["mode"]&0o7777:o}\n')
            try:
                with open(path + '.special', 'w', encoding='utf-8') as sf:
                    sf.write(f'mode=0{hdr["mode"]&0o7777:o}\nrdev={rdev}\n')
            except OSError:
                pass

    print(f'wrote {manifest_path}')
    print(f'wrote {links_path}')

if __name__ == '__main__':
    base = 'personal_dump/partitions'
    out_base = 'personal_dump/extracted'
    # Use .data.bin (OOB stripped) — YAFFS2 tags here are inband, last 16 bytes of each 2048-byte page.
    targets = [
        ('ra',   f'{base}/ra.data.bin',   f'{out_base}/ra'),
        ('rb',   f'{base}/rb.data.bin',   f'{out_base}/rb'),
        ('conf', f'{base}/conf.data.bin', f'{out_base}/conf'),
        ('r',    f'{base}/r.data.bin',    f'{out_base}/r'),
    ]
    if len(sys.argv) > 1:
        wanted = set(sys.argv[1:])
        targets = [t for t in targets if t[0] in wanted]
    for label, src, dst in targets:
        extract(src, dst, label)
