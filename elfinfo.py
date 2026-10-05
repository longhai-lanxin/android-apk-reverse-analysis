"""Minimal ELF reader: header, sections, dynamic deps, exported/imported symbols, strings."""
import struct, sys, os, glob, re, hashlib

MACH = {3: 'x86 (EM_386)', 8: 'MIPS', 40: 'ARM (EM_ARM)', 62: 'x86-64 (EM_X86_64)',
        183: 'AArch64 (EM_AARCH64)', 243: 'RISC-V'}
ETYPE = {0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN(shared)', 4: 'CORE'}


def read_elf(path):
    d = open(path, 'rb').read()
    is64 = d[4] == 2
    little = d[5] == 1
    en = '<' if little else '>'
    if is64:
        e_type, e_machine = struct.unpack_from(en + 'HH', d, 16)
        e_shoff, = struct.unpack_from(en + 'Q', d, 40)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + 'HHH', d, 58)
        e_phoff, = struct.unpack_from(en + 'Q', d, 32)
        e_phentsize, e_phnum = struct.unpack_from(en + 'HH', d, 54)
    else:
        e_type, e_machine = struct.unpack_from(en + 'HH', d, 16)
        e_shoff, = struct.unpack_from(en + 'I', d, 32)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + 'HHH', d, 46)
        e_phoff, = struct.unpack_from(en + 'I', d, 28)
        e_phentsize, e_phnum = struct.unpack_from(en + 'HH', d, 42)

    def shdr(i):
        o = e_shoff + i * e_shentsize
        if is64:
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(en + 'IIQQQQIIQQ', d, o)
        else:
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(en + 'IIIIIIIIII', d, o)
        return dict(name=name, type=typ, flags=flags, addr=addr, off=off, size=size, link=link, info=info, entsize=entsize)

    secs = [shdr(i) for i in range(e_shnum)]
    shstr = secs[e_shstrndx]
    def sname(n):
        base = shstr['off'] + n
        end = d.index(b'\x00', base)
        return d[base:end].decode('utf-8', 'replace')

    for s in secs:
        s['sname'] = sname(s['name'])
    return d, is64, en, secs, e_type, e_machine


DT = {1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB',
      7: 'RELA', 8: 'RELASZ', 9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 14: 'SONAME',
      15: 'RPATH', 20: 'PLTREL', 23: 'JMPREL', 29: 'RUNPATH', 30: 'FLAGS', 0x6ffffef5: 'GNU_HASH',
      0x6ffffff0: 'VERSYM', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERNEEDNUM', 0x6ffffffc: 'VERDEF',
      0x6ffffffd: 'VERDEFNUM', 0x6ffffdf5: '?', 0x6ffffdf8: '?', 0x6ffffdf9: '?'}


def dyn_info(d, is64, en, secs):
    out = {'needed': [], 'soname': None, 'runpath': None}
    dyn = next((s for s in secs if s['sname'] == '.dynamic'), None)
    if not dyn:
        return out
    ent = 16 if is64 else 8
    p = dyn['off']
    entries = []
    while p < dyn['off'] + dyn['size']:
        if is64:
            tag, val = struct.unpack_from(en + 'QQ', d, p)
        else:
            tag, val = struct.unpack_from(en + 'II', d, p)
        entries.append((tag, val))
        p += ent
    strtab = None
    for s in secs:
        if s['sname'] == '.dynstr':
            strtab = s
    def s(off):
        b = strtab['off'] + off
        e = d.index(b'\x00', b)
        return d[b:e].decode('utf-8', 'replace')
    for tag, val in entries:
        if tag == 1:
            out['needed'].append(s(val))
        elif tag == 14:
            out['soname'] = s(val)
        elif tag in (15, 29):
            out['runpath'] = s(val)
    return out


def symbols(d, is64, en, secs):
    """return (exported, imported) from .dynsym"""
    dsym = next((s for s in secs if s['sname'] == '.dynsym'), None)
    dstr = next((s for s in secs if s['sname'] == '.dynstr'), None)
    if not dsym or not dstr:
        return [], []
    ent = 24 if is64 else 16
    n = dsym['size'] // ent
    exp, imp = [], []
    for i in range(n):
        o = dsym['off'] + i * ent
        if is64:
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(en + 'IBBHQQ', d, o)
        else:
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(en + 'IIIBBH', d, o)
        b = dstr['off'] + st_name
        e = d.index(b'\x00', b)
        nm = d[b:e].decode('utf-8', 'replace')
        bind = st_info >> 4
        typ = st_info & 0xf
        if not nm:
            continue
        rec = (nm, hex(st_value), st_size, bind, typ, st_shndx)
        if st_shndx == 0:
            imp.append(rec)
        else:
            exp.append(rec)
    return exp, imp


printable = re.compile(rb'[\x20-\x7e]{4,}')


def strings_of(d, minlen=5):
    res = []
    for m in printable.finditer(d):
        res.append((m.start(), m.group().decode('ascii')))
    return res


def main():
    for path in sys.argv[1:]:
        print('=' * 100)
        print('FILE:', path, ' size=', os.path.getsize(path), ' sha256=', hashlib.sha256(open(path, 'rb').read()).hexdigest()[:32], '...')
        d, is64, en, secs, e_type, e_machine = read_elf(path)
        print(f'  class={"ELF64" if is64 else "ELF32"} machine={e_machine} {MACH.get(e_machine)} type={ETYPE.get(e_type)} sections={len(secs)}')
        print('  sections:', ', '.join(f"{s['sname']}({s['size']})" for s in secs if s['sname']))
        di = dyn_info(d, is64, en, secs)
        print('  SONAME :', di['soname'])
        print('  NEEDED :', ', '.join(di['needed']))
        print('  RUNPATH:', di['runpath'])
        exp, imp = symbols(d, is64, en, secs)
        print(f'  .dynsym exported={len(exp)} imported={len(imp)}')
        print('  --- exported symbols (bind:1=GLOBAL 2=WEAK, type:2=FUNC 1=OBJECT) ---')
        for nm, val, sz, bind, typ, shn in exp:
            print(f'     {val:>14} {sz:>6} bind={bind} type={typ} shndx={shn} {nm}')
        print('  --- JNI-ish exported (Java_ or JNI_OnLoad) ---')
        for nm, val, sz, bind, typ, shn in exp:
            if nm.startswith('Java_') or 'JNI_OnLoad' in nm:
                print(f'     {val:>14} {nm}')
        print('  --- imported symbols (first 60) ---')
        for nm, val, sz, bind, typ, shn in imp[:60]:
            print('     ', nm)
        print(f'  --- printable strings (first 120, len>=5) ---')
        st = strings_of(d)
        for off, s in st[:120]:
            print(f'     0x{off:08x} {s}')
        print('  --- strings matching URL/IP/host ---')
        pat = re.compile(r'(https?://[^\s\x00]{6,}|\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-z0-9-]+\.(?:com|cn|net|org|io|so)(?:[:./][^\s\x00]*)?)')
        seen = set()
        for off, s in st:
            for m in pat.findall(s):
                if m not in seen:
                    seen.add(m)
                    print(f'     0x{off:08x} {m}')


main()
