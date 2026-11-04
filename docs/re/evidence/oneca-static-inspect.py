"""Read-only PE/import/export/string inventory; never loads target code.

Usage: python3 docs/re/evidence/oneca-static-inspect.py > docs/re/evidence/oneca-static-inventory.json
Scope: regular original/extracted files under .local/oneca-windows.
"""
from pathlib import Path
import hashlib, json, re, struct

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / '.local/oneca-windows'

def inspect(path):
    b = path.read_bytes()
    out = dict(path=str(path.relative_to(ROOT)), size=len(b), sha256=hashlib.sha256(b).hexdigest(), sha1=hashlib.sha1(b).hexdigest())
    if not b.startswith(b'MZ'):
        if path.suffix.lower() in ('.reg', '.inf', '.ini', '.bat'):
            out['text'] = b.decode('utf-16' if b[:2] in (b'\xff\xfe', b'\xfe\xff') else 'utf-8', errors='replace')
        return out
    def u16(o): return struct.unpack_from('<H', b, o)[0]
    def u32(o): return struct.unpack_from('<I', b, o)[0]
    def u64(o): return struct.unpack_from('<Q', b, o)[0]
    pe = u32(0x3c)
    assert b[pe:pe+4] == b'PE\0\0'
    opt = pe+24
    x64 = u16(opt) == 0x20b
    sec = opt+u16(pe+20)
    sections=[]
    for i in range(u16(pe+6)):
        p=sec+40*i
        sections.append(dict(name=b[p:p+8].split(b'\0')[0].decode(),virtual_size=u32(p+8),rva=u32(p+12),raw_size=u32(p+16),offset=u32(p+20)))
    def raw(rva):
        if rva < u32(opt+60): return rva
        for s in sections:
            if s['rva'] <= rva < s['rva']+s['raw_size']: return s['offset']+rva-s['rva']
        raise ValueError(hex(rva))
    def cstr(p): return b[p:b.index(0,p)].decode('ascii',errors='replace')
    dd=opt+(112 if x64 else 96)
    imagebase=u64(opt+24) if x64 else u32(opt+28)
    exports=[]
    er,es=u32(dd),u32(dd+4)
    if er:
        p=raw(er); ordinal_base,nf,nn,funcs,names,ords=struct.unpack_from('<IIIIII', b,p+16)
        names_by_ord={u16(raw(ords)+2*i):cstr(raw(u32(raw(names)+4*i))) for i in range(nn)}
        for i in range(nf):
            rva=u32(raw(funcs)+4*i)
            if not rva: continue
            exports.append(dict(ordinal=ordinal_base+i,name=names_by_ord.get(i),rva=hex(rva),address=hex(imagebase+rva),forwarder=cstr(raw(rva)) if er <= rva < er+es else None))
    imports=[]
    ir=u32(dd+8)
    if ir:
        p=raw(ir)
        while any(b[p:p+20]):
            lookup,_,_,name,iat=struct.unpack_from('<IIIII',b,p)
            q=raw(lookup or iat); funcs=[]; stride=8 if x64 else 4
            while (v:=(u64(q) if x64 else u32(q))):
                funcs.append({'ordinal':v & 0xffff} if v & (1<<(stride*8-1)) else {'name':cstr(raw(v)+2)})
                q+=stride
            imports.append(dict(dll=cstr(raw(name)),functions=funcs));p+=20
    strings=[]
    pattern=re.compile(r'one.?ca|longmai|cryptoid|vid_|pid_|gm3000|gmpcsc|\.pdb|pkcs|mToken|SCard|SKF_|MKF_|RSA|CERT|http|NCrypt|KSP|CardAcquire',re.I)
    for encoding,regex in [('ascii',rb'[\x20-\x7e]{5,}'),('utf-16-le',rb'(?:[\x20-\x7e]\x00){5,}')]:
        for m in re.finditer(regex,b):
            val=m.group().decode(encoding)
            if pattern.search(val): strings.append(dict(offset=hex(m.start()),encoding=encoding,value=val))
    out.update(machine=hex(u16(pe+4)),architecture='x86_64' if x64 else 'x86',image_base=hex(imagebase),entrypoint=hex(imagebase+u32(opt+16)),sections=sections,exports=exports,imports=imports,selected_strings=strings,clr_directory=hex(u32(dd+14*8)))
    return out

records=[inspect(p) for folder in ('original','extracted') for p in sorted((BASE/folder).rglob('*')) if p.is_file()]
print(json.dumps(dict(evidence_id='oneca-local-static-20261023',authority='shipped-artifact',method='stdlib PE header/import/export parser and bounded ASCII/UTF16 string scan',limitations=['No target code executed.', 'Strings are data and do not establish reachable behavior.', 'Import scan covers normal imports; delayed/dynamic loads require tracing.', 'No Authenticode trust validation.', 'Extraction preserves Inno duplicate files with --collisions rename.'],files=records),indent=2))
