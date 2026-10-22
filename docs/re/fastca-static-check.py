# Read-only, known-artifact Mach-O/CodeDirectory check; does not load the module.
import hashlib,json,struct,pathlib,sys
p=pathlib.Path(sys.argv[1])
assert p.stat().st_size <= 16*1024*1024, 'artifact too large'
b=p.read_bytes()
assert hashlib.sha256(b).hexdigest() == '3e7b9e91a861fccbafa9e992daa4c3c4746d9a20eb99e2f43ac860037159cf9c', 'different artifact: review with a new analysis profile'
assert b[:4] == bytes.fromhex('cafebabe'), 'expected bounded universal Mach-O'
n=struct.unpack_from('>I',b,4)[0]
assert n == 2, 'expected two slices'
r={'artifact':str(p),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'slices':[]}
for i in range(n):
 cpu,sub,off,size,align=struct.unpack_from('>IIIII',b,8+20*i); s=b[off:off+size]
 nc=struct.unpack_from('<I',s,16)[0]; co=32; cs=None
 for j in range(nc):
  cmd,ln=struct.unpack_from('<II',s,co)
  if cmd==0x1d: cs=struct.unpack_from('<II',s,co+8)
  co+=ln
 row={'architecture':{0x1000007:'x86_64',0x100000c:'arm64'}.get(cpu,str(cpu)),'file_offset':off,'bytes':size,'sha256':hashlib.sha256(s).hexdigest(),'code_directories':[]}
 at=bytes.fromhex('3b9f958131fe9f006646530500000071df000000000000'); hits=[]; pos=0
 while (pos:=s.find(at,pos))>=0:
  hits.append({'slice_offset':pos,'file_offset':off+pos,'value':s[pos:pos+23].hex(),'following_23_bytes':s[pos+23:pos+46].hex()});pos+=1
 row['atr_pattern_candidates']=hits
 for hit in hits:
  mask_off=hit['slice_offset']+(32 if cpu==0x1000007 else 23)
  hit['candidate_mask_slice_offset']=mask_off
  hit['candidate_mask']=s[mask_off:mask_off+23].hex()
 if cs:
  sig=s[cs[0]:cs[0]+cs[1]]; magic,length,count=struct.unpack_from('>III',sig)
  for j in range(count):
   typ,po=struct.unpack_from('>II',sig,12+8*j); mg,ln=struct.unpack_from('>II',sig,po); blob=sig[po:po+ln]
   if mg==0xfade0c02:
    _,_,ver,flags,ho,io,ns,nc,limit=struct.unpack_from('>IIIIIIIII',blob)
    hs,ht,platform,pg=struct.unpack_from('4B',blob,36); alg={1:'sha1',2:'sha256',3:'sha256',4:'sha384'}.get(ht)
    mism=[]
    for k in range(nc):
     actual=hashlib.new(alg,s[k*(1<<pg):min((k+1)*(1<<pg),limit)]).digest()[:hs]
     stored=blob[ho+k*hs:ho+(k+1)*hs]
     if actual!=stored:mism.append(k)
    row['code_directories'].append({'sha256':hashlib.sha256(blob).hexdigest(),'hash_type':ht,'hash_size':hs,'page_size':1<<pg,'code_limit':limit,'code_slots':nc,'mismatched_code_slots':mism})
   if mg==0xfade0b01:
    row['cms_sha256']=hashlib.sha256(blob[8:]).hexdigest()
 r['slices'].append(row)
print(json.dumps(r,indent=2))
