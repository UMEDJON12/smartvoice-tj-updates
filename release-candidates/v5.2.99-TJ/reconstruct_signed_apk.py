#!/usr/bin/env python3
"""Reconstruct exact pre-signed SmartVoice APK from public base and patch; verify bytes before upload."""
import base64, hashlib, json, os, struct, subprocess, sys, tempfile, zipfile, zlib
from pathlib import Path

def sha(data):return hashlib.sha256(data).hexdigest()

def rebuild(base_path,patch_path,out_path):
  base=Path(base_path).read_bytes()
  with zipfile.ZipFile(patch_path) as patch:
    meta=json.loads(patch.read('meta.json'))
    assert len(base)==meta['base_size'] and sha(base)==meta['base_sha256'], 'Untrusted or unexpected base APK'
    headers={name:base64.b64decode(value) for name,value in meta['target_headers'].items()}
    replacement={name:patch.read(filename) for name,filename in meta['target_compressed_payloads'].items()}
    with zipfile.ZipFile(base_path) as oldzip:
      with tempfile.TemporaryDirectory() as tmp:
        olddex=Path(tmp)/'old.dex'; newdex=Path(tmp)/'new.dex'; patchdex=Path(tmp)/'dex2.zst'
        olddex.write_bytes(oldzip.read('classes2.dex'))
        patchdex.write_bytes(patch.read(meta['dex_patch']))
        subprocess.run(['zstd','-q','-d','--patch-from='+str(olddex),str(patchdex),'-o',str(newdex)],check=True)
        co=zlib.compressobj(meta['zlib_level'],zlib.DEFLATED,-15)
        data=co.compress(newdex.read_bytes())+co.flush()
        assert sha(data)==meta['dex_compressed_sha256'],'Rebuilt DEX compression mismatch'
        replacement['classes2.dex']=data
    with open(out_path,'wb') as out:
      for item in oldzip.infolist():
        start=item.header_offset
        h=base[start:start+30]
        assert h[:4]==b'PK\x03\x04'
        namelen,extra=struct.unpack_from('<HH',h,26)
        end=start+30+namelen+extra
        header=base[start:end]
        compressed=base[end:end+item.compress_size]
        out.write(headers.get(item.filename,header))
        out.write(replacement.get(item.filename,compressed))
      out.write(patch.read(meta['footer']))
  o=Path(out_path)
  assert o.stat().st_size==meta['target_size'],f'Unexpected output size: {o.stat().st_size}'
  digest=hashlib.sha256(o.read_bytes()).hexdigest()
  assert digest==meta['target_sha256'],f'Unexpected output digest: {digest}'
  print('APK byte-for-byte reconstruction SUCCESS:',str(o), 'sha256:',digest)

if __name__=='__main__':
  assert len(sys.argv)==4, 'usage: reconstruct_signed_apk.py base.apk patch.zip target.apk'
  rebuild(*sys.argv[1:])