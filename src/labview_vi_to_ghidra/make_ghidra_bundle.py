"""Prepare a conservative LV13 x86 Ghidra relocation plan from full VI XML.
Original implementation based on static lvrt.dll handler at RVA 0x170690.
No target execution. Addresses and patch handling apply to the supported runtime build only.
"""
from pathlib import Path
import sys,json,struct,hashlib,xml.etree.ElementTree as ET,collections
if __package__:
 from .toolchain import validate_runtime
else:
 from toolchain import validate_runtime
def sha(b):return hashlib.sha256(b).hexdigest()
def build(name,base=0x10000000,*,xml_path,vi_path,output_dir,runtime,runtime_map,embed_vi=False):
 x=Path(xml_path).resolve();d=x.parent;root=ET.parse(x).getroot()
 ver=root.find('./LVSR/Section/Version');assert ver.get('Major')=='13'
 sections=root.findall('./VICD/Section');assert len(sections)==1
 sec=sections[0];assert sec.find('General').get('CodeID')=='i386'
 rt=validate_runtime(runtime,runtime_map)
 callbacks={f['ident']:(m,f) for m in rt['modules'] for f in m['functions']}
 code=d/sec.find('Code').get('File');original=code.read_bytes();patched=bytearray(original)
 changes=[];unresolved=[];targets={};records=[];written=set()
 def change(off,new,kind,record,**extra):
  assert 0<=off<=len(patched)-4,(kind,off)
  assert not set(range(off,off+4))&written,('overlapping patch',off)
  written.update(range(off,off+4));old=struct.unpack_from('<I',patched,off)[0];struct.pack_into('<I',patched,off,new&0xffffffff)
  changes.append(dict(offset=off,old=old,new=new&0xffffffff,kind=kind,record=record,**extra))
 for idx,p in enumerate(sec.findall('./Patches/Patch')):
  off=int(p.get('Offset'),0);ident=int(p.get('Ident'),0);record={'offset':off,'ident':ident,'attributes':p.attrib,'relocations':[int(e.text,0) for e in p.findall('Reloc')]};records.append(record)
  if ident in [0x20000,0x20007]:
   oldbase=int(p.get('Field2'),0);delta=base-oldbase
   for off2 in record['relocations']:
    old=struct.unpack_from('<I',original,off2)[0]
    change(off2,old+delta,'code_base',idx,ident=ident,old_base=oldbase)
   continue
  if list(p):unresolved.append(dict(record=idx,reason='Unsupported structured record'));continue
  if ident not in callbacks or callbacks[ident][1]['unimplemented'] or not callbacks[ident][1]['executable']:
   unresolved.append(dict(record=idx,offset=off,ident=ident,reason='No verified callback target'));continue
  mod,f=callbacks[ident];target=f['target'];assert 0<off<=len(original)-4
  # Mirrors 0x301707f2..0x3017092e. The byte immediately before the
  # patch operand selects relative CALL versus absolute 32-bit pointer.
  relative=original[off-1]==0xe8
  value=target-(base+off+4) if relative else target
  symbol=f['export_names'][0] if f['export_names'] else 'LVRT_'+mod['name']+'_'+format(f['index'],'04x')
  targets.setdefault(str(target),{'address':target,'name':symbol,'aliases':[],'export_names':f['export_names']})['aliases'].append(hex(ident))
  change(off,value,'runtime_rel32' if relative else 'runtime_abs32',idx,ident=ident,target=target,symbol=symbol,module=mod['name'])
 out=Path(output_dir).resolve();out.mkdir(parents=True,exist_ok=True)
 entries=json.loads(code.with_suffix('.entrypoints.json').read_text());entries=list({(e['name'],e['offset']):e for e in entries}.values())
 original_vi=Path(vi_path).resolve();vi_data=original_vi.read_bytes()
 resources=[];resource_address=0x50000000;labels=set();paths=set()
 archived=[('Original_VI',original_vi)] if embed_vi else []
 archived+=[('VI_Metadata_XML',x)]+[('FrontPanel_XML',p.resolve()) for p in d.glob('*FPH*.xml')]
 for label,p in archived:
  if label in labels or str(p) in paths:raise ValueError('Duplicate archived resource')
  data=vi_data if label=='Original_VI' else p.read_bytes();size=len(data)
  if not size or resource_address+size>=0x60000000:raise ValueError('Empty resource or resource archive exceeds its address range')
  labels.add(label);paths.add(str(p))
  resources.append({'label':label,'path':str(p),'sha256':sha(data),'size':size,'address':resource_address})
  resource_address=(resource_address+size+0xfffff)&~0xfffff
 plan={'schema':1,'vi':name,'original_vi_embedded':bool(embed_vi),'original_vi_sha256':sha(vi_data),'source_xml':str(x),'code_path':str(code),'source_sha256':sha(original),'patched_sha256':sha(patched),'code_size':len(original),'base':base,'runtime':rt['runtime'],'runtime_sha256':rt['sha256'],'runtime_base':rt['image_base'],'patches':records,'changes':changes,'unresolved':unresolved,'targets':list(targets.values()),'entries':entries,'resources':resources,'scope':'analysis-only static import, not an executable VI'}
 (out/'plan.json').write_text(json.dumps(plan,indent=2));(out/'code.original.bin').write_bytes(original);(out/'code.relocated.bin').write_bytes(patched)
 # Invariants independently reconstruct each resolved reference from output bytes.
 for c in changes:
  word=struct.unpack_from('<I',patched,c['offset'])[0]
  if c['kind']=='runtime_rel32':assert (word+base+c['offset']+4)&0xffffffff==c['target']
  elif c['kind']=='runtime_abs32':assert word==c['target']
  else:assert word==(c['old']+base-c['old_base'])&0xffffffff
 for off in range(len(original)):
  if off not in written:assert original[off]==patched[off]
 counts=dict(collections.Counter(c['kind'] for c in changes));print(name,counts,'unresolved',len(unresolved),'targets',len(targets))
 (out/'validation.json').write_text(json.dumps({'changes':counts,'unresolved':len(unresolved),'targets':len(targets),'unchanged_bytes_outside_patches':True,'reconstructed_targets_match':True},indent=2))
 return plan
