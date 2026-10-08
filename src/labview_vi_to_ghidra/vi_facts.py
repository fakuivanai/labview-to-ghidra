"""Evidence-backed VI facts for Ghidra, not inferred runtime state.
Native extents use an empirical LV13/i386 profile checked against independent saved
offsets. RSRC field meanings follow pinned pylabview, cited at the relevant rules.
Unsupported layouts and sparse-value encodings are retained as unresolved.
"""
from pathlib import Path
import hashlib,json,re,struct,xml.etree.ElementTree as E
def sha(b):return hashlib.sha256(b).hexdigest()
def parse(path):return E.parse(path,parser=E.XMLParser(target=E.TreeBuilder(insert_comments=True)))
def textlabel(s):return s[1:-1] if s and s.startswith('"') and s.endswith('"') else s
SLOTS={'Ptr','PtrTo','String','Array','Path','Refnum','Picture','LVVariant'}
def dco_records(root):
 out=[]
 for df in root.findall('DFDS/Section/DataFill'):
  if not any(c.tag is E.Comment and 'Table of Front Panel DCOs' in (c.text or '') for c in df):continue
  for cl in df.findall('RepeatedBlock/Cluster'):
   values={};key=None
   for c in cl:
    if c.tag is E.Comment:key=(c.text or '').strip()
    elif key:values[key]=c.text if c.tag=='Block' else int(c.text);key=None
   out.append(dict(table_type=df.get('TypeID'),values=values))
 return out
class Layout:
 def __init__(self,root):
  self.flat=root.findall('VCTP/Section/TypeDesc');self.top={int(t.get('Index')):int(t.get('FlatTypeID')) for t in root.findall('VCTP/Section/TopLevel/TypeDesc')};self.cache={};self.active=set();self.sources={i:f'VCTP flat index {i}' for i in range(len(self.flat))};self.inline={}
 def td(self,i):
  if i<0 or i>=len(self.flat):raise ValueError('Type ID outside VCTP')
  return self.flat[i]
 def desc(self,i):
  if i in self.cache:return self.cache[i]
  if i in self.active:raise ValueError('Recursive by-value type')
  self.active.add(i);t=self.td(i);kind=t.get('Type');children=[];offset=0
  d={'id':i,'kind':kind,'label':t.get('Label'),'representation':'opaque','source':self.sources[i]}
  m=re.fullmatch(r'(?:Num|Unit)(UInt|Int|Float|Complex)(\d+)',kind or '')
  if m:
   bits=int(m[2]);size=bits//8
   if bits%8 or bits not in [8,16,32,64,128]:raise ValueError('Unsupported scalar width')
   d['scalar']=('Num'+m[1]+m[2]) if m[1]!='Complex' else None;d['representation']='scalar' if d['scalar'] else 'opaque'
  elif kind in ['NumFloatExt','UnitFloatExt']:
   # Native width is corroborated by explicit 10-byte DCO value extents and
   # independent offsets under this LV13/i386 profile. The saved DFDS value
   # uses 16 bytes instead; its encoding must not determine the native width.
   # https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVdatafill.py#L252-L287
   size=10;d['note']='Opaque 10-byte native extended-float extent under the anchored LV13/i386 profile; saved DFDS storage is 16 bytes. No native scalar ABI or byte conversion asserted.'
  elif kind in ['Void','AlignmntMarker']:size=0
  elif kind=='Boolean':size=1;d.update(scalar='Boolean',representation='scalar')
  elif kind in SLOTS:size=4;d['representation']='opaque_slot32'
  elif kind=='SubString':size=12
  elif kind=='SubArray':size=4+8*len(t.findall('Dimension'))
  elif kind=='MeasureData':
   flavor=t.get('Flavor');size={'Dynamicdata':4,'Float64Waveform':41,'TimeStamp':16}.get(flavor)
   if size is None:raise ValueError('Unsupported MeasureData flavor '+str(flavor)+'; native extent not established')
   # Timestamp's 16-byte block agrees with explicit native DCO extents and
   # offsets; its integer/fractional field layout is deliberately left opaque.
   # https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVdatafill.py#L881-L884
   d['note']='Opaque 16-byte timestamp extent corroborated by native DCO records under the anchored LV13/i386 profile; internal fields and runtime values unresolved.' if flavor=='TimeStamp' else 'Extent only; internal layout opaque (41-byte waveform extent is empirical for this build).'
  elif kind in ['AlignedBlock','Block']:size=int(t.get('BlockSize'),0)
  elif kind in ['Cluster','TypeDef','RepeatedBlock']:
   for n,c in enumerate(t.findall('TypeDesc')):
    if c.get('TypeID') is None:
     if id(c) not in self.inline:
      self.inline[id(c)]=len(self.flat);self.sources[len(self.flat)]=f'{self.sources[i]}, inline child {n}';self.flat.append(c)
     cid=self.inline[id(c)]
    else:cid=int(c.get('TypeID'))
    child=self.desc(cid);children.append(dict(id=cid,offset=offset,size=child['size'],name=f'm{n}_'+(child['label'] or child['kind'])));offset+=child['size']
   if kind=='Cluster':size=offset;d['representation']='packed_cluster'
   else:
    if len(children)!=1:raise ValueError('Aggregate arity mismatch')
    count=int(t.get('NumRepeats')) if kind=='RepeatedBlock' else 1
    if count<0:raise ValueError('Negative repeat count')
    size=count*children[0]['size'];d.update(count=count,representation='repeat' if kind=='RepeatedBlock' else 'typedef')
   d['children']=children
  else:raise ValueError('Unsupported native type '+str(kind))
  if size<0 or size>16*1024*1024:raise ValueError('Native extent outside supported bounds')
  d['size']=size;self.active.remove(i);self.cache[i]=d;return d
 def rows(self,root):
  tm=root.find('TM80/Section')
  if tm is None:raise ValueError('Missing TM80')
  self.shift=int(tm.get('IndexShift'));offset=0;rows=[]
  for i,c in enumerate(tm.findall('Client')):
   tid=self.shift+i;fid=self.top[tid];d=self.desc(fid);rows.append(dict(type_id=tid,flat_id=fid,offset=offset,size=d['size'],label=d['label'],kind=d['kind']));offset+=d['size']
  return rows,offset

def sparse_integer(raw, kind):
    """Decode a compact heap integer without using the native byte order."""
    # HeapNodeTDDataFill shrinks redundant leading sign bits and reads its
    # integer payloads big endian, including sign extension of unsigned data.
    # https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVheap.py#L1984-L2063
    match = re.fullmatch(r'(Num|Unit)(U?Int)(8|16|32|64)', kind or '')
    if not match or match[1] == 'Unit' and (match[2] != 'UInt' or match[3] == '64'):
        raise ValueError('Ring value type is not a supported integer')
    width = int(match[3]) // 8
    try:
        payload = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError('Malformed sparse integer hex payload') from exc
    if not 1 <= len(payload) <= width:
        raise ValueError('Sparse integer payload extent exceeds value type or is empty')
    signed = match[2] == 'Int'
    value = int.from_bytes(payload, 'big', signed=True)
    if not signed:
        value &= (1 << (width * 8)) - 1
    return value, width, signed


def ring_labels(raw):
    """Read the pinned decoder's Pascal-string-list XML form."""
    # Quotes and most control characters use literal numeric entities inside
    # the decoded XML text. Backslashes have no escaping role in this format.
    # https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVheap.py#L1864-L1923
    # https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVxml.py#L202-L239
    match = re.fullmatch(r'\((\d+)\)((?:"[^"]*")*)', raw, re.DOTALL)
    if not match:
        raise ValueError('Malformed sparse ring label list')
    labels = re.findall(r'"([^"]*)"', match[2], re.DOTALL)
    if int(match[1]) != len(labels):
        raise ValueError('Sparse ring label-list count mismatch')
    escaped = {f'&#x{c:02X};': chr(c) for c in range(32) if c not in (9, 10)}
    escaped['&#x22;'] = '"'
    pattern = re.compile('|'.join(re.escape(k) for k in escaped))
    return [pattern.sub(lambda m: escaped[m[0]], label) for label in labels]


def rings(root,panel,layout):
 if panel is None:return []
 pr=parse(panel);shift=root.find('DTHP/Section/TypeDescSlice');shift=int(shift.get('IndexShift')) if shift is not None else None;out=[]
 for e in pr.iter():
  if e.get('class')!='fPDCO' or e.find('ddo/ringSparseValues') is None:continue
  raw=e.find('ddo/ringSparseValues');labels=[textlabel(z.text or '') for z in e.findall('ddo/partsList/SL__arrayElement/textRec/text') if z.text];bufs=[z.findtext('buf') for z in e.findall('ddo/partsList/SL__arrayElement') if z.get('class')=='multiLabel' and z.find('buf') is not None]
  item=dict(uid=e.get('uid'),labels=list(dict.fromkeys(labels)),raw_values=[c.text or '' for c in raw],raw_labels=bufs,status='unresolved',binding='Front-panel UID only; no native DCO/field binding inferred')
  try:
   if len(bufs)!=1:raise ValueError('Ambiguous label list')
   names=ring_labels(bufs[0]);values=item['raw_values']
   if len(names)!=len(values) or not names:raise ValueError('Sparse values/labels count mismatch')
   value_td=e.findtext('ddo/typeDesc');m=re.fullmatch(r'TypeID\((\d+)\)',value_td or '')
   if shift is None or not m or int(m[1])<=0:raise ValueError('No value type mapping')
   fid=layout.top[shift+int(m[1])-1];t=layout.td(fid);kind=t.get('Type')
   decoded=[sparse_integer(v,kind) for v in values]
   width,signed=decoded[0][1:]
   item.update(size=width,signed=signed,value_type=kind,flat_id=fid,encoding='big_endian_compact_heap_integer',entries=[dict(label=name,value=value[0]) for name,value in zip(names,decoded)])
   if any(value[0]>(1<<63)-1 for value in decoded):
    raise ValueError('Unsigned 64-bit value exceeds the verified Ghidra enum range; exact decoded entries retained without enum import')
   item['status']='recorded'
  except (ValueError,KeyError,IndexError) as exc:item['reason']=str(exc)
  out.append(item)
 return out

def constant_frames(code,plan):
 """Candidates only. Ghidra must verify instruction boundaries and incoming flows."""
 if not plan.get('dispatchers'):
  return [dict(offset=c['offset']-1,status='unresolved',reason='No verified EBP=data-space context for this emitter',candidates=[]) for c in plan['changes'] if c.get('symbol')=='WriteDCOTransferData' and c['kind']=='runtime_rel32']
 from capstone import Cs,CS_ARCH_X86,CS_MODE_32
 from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM,X86_REG_EBP,X86_REG_ESP
 md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True;out=[]
 for patch in plan['changes']:
  if patch.get('symbol')!='WriteDCOTransferData' or patch['kind']!='runtime_rel32':continue
  off=patch['offset']-1;record=dict(offset=off,status='unresolved',reason='No verified constant argument frame',candidates=[])
  # Seven pushes are corroborated by the caller's explicit stack cleanup.
  if code[off+5:off+9]!=bytes.fromhex('8d64241c'):
   record['reason']='Unverified caller stack cleanup';out.append(record);continue
  for start in range(max(45,off-100),off):
   ins=list(md.disasm(code[start:off+5],start))
   if not ins or ins[-1].address!=off or ins[-1].mnemonic!='call' or sum(i.size for i in ins)!=off+5-start:continue
   regs={X86_REG_EBP:('ds',0)};stack=[];valid=True
   def val(o):return ('imm',o.imm) if o.type==X86_OP_IMM else regs.get(o.reg) if o.type==X86_OP_REG else None
   for i in ins[:-1]:
    o=i.operands
    if i.mnemonic=='mov' and len(o)==2 and o[0].type==X86_OP_REG and o[0].reg not in [X86_REG_EBP,X86_REG_ESP]:regs[o[0].reg]=val(o[1])
    elif i.mnemonic=='lea' and len(o)==2 and o[0].type==X86_OP_REG and o[0].reg not in [X86_REG_EBP,X86_REG_ESP] and o[1].type==X86_OP_MEM:
     v=regs.get(o[1].mem.base);regs[o[0].reg]=(v[0],v[1]+o[1].mem.disp) if v and o[1].mem.index==0 else None
    elif i.mnemonic=='push' and len(o)==1 and o[0].size==4:stack.append(val(o[0]))
    elif i.mnemonic=='add' and len(o)==2 and o[0].type==X86_OP_MEM and o[0].mem.base==X86_REG_ESP and o[0].mem.index==0 and o[0].mem.disp==0 and o[0].size==4 and o[1].type==X86_OP_IMM and stack:
     v=stack[-1];stack[-1]=(v[0],v[1]+o[1].imm) if v else None
    else:valid=False;break
   args=list(reversed(stack))
   if not valid or len(args)!=7 or args[0]!=('ds',0) or not args[1] or args[1][0]!='imm' or not args[2] or args[2][0]!='ds' or args[3]!=('imm',2) or args[5:]!=[('imm',0),('imm',0)] or args[4] is None:continue
   record['candidates'].append(dict(start=start,args=args,instructions=[dict(offset=i.address,hex=bytes(i.bytes).hex()) for i in ins]))
  if record['candidates']:record.update(status='candidate',reason='Requires Ghidra instruction, function-body and incoming-flow verification')
  out.append(record)
 return out

def dsinit_offset_anchors(root, layout, rows):
    """Validate the known DSINIT prefix in a no-DCO 54-word record.

    Only the primary TM80 slot 1 form is supported. The three suffix words and
    the runtime semantics of its tables remain opaque. Every offset is checked;
    neither a plausible size nor an unrelated 54-element array is an anchor.
    """
    # DSINIT's offset/TMI fields and low-24-bit TMI indexing follow:
    # https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVparts.py#L207-L261
    # https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVblock.py#L5898-L5906
    # The anchored LV13/i386 corpus consistently places DSINIT at TM80 slot 1.
    # Require that position, exact saved shape and all three independent pairs.
    if len(rows) < 2:
        return []
    source = rows[1]
    td = layout.td(source['flat_id'])
    children = td.findall('TypeDesc')
    if td.get('Type') != 'RepeatedBlock' or td.get('NumRepeats') != '54' or len(children) != 1:
        return []
    child = children[0]
    if child.get('TypeID') is None or layout.td(int(child.get('TypeID'))).get('Type') != 'NumInt32':
        return []
    fills = root.findall(f"DFDS/Section/DataFill[@TypeID='{source['type_id']}']")
    if len(fills) > 1:
        raise ValueError('Ambiguous primary DSINIT saved fill')
    if not fills:
        return []
    repeated = fills[0].findall('RepeatedBlock')
    if len(repeated) != 1:
        return []
    leaves = list(repeated[0])
    if len(leaves) != 54 or any(leaf.tag != 'I32' or len(leaf) for leaf in leaves):
        return []
    values = [int(leaf.text) for leaf in leaves]
    if values[6] != 0 or values[8] != -1:
        return []
    anchors = []
    for table, count_field, offset_field, tmi_field in [
        ('hilite', 0, 1, 2), ('probe', 3, 4, 5), ('VI parameter', 12, 13, 14)
    ]:
        count = values[count_field]
        offset = values[offset_field]
        index = values[tmi_field] & 0xffffff
        if count <= 0 or offset < 0 or index >= len(rows):
            raise ValueError('Incomplete DSINIT offset anchors: ' + table)
        row = rows[index]
        if offset != row['offset']:
            raise ValueError('DSINIT offset anchor mismatch: ' + table)
        desc = layout.desc(row['flat_id'])
        if table == 'hilite':
            valid = desc['kind'] == 'RepeatedBlock' and desc.get('count') == count and desc['size'] == 8 * count
        elif table == 'probe':
            valid = desc['kind'] == 'RepeatedBlock' and desc.get('count') == 2 * count and desc['size'] == 8 * count
            if valid:
                child = layout.desc(desc['children'][0]['id'])
                valid = child['kind'] == 'NumInt32'
        else:
            valid = count == 1 and desc['kind'] == 'Cluster' and desc['size'] == 48 and len(desc.get('children', [])) == 12 and all(child['size'] == 4 for child in desc['children'])
        if not valid:
            raise ValueError('DSINIT table type/count mismatch: ' + table)
        anchors.append(dict(kind='DSINIT_offset_tmi', table=table, source_type_id=source['type_id'], source_tm80_slot=1, count_field=count_field, offset_field=offset_field, tmi_field=tmi_field, type_id=row['type_id'], offset=offset))
    return anchors


def extract(xml_path,panel_path,out,plan=None):
 xml_path=Path(xml_path);out=Path(out);out.mkdir(parents=True,exist_ok=True);root=parse(xml_path).getroot();layout=Layout(root);dcos=dco_records(root);rows=[];types=[];controls=[];reasons=[];status='unresolved';anchors=[];extent=0
 version=root.find('LVSR/Section/Version');general=root.find('VICD/Section/General')
 profile=version is not None and all(int(version.get(k,'-1'),0)==v for k,v in [('Major',13),('Minor',0),('Bugfix',0)]) and general is not None and general.get('CodeID')=='i386' and int(general.get('Version','0'),0)==0x13008000
 try:
  if not profile:raise ValueError('Outside validated LV13.0 i386 build profile')
  rows,extent=layout.rows(root)
  for d in dcos:
   v=d['values'];index=v.get('flagTMI',-1);off=v.get('flagDSO',-1)
   if index<0 or off<0:continue
   if index>=len(rows) or rows[index]['offset']!=off:raise ValueError(f'DCO flag anchor mismatch: {v.get("dcoIndex")}')
   anchors.append(dict(dco=v['dcoIndex'],type_id=rows[index]['type_id'],offset=off))
  if not anchors and not dcos:anchors=dsinit_offset_anchors(root,layout,rows)
  if not anchors:raise ValueError('No independent saved offset anchors')
  types=list(layout.cache.values());status='anchored_profile'
 except (ValueError,KeyError,IndexError,TypeError) as exc:reasons.append(str(exc));types=[]
 # Control names are type-record labels, not a guessed front-panel UID join.
 tm=root.find('TM80/Section');shift=int(tm.get('IndexShift')) if tm is not None else None
 for d in dcos:
  v=d['values'];c=dict(index=v.get('dcoIndex'),table_type=d['table_type'],label=None,type=None,flag_offset=v.get('flagDSO'),default_offset=v.get('defaultDataOffset'),transfer_offset=v.get('transferDataOffset'),size=v.get('dsSz'),source='DFDS DCO flagTMI -> TM80/VCTP value-type label; no UI UID inferred')
  try:
   if v['flagTMI']<0 or v.get('flagDSO',-1)<0:raise ValueError('Invalid DCO type-map reference')
   td=layout.td(layout.top[shift+v['flagTMI']]);children=td.findall('TypeDesc')
   if len(children)<2:raise ValueError('No value child')
   fid=int(children[1].get('TypeID'));value=layout.td(fid);c.update(label=value.get('Label'),type=value.get('Type'),value_flat_id=fid)
  except (ValueError,KeyError,IndexError,TypeError):c['unresolved']='Control value type mapping unavailable'
  controls.append(c)
 defaults={}
 for df in root.findall('DFDS/Section/DataFill'):
  tid=int(df.get('TypeID'));raw=E.tostring(df,encoding='utf-8');leaves=[dict(tag=c.tag,text=c.text) for c in df.iter() if isinstance(c.tag,str) and not len(c) and c.text and c.text.strip()]
  defaults[tid]=dict(type_id=tid,xml_sha256=sha(raw),preview=leaves[:8],preview_truncated=len(leaves)>8,meaning='Saved DFDS default, NOT proven current runtime value')
 facts=[]
 if status=='anchored_profile':
  for row in rows:
   if row['size']==0:continue
   row['name']=f"t{row['type_id']}_"+(row['label'] or row['kind']);row['default']=defaults.get(row['type_id'])
   facts.append(dict(offset=row['offset'],text=f"DS {row['name']} ({row['kind']}, {row['size']} bytes); "+(json.dumps(row['default'],ensure_ascii=True) if row['default'] else 'no saved default attached')))
  for c in controls:
   for key in ['flag_offset','default_offset','transfer_offset']:
    if c[key] is not None and c[key]>=0:facts.append(dict(offset=c[key],text=f"DCO {c['index']} {c['label'] or '(unnamed)'} {key}; recorded offset, label from VCTP"))
 links=[]
 for e in root.findall('LIds/Section/VIDS/DSDS'):
  name='/'.join(z.text or '' for z in e.findall('LinkSaveQualName/String'))
  for z in e.findall('LinkOffsetList/Offset'):
   off=int(z.text,0);links.append(dict(name=name,offset=off,status='saved_slot_only',meaning='Runtime instance binding and slot width unresolved'))
   if status=='anchored_profile':facts.append(dict(offset=off,text=f'Saved SubVI link slot: {name}; runtime instance binding and slot width unresolved'))
 calls=[]
 if plan:
  code=bytearray(Path(plan['code_path']).read_bytes())
  for patch in plan['changes']:
   if struct.unpack_from('<I',code,patch['offset'])[0]!=patch['old']:raise ValueError('Relocation source mismatch')
   struct.pack_into('<I',code,patch['offset'],patch['new'])
  if sha(code)!=plan['patched_sha256']:raise ValueError('Relocated code hash mismatch')
  calls=constant_frames(code,plan)
 data=dict(schema=1,profile='LV13_i386_packed_DS_empirical_v2',sources={str(xml_path):sha(xml_path.read_bytes())},layout=dict(status=status,reasons=reasons,extent=extent if status=='anchored_profile' else None,anchors=anchors,rows=rows if status=='anchored_profile' else [],types=types),controls=controls,rings=rings(root,panel_path,layout),links=links,offset_facts=facts,calls=calls,limitations=['Native offsets use an empirical build-specific layout profile checked against available independent saved DCO or DSINIT offset anchors.','Opaque handle slots and waveform extents do not imply known pointee/internal layouts.','Saved defaults do not establish current runtime values.','Ring enums remain attached to front-panel UIDs; no automatic native field binding.','No new runtime function signatures or dynamic SubVI instance bindings are asserted.'])
 if panel_path:data['sources'][str(panel_path)]=sha(Path(panel_path).read_bytes())
 if plan:data.update(base=plan['base'],code_size=plan['code_size'],patched_sha256=plan['patched_sha256'],dispatchers=plan['dispatchers'],relocation_plan=str(out/'plan.json'))
 (out/'facts.json').write_text(json.dumps(data,indent=2,ensure_ascii=True));return data
