"""Extract evidence only; no target execution and no inferred native aggregate layouts.
DCO field names are decoder interpretations from pylabview, pinned revision
https://github.com/mefistotelis/pylabview/blob/5f20e23de6a386021eb955c825cc43d221f09ff1/pylabview/LVparts.py
(decoder version and license are documented in README.md).
"""
from pathlib import Path
import xml.etree.ElementTree as E
import json, hashlib, re
def extract(xml_path, panel_path, output_dir, vi_name):
 D=Path(output_dir);D.mkdir(exist_ok=True,parents=True)
 x=Path(xml_path);p=Path(panel_path) if panel_path else None
 r=E.parse(x,parser=E.XMLParser(target=E.TreeBuilder(insert_comments=True))).getroot();panel=E.parse(p).getroot() if p else E.Element('NoPanel')
 flat=r.findall('VCTP/Section/TypeDesc'); top={int(e.get('Index')):int(e.get('FlatTypeID')) for e in r.findall('VCTP/Section/TopLevel/TypeDesc')}
 slice=r.find('DTHP/Section/TypeDescSlice');shift=int(slice.get('IndexShift')) if slice is not None else None
 def node(e):
  return {'tag':e.tag,'attributes':e.attrib,'text':(e.text or '').strip(),'children':[node(c) for c in e if isinstance(c.tag,str)]}
 records=[]
 def rec(kind,key,value):
  records.append({'kind':kind,'key':str(key),'value':value})
 for i,e in enumerate(flat):rec('VCTP_flat',i,node(e))
 rec('VCTP_top_to_flat','mapping',top)
 if r.find('CONP/Section') is not None:rec('CONP','logical_connector_only',node(r.find('CONP/Section')))
 for e in r.findall('DFDS/Section/DataFill'):rec('DFDS',e.get('TypeID'),node(e))
 for tag in ['LIvi','LIds','TM80','DTHP']:
  for i,e in enumerate(r.findall(tag+'/Section')):rec(tag,i,node(e))
 # Join only explicit connector numbers / connector-pane UID references.
 connections={};next_index=0
 for e in panel.findall('.//conPane/cons/SL__arrayElement'):
  index=int(e.get('index',str(next_index)),0);next_index=index+1
  connection=e.find('ConnectionDCO')
  if connection is not None:
   uid=connection.get('uid')
   assert uid not in connections, 'Duplicate connector UID'
   connections[uid]=index
 panels={}
 for e in panel.iter():
  if e.get('class')!='fPDCO':continue
  uid=e.get('uid');cn=e.findtext('conNum');con=int(cn) if cn is not None else connections.get(uid,-1)
  if uid in connections:assert con==connections[uid]
  if shift is None or not e.findtext('typeDesc'):continue
  heap=int(re.fullmatch(r'TypeID\((\d+)\)',e.findtext('typeDesc')).group(1));tid=shift+heap-1;fid=top[tid]
  labels=list(dict.fromkeys(z.findtext('textRec/text') for z in e.findall('ddo/partsList/SL__arrayElement') if z.get('class')=='label' and z.findtext('textRec/text')))
  info={'uid':uid,'connector':con,'heap_type':heap,'top_type':tid,'flat_type':fid,'type':flat[fid].get('Type'),'labels':labels}
  rec('FPHb_control',uid,info)
  if con>=0:assert con not in panels;panels[con]=info
 sizes={'Boolean':1,'NumInt8':1,'NumUInt8':1,'NumInt16':2,'NumUInt16':2,'NumInt32':4,'NumUInt32':4,'NumInt64':8,'NumUInt64':8,'NumFloat32':4,'NumFloat64':8}
 dcos=[];fields=[];offsets=[]
 for f in r.findall('DFDS/Section/DataFill'):
  if not any(c.tag is E.Comment and 'Table of Front Panel DCOs' in c.text for c in f):continue
  for c in f.findall('RepeatedBlock/Cluster'):
   values={};key=None
   for e in c:
    if e.tag is E.Comment:key=e.text.strip()
    elif key:values[key]=int(e.text) if e.tag!='Block' else e.text;key=None
   idx=values['dcoIndex'];control=panels.get(values['conNum']);label=(control['labels'][0].strip('"') if control and control['labels'] else 'unnamed')
   d={'index':idx,'source':f'DFDS/DataFill[@TypeID="{f.get("TypeID")}"]/RepeatedBlock/Cluster[{idx+1}]','values':values,'control':control};dcos.append(d);rec('DCO',idx,d)
   for k in ['flagDSO','defaultDataOffset','transferDataOffset','extraDataOffset','execDataPtrOffset','subTypeDSO']:
    if values[k]>=0:offsets.append({'name':f'DCO{idx}_{label}_{k}','offset':values[k],'source':d['source']})
   for k in ['defaultDataOffset','transferDataOffset']:
    off=values[k];size=values['dsSz']
    if off<0 or size<=0:continue
    assert size<100000
    typ=control['type'] if control and sizes.get(control['type'])==size else None
    fields.append({'name':f'DCO{idx}_{label}_{k}','offset':off,'size':size,'type':typ,'comment':json.dumps(d,ensure_ascii=True)})
 links=[]
 for e in r.findall('LIds/Section/VIDS/DSDS'):
  name='/'.join(z.text or '' for z in e.findall('LinkSaveQualName/String'))
  for z in e.findall('LinkOffsetList/Offset'):
   links.append({'name':name,'offset':int(z.text,0),'source':'LIds/Section/VIDS/DSDS/LinkOffsetList; slot width and instance identity unresolved'})
 for i,l in enumerate(links):offsets.append({'name':f'LINK{i}_{l["name"]}','offset':l['offset'],'source':l['source']})
 # Duplicate saved DCO tables share native fields but retain distinct copy-proc metadata.
 # Keep every raw/DCO record; merge only identical field declarations.
 unique_fields={}
 for field in fields:
  key=(field['name'],field['offset'],field['size'],field['type'])
  unique_fields.setdefault(key,field)
 fields=list(unique_fields.values())
 unique_offsets={}
 for off in offsets:
  key=(off['name'],off['offset']);unique_offsets.setdefault(key,off)
 offsets=list(unique_offsets.values())
 fields.sort(key=lambda f:f['offset'])
 for a,b in zip(fields,fields[1:]):assert a['offset']+a['size']<=b['offset']
 blob=bytearray();index=[]
 for record in records:
  data=(json.dumps(record,ensure_ascii=True,separators=(',',':'))+'\0').encode('ascii')
  index.append({'kind':record['kind'],'key':record['key'],'offset':len(blob),'size':len(data)})
  blob+=data
 (D/'records.bin').write_bytes(blob)
 plan={'schema':1,'vi':vi_name,'relocation_plan':str(D/'plan.json'),'sources':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in [x,p] if f is not None},'blob':str(D/'records.bin'),'blob_sha256':hashlib.sha256(blob).hexdigest(),'records':index,'fields':fields,'offsets':offsets,'links':links,'dcos':dcos,'flat_types':len(flat),'top_types':len(top),'limitations':['DS struct covers known front-panel default/transfer fields only; length is a lower bound, gaps unknown.','No synthetic runtime data-space allocation or initialization.','No callback ABI or aggregate native layout inferred from logical types.','Defaults retained as decoded trees; not treated as native bytes.','No Instance/N to extracted VINS file binding assumed.','DCO field semantics inherited from pinned third-party decoder; raw XML and original VI retained.']}
 (D/'metadata.json').write_text(json.dumps(plan,indent=2,ensure_ascii=True))
 print(json.dumps({'records':len(records),'fields':len(fields),'scalar_fields':sum(f['type'] is not None for f in fields),'dcos':len(dcos),'connector_matched':sum(d['control'] is not None for d in dcos),'links':len(links),'types':len(flat),'top_types':len(top)}))
 return plan
