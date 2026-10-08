#!/usr/bin/env python3
"""Static smoke test of an independently generated three-state dispatcher."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,struct,subprocess,sys

from labview_vi_to_ghidra import vi_dispatch
from labview_vi_to_ghidra.toolchain import (
 GHIDRA_SCRIPT_DIRECTORY,acquire_job,ghidra_backend,resolve_ghidra_installation,
 snapshot_ghidra_scripts,
)

def digest(data):return hashlib.sha256(data).hexdigest()

def prepare(output,backend):
 if output.exists() and any(output.iterdir()):raise ValueError('Output must be new or empty')
 output.mkdir(parents=True,exist_ok=True)
 base=0x10000000;dispatch=100;targets=[48,64,80];table=dispatch+37;epilogue=table+4*len(targets)
 code=bytearray(b'\xcc'*(epilogue+8))
 code[:40]=bytes(40)
 code[40:45]=b'\xe9'+struct.pack('<i',dispatch-45)
 for index,target in enumerate(targets):
  code[target:target+10]=b'\xb8'+struct.pack('<I',index)+b'\xe9'+struct.pack('<i',epilogue-target-10)
 code[dispatch:dispatch+23]=vi_dispatch.PREFIX
 struct.pack_into('<I',code,dispatch+23,table)
 code[dispatch+27:table]=vi_dispatch.SUFFIX
 for index,target in enumerate(targets):struct.pack_into('<i',code,table+4*index,target-table-4*index)
 code[epilogue:epilogue+8]=vi_dispatch.EPILOGUE
 original=bytes(code);struct.pack_into('<I',code,dispatch+23,base+table);patched=bytes(code)
 (output/'native-code.bin').write_bytes(original)
 runtime=output/'runtime.bin';runtime.write_bytes(b'Generated smoke-test runtime placeholder; no runtime calls')
 resources=[];address=0x50000000
 for label,data in [('Original_VI',b'RSRC generated three-state preservation fixture'),('VI_Metadata_XML',b'<VI><Synthetic states="3"/></VI>')]:
  path=output/(label+'.bin');path.write_bytes(data)
  resources.append(dict(label=label,path=str(path),sha256=digest(data),size=len(data),address=address))
  address=(address+len(data)+0xfffff)&~0xfffff
 plan=dict(schema=1,vi='synthetic.vi',base=base,code_size=len(original),code_path=str(output/'native-code.bin'),program_name='native-code.bin',source_sha256=digest(original),patched_sha256=digest(patched),runtime=str(runtime),runtime_sha256=digest(runtime.read_bytes()),changes=[dict(offset=dispatch+23,old=table,new=base+table,kind='code_base',record=0,ident=0x20000,old_base=0)],targets=[],entries=[dict(name='RunProc',offset=40,evidence='Independently generated three-state dispatcher fixture')],unresolved=[],resources=resources,portable_export=str(output/'analysis.gzf'),ghidra_installation=resolve_ghidra_installation(backend))
 plan['dispatchers']=vi_dispatch.recognize_dispatchers(original,plan)
 assert plan['dispatchers'][0]['targets']==targets
 plan_path=output/'plan.json';plan_path.write_text(json.dumps(plan,indent=2))
 value={'kind':'synthetic','key':'state_fixture','value':'Independent generated fixture'}
 blob=(json.dumps(value,separators=(',',':'))+'\0').encode()
 blob_path=output/'records.bin';blob_path.write_bytes(blob)
 metadata=dict(schema=1,vi='synthetic.vi',relocation_plan=str(plan_path),sources={resources[1]['path']:resources[1]['sha256']},blob=str(blob_path),blob_sha256=digest(blob),records=[dict(kind='synthetic',key='state_fixture',offset=0,size=len(blob))],fields=[dict(name='Example',offset=0,size=1,type='NumUInt8',comment='Generated test field')],offsets=[dict(name='Example',offset=0,source='Generated fixture')])
 (output/'metadata.json').write_text(json.dumps(metadata,indent=2))
 scripts=output/'scripts'
 names=snapshot_ghidra_scripts(scripts,[GHIDRA_SCRIPT_DIRECTORY/(name+'.java') for name in ['ImportLabVIEW13','RecoverVIStateDispatch','ImportVIMetadata','ValidateExportLabVIEW13']])
 (output/'source-info.json').write_text(json.dumps({'scripts':{p.name:digest(p.read_bytes()) for p in scripts.iterdir()},'classes':names,'synthetic_code_sha256':plan['source_sha256'],'expected_relocated_sha256':plan['patched_sha256'],'states':3},indent=2))
 shutil.copy2(__file__,output/'runner.py')

def run(output,backend):
 plan_path=output/'plan.json';p=json.loads(plan_path.read_text());names=json.loads((output/'source-info.json').read_text())['classes']
 head,env,version=ghidra_backend(backend,output);(output/'ghidra-version.txt').write_text(version)
 projects=output/'project';projects.mkdir()
 flags=['-max-cpu','1','-noanalysis','-scriptPath',str(output/'scripts')]
 common=head+[str(projects),'VIAnalysis'];commands=[]
 def stage(name,argv,markers):
  commands.append(dict(stage=name,argv=argv))
  with (output/(name+'.log')).open('w') as log:r=subprocess.run(argv,env=env,stdout=log,stderr=subprocess.STDOUT)
  text=(output/(name+'.log')).read_text(errors='replace')
  if r.returncode or any(m not in text for m in markers):raise RuntimeError(name+' failed; see '+str(output/(name+'.log')))
 try:
  lock,limits=acquire_job()
  try:
   stage('import',common+['-import',str(output/'native-code.bin'),'-loader','BinaryLoader','-loader-baseAddr',hex(p['base']),'-processor','x86:LE:32:default','-cspec','windows']+flags+['-postScript',names['ImportLabVIEW13'],str(plan_path)],['failed=0'])
   stage('dispatch',common+['-process','native-code.bin']+flags+['-postScript',names['RecoverVIStateDispatch'],str(plan_path)],['VI_DISPATCH_OK'])
   stage('metadata',common+['-process','native-code.bin']+flags+['-postScript',names['ImportVIMetadata'],str(output/'metadata.json')],['VI_METADATA_OK'])
   stage('export',common+['-process','native-code.bin']+flags+['-postScript',names['ValidateExportLabVIEW13'],str(plan_path),'audit-only','-postScript',names['ImportVIMetadata'],str(output/'metadata.json'),'export'],['LABVIEW_AUDIT_OK','VI_METADATA_OK'])
  finally:lock.close()
  child_env=dict(env,PYTHONDONTWRITEBYTECODE='1')
  argv=[sys.executable,'-B','-m','labview_vi_to_ghidra.vi_state_views',str(plan_path)]
  commands.append(dict(stage='default-state-views',argv=argv))
  with (output/'default-state-views.log').open('w') as log:r=subprocess.run(argv,env=child_env,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError('Default state views failed; see '+str(output/'default-state-views.log'))
  lock,limits=acquire_job()
  try:
   stage('reopen-after-state-views',common+['-process','native-code.bin']+flags+['-postScript',names['ValidateExportLabVIEW13'],str(plan_path),'audit-only','-postScript',names['ImportVIMetadata'],str(output/'metadata.json'),'stateviews-reopen'],['LABVIEW_AUDIT_OK','VI_METADATA_OK'])
  finally:lock.close()
  reports=json.loads((output/'state-views/report.json').read_text());assert [r['state'] for r in reports]==[0,1,2]
  assert all(r['decompiled'] for r in reports),reports
  before=json.loads((output/'audit-export.json').read_text());after=json.loads((output/'audit-stateviews-reopen.json').read_text())
  for key in before:
   if key!='mode':assert before[key]==after[key],key
  audit=json.loads((output/'ghidra-audit.json').read_text());assert audit['saved_code_sha256']==p['patched_sha256'] and audit['dispatcher_states_verified']==3
  result=dict(status='passed',states=3,sampled_states=[r['state'] for r in reports],decompiled=3,native_bytes_preserved=True,metadata_and_function_signatures_preserved=True,reopened_after_state_views=True,synthetic_only=True)
  (output/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
 finally:(output/'commands.json').write_text(json.dumps(commands,indent=2))

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--ghidra',required=True,help='Ghidra installation directory, or flatpak')
 parser.add_argument('--output',type=Path,required=True,help='new or empty test output directory')
 args=parser.parse_args();output=args.output.expanduser().resolve()
 if output.exists() and (not output.is_dir() or any(output.iterdir())):parser.error('Output must be new or empty')
 try:
  prepare(output,args.ghidra)
  run(output,args.ghidra)
 except Exception as error:
  if output.is_dir():(output/'FAILED.json').write_text(json.dumps({'error':str(error)},indent=2))
  raise

if __name__=='__main__':main()
