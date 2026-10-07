#!/usr/bin/env python3
"""Export bounded pseudocode views from a generated dispatcher VI project.
No native code is run. Views are fragments, not recovered source or callable functions.
"""
import argparse,hashlib,json,subprocess,shutil,os
from pathlib import Path
W=Path(__file__).resolve().parent
if __package__:
 from .toolchain import acquire_job,ghidra_backend
else:
 from toolchain import acquire_job,ghidra_backend
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def select_states(count,selection='sample'):
 if count<1:raise ValueError('Dispatcher has no states')
 if selection=='sample':indices=sorted(i for i in {0,1,2,10,20,50,100,200,500,count//2,count-1} if 0<=i<count)
 elif selection=='all':indices=list(range(count))
 else:indices=[int(v) for v in selection.split(',')]
 if not indices or any(i<0 or i>=count for i in indices):raise ValueError(f'State indices must be in 0..{count-1}')
 return indices
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('plan',type=Path);ap.add_argument('--ghidra',help='Ghidra installation directory or flatpak; default: backend recorded in plan, then GHIDRA_HOME/PATH');ap.add_argument('--states',default='sample',help='comma-separated indices, sample, or all (potentially slow)');args=ap.parse_args();plan=args.plan.resolve();p=json.loads(plan.read_text());out=plan.parent
 try:resource_lock,limits=acquire_job()
 except (ValueError,OSError) as e:ap.error(str(e))
 if not p.get('dispatchers'):ap.error('This project has no recognized dispatcher')
 targets=p['dispatchers'][0]['targets'];n=len(targets)
 try:indices=select_states(n,args.states)
 except ValueError as e:ap.error(str(e))
 # Snapshot source and use content-addressed names to avoid Ghidra's shared script cache.
 scripts=out/'state-views-reproduce';scripts.mkdir(exist_ok=True);shutil.copy2(__file__,scripts/'vi_state_views.py');shutil.copy2(W/'toolchain.py',scripts/'toolchain.py');names={}
 for original in ['DecompileVIState','ValidateExportLabVIEW13','ImportVIMetadata']+(['ImportVIFacts'] if (out/'facts.json').exists() else []):
  src=W/(original+'.java');shutil.copy2(src,scripts/src.name);name=original+'_'+digest(src)[:12];(scripts/(name+'.java')).write_text(src.read_text().replace('public class '+original+' ','public class '+name+' '));names[original]=name+'.java'
 head,env,tool_files=ghidra_backend(args.ghidra or p.get('ghidra_installation'),out)
 (out/'state-views-ghidra-version.txt').write_text(tool_files)
 command=head+[str(out/'project'),'VIAnalysis','-process',p.get('program_name',Path(p['code_path']).name),'-max-cpu','1','-noanalysis','-scriptPath',str(scripts),'-postScript',names['DecompileVIState'],str(plan),','.join(map(str,indices)),'-postScript',names['ValidateExportLabVIEW13'],str(plan),'audit-only','-postScript',names['ImportVIMetadata'],str(out/'metadata.json'),'stateviews']
 if (out/'facts.json').exists():command+=['-postScript',names['ImportVIFacts'],str(out/'facts.json'),'stateviews']
 (out/'state-views-command.json').write_text(json.dumps({'argv':command,'plan_sha256':digest(plan),'sources':{str(f):digest(f) for f in scripts.iterdir()}},indent=2))
 with (out/'state-views.log').open('w') as log:r=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
 text=(out/'state-views.log').read_text(errors='replace')
 if r.returncode or any(marker not in text for marker in ['VI_STATE_VIEWS_OK','LABVIEW_AUDIT_OK','VI_METADATA_OK']):raise RuntimeError('State views failed; see '+str(out/'state-views.log'))
 a=json.loads((out/'audit-export.json').read_text());b=json.loads((out/'audit-stateviews.json').read_text())
 for key in ['code_sha256','metadata_sha256','records','fields','scalar_fields','function_signatures_sha256']:
  if a[key]!=b[key]:raise RuntimeError('State view round-trip mismatch: '+key)
 if (out/'facts.json').exists():
  if 'VI_FACTS_OK' not in text:raise RuntimeError('State-view facts audit failed')
  before=json.loads((out/'facts-audit-apply.json').read_text());after=json.loads((out/'facts-audit-stateviews.json').read_text())
  for key in before:
   if key!='mode' and before[key]!=after[key]:raise RuntimeError('State-view facts changed: '+key)
 resource_lock.close()
 report=json.loads((out/'state-views/report.json').read_text());print(json.dumps({'views':len(report),'decompiled':sum(r['decompiled'] for r in report),'directory':str(out/'state-views')},indent=2))
if __name__=='__main__':main()
