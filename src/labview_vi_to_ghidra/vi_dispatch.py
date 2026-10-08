"""Strict recognition of the LV13 i386 return-dispatch emitter.
Original structural recognizer for the documented VICD emitter profile.
All offsets are code-relative. Each signed table word is relative to its own address.
"""
import struct
PREFIX=bytes.fromhex('558b6c240853515256578b4424208b742424c1e60256be')
SUFFIX=bytes.fromhex('0334240336893424c390')
EPILOGUE=bytes.fromhex('5f5e5a595b5dc390')
def scan(code,require=False):
 if len(code)<45 or code[40]!=0xe9:
  if require:raise ValueError('Missing dispatcher trampoline')
  return None
 dispatch=45+struct.unpack_from('<i',code,41)[0]
 if dispatch<45 or code[dispatch:dispatch+23]!=PREFIX or code[dispatch+27:dispatch+37]!=SUFFIX:
  if require:raise ValueError('Unsupported trampoline dispatcher profile')
  return None
 table=dispatch+37;targets=[];at=table
 while at+4<=len(code):
  if code[at:at+8]==EPILOGUE:break
  target=at+struct.unpack_from('<i',code,at)[0]
  if not 45<=target<dispatch:raise ValueError(f'Invalid dispatcher destination at {at:#x}')
  targets.append(target);at+=4
 if not targets or code[at:at+8]!=EPILOGUE:raise ValueError('Truncated dispatcher table / missing epilogue')
 return dict(profile='LV13_i386_ret_relative_table_v1',entry=40,dispatch=dispatch,branch=dispatch+35,table=table,end=at,targets=targets)
def recognize_dispatchers(code,plan):
 d=scan(code,require=any(e['offset']==40 and e['name']=='RunProc' for e in plan['entries']))
 if d is None:return []
 if not any(e['offset']==40 and e['name']=='RunProc' for e in plan['entries']):raise ValueError('Dispatcher has no verified RunProc callback')
 reloc=[c for c in plan['changes'] if c['offset']==d['dispatch']+23]
 if len(reloc)!=1 or reloc[0]['kind']!='code_base' or reloc[0]['new']!=plan['base']+d['table']:raise ValueError('Dispatcher table pointer lacks matching relocation')
 d['table_relocation_record']=reloc[0]['record']
 return [d]
