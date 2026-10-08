// Independently verify saved Ghidra programs against their relocation plans and export GZF.
// @category LabVIEW
import java.io.*;
import java.util.*;
import ghidra.program.model.pcode.HighFunction;
import java.nio.file.*;
import java.security.MessageDigest;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.GzfExporter;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
public class ValidateExportLabVIEW13 extends GhidraScript {
 private static String hash(byte[] data)throws Exception{
  StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(data))out.append(String.format("%02x",b&255));return out.toString();
 }
 private JsonArray verifyResources(JsonObject plan)throws Exception{
  JsonArray verified=new JsonArray();HashSet<String> names=new HashSet<>();long address=0x50000000L;
  for(JsonElement element:plan.getAsJsonArray("resources")){
   JsonObject resource=element.getAsJsonObject();String name=resource.get("label").getAsString().replaceAll("[^A-Za-z0-9_]","_");
   if(name.isEmpty()||!names.add(name))throw new IOException("Duplicate/invalid resource archive name: "+name);
   // Older plans lack extents; they need the original source file only to obtain
   // its length. New plans verify archives without depending on that file.
   long size=resource.has("size")?resource.get("size").getAsLong():Files.size(Path.of(resource.get("path").getAsString()));
   if(size<=0||size>Integer.MAX_VALUE||address+size>0x60000000L)throw new IOException("Resource archive overlaps reserved addresses/invalid extent: "+name);
   if(resource.has("address")&&resource.get("address").getAsLong()!=address)throw new IOException("Resource archive address differs from canonical allocation: "+name);
   MemoryBlock block=currentProgram.getMemory().getBlock(toAddr(address));
   if(block==null)throw new IOException("Resource archive block missing: "+name);
   if(!block.getName().equals(name)||!block.getStart().equals(toAddr(address))||block.getSize()!=size||!block.isInitialized())throw new IOException("Resource archive identity/extent mismatch: "+name);
   if(!block.isRead()||block.isWrite()||block.isExecute())throw new IOException("Resource archive permissions mismatch: "+name);
   byte[] data=new byte[(int)size];if(currentProgram.getMemory().getBytes(block.getStart(),data)!=data.length)throw new IOException("Resource archive truncated: "+name);
   String savedHash=hash(data);if(!savedHash.equals(resource.get("sha256").getAsString()))throw new IOException("Resource archive hash mismatch: "+name);
   JsonObject record=new JsonObject();record.addProperty("label",name);record.addProperty("address",address);record.addProperty("size",size);record.addProperty("sha256",savedHash);verified.add(record);
   address=(address+size+0xfffffL)&~0xfffffL;
  }
  return verified;
 }
 public void run() throws Exception {
  File file=new File(getScriptArgs()[0]);JsonObject p=JsonParser.parseString(Files.readString(file.toPath())).getAsJsonObject();
  long base=p.get("base").getAsLong();int size=p.get("code_size").getAsInt();byte[] bytes=new byte[size];currentProgram.getMemory().getBytes(toAddr(base),bytes);
  StringBuilder hash=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))hash.append(String.format("%02x",b&255));
  if(!hash.toString().equals(p.get("patched_sha256").getAsString()))throw new IOException("Saved program hash mismatch");
  JsonArray resources=verifyResources(p);
  int checked=0,notDisassembled=0;
  for(JsonElement e:p.getAsJsonArray("changes")){
   JsonObject c=e.getAsJsonObject();if(!c.get("kind").getAsString().equals("runtime_rel32"))continue;
   long off=c.get("offset").getAsLong();Address target=toAddr(c.get("target").getAsLong());
   Instruction ins=getInstructionAt(toAddr(base+off-1));
   if(ins==null){notDisassembled++;continue;}
   boolean found=false;for(Address flow:ins.getFlows())if(flow.equals(target))found=true;
   if(!found)throw new IOException("Call flow mismatch at "+ins.getAddress());
   Function f=getFunctionAt(target);if(f==null||!f.isThunk()||!f.getThunkedFunction(true).isExternal())throw new IOException("Missing external thunk at "+target);
   checked++;
  }
  for(JsonElement e:p.getAsJsonArray("entries")){JsonObject entry=e.getAsJsonObject();if(getFunctionAt(toAddr(base+entry.get("offset").getAsLong()))==null)throw new IOException("Missing callback");}
  JsonObject audit=new JsonObject();audit.addProperty("saved_code_sha256",hash.toString());audit.addProperty("runtime_calls_with_verified_flow_and_external_thunk",checked);audit.addProperty("runtime_call_sites_not_disassembled",notDisassembled);audit.addProperty("callback_functions_present",p.getAsJsonArray("entries").size());
  audit.add("resource_archives",resources);audit.addProperty("resource_archives_verified",resources.size());
  int states=0;long recoveredBytes=0;
  if(p.has("dispatchers"))for(JsonElement element:p.getAsJsonArray("dispatchers")){
   JsonObject d=element.getAsJsonObject();Address branch=toAddr(base+d.get("branch").getAsLong());Function f=getFunctionAt(toAddr(base+d.get("entry").getAsLong()));
   Instruction ins=getInstructionAt(branch);if(ins==null||ins.getFlowOverride()!=FlowOverride.BRANCH||!f.getBody().contains(branch)||f.isThunk())throw new IOException("Lost dispatcher flow/body override");
   Namespace overrides=HighFunction.findOverrideSpace(f);if(overrides==null)throw new IOException("Missing switch overrides");
   Namespace ns=currentProgram.getSymbolTable().getNamespace("jmp_"+branch,overrides);if(ns==null)throw new IOException("Missing dispatcher override namespace");
   HashSet<Address> expected=new HashSet<>(),actual=new HashSet<>(Arrays.asList(ins.getFlows()));int index=0;
   for(JsonElement target:d.getAsJsonArray("targets")){
    Address a=toAddr(base+target.getAsLong()),word=toAddr(base+d.get("table").getAsLong()+4L*index);expected.add(a);
    if(!f.getBody().contains(a)||getInstructionAt(a)==null||!word.add(currentProgram.getMemory().getInt(word)).equals(a))throw new IOException("Bad saved state destination "+index);
    if(currentProgram.getSymbolTable().getSymbol("case_"+index,a,ns)==null)throw new IOException("Lost jump-table override case "+index);
    if(getDataAt(word)==null||getInstructionAt(word)!=null)throw new IOException("Lost dispatcher table data");
    index++;
   }
   if(!expected.equals(actual))throw new IOException("Dispatcher destination set differs from plan");
   states+=index;recoveredBytes+=f.getBody().getNumAddresses();
  }
  audit.addProperty("dispatcher_states_verified",states);audit.addProperty("dispatcher_body_bytes",recoveredBytes);
  File gzf=p.has("portable_export")?new File(p.get("portable_export").getAsString()):new File(file.getParentFile(),p.get("vi").getAsString()+".gzf");
  if(getScriptArgs().length<2 && !new GzfExporter().export(gzf,currentProgram.getDomainFile(),monitor))throw new IOException("GZF export failed");
  audit.addProperty("gzf",gzf.toString());Files.writeString(new File(file.getParentFile(),"ghidra-audit.json").toPath(),new GsonBuilder().setPrettyPrinting().create().toJson(audit));println("LABVIEW_AUDIT_OK "+audit.toString());
 }
}
