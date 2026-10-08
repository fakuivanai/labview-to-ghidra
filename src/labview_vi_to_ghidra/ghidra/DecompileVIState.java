// Temporary analysis views of individual dispatcher entries; original project restored.
// These are fragments, not independent native functions and not recovered source.
// @category LabVIEW
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
public class DecompileVIState extends GhidraScript {
 public void run() throws Exception {
  Path path=Path.of(getScriptArgs()[0]);JsonObject p=JsonParser.parseString(Files.readString(path)).getAsJsonObject();long base=p.get("base").getAsLong();JsonObject d=p.getAsJsonArray("dispatchers").get(0).getAsJsonObject();
  byte[] code=new byte[p.get("code_size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(base),code);StringBuilder hash=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(code))hash.append(String.format("%02x",b&255));if(!hash.toString().equals(p.get("patched_sha256").getAsString()))throw new Exception("Plan/code hash mismatch");
  Function run=getFunctionAt(toAddr(base+d.get("entry").getAsLong()));AddressSet original=new AddressSet(run.getBody());Path out=path.resolveSibling("state-views");Files.createDirectories(out);Files.deleteIfExists(out.resolve("report.json"));JsonArray report=new JsonArray();
  try{
   run.setBody(new AddressSet(run.getEntryPoint()));
   for(String selection:getScriptArgs()[1].split(",")){
    int index=Integer.parseInt(selection);Path cPath=out.resolve(String.format("state_%04d.c",index));Files.deleteIfExists(cPath);Address entry=toAddr(base+d.getAsJsonArray("targets").get(index).getAsLong());AddressSet body=new AddressSet();ArrayDeque<Address> queue=new ArrayDeque<>();queue.add(entry);
    while(!queue.isEmpty()){
     Address a=queue.remove();if(body.contains(a))continue;if(!original.contains(a))throw new Exception("State escapes verified body "+a);
     Instruction i=getInstructionAt(a);if(i==null)throw new Exception("Missing state instruction "+a);body.addRange(a,i.getMaxAddress());if(i.getFallThrough()!=null)queue.add(i.getFallThrough());if(i.getFlowType().isJump())for(Address dest:i.getFlows())queue.add(dest);
    }
    JsonArray ranges=new JsonArray();for(AddressRange range:body){JsonArray pair=new JsonArray();pair.add(range.getMinAddress().getOffset()-base);pair.add(range.getMaxAddress().getOffset()-base);ranges.add(pair);}
    StringBuilder listing=new StringBuilder("; Original relocated instructions for dispatcher state "+index+".\n");
    for(Instruction i:currentProgram.getListing().getInstructions(body,true)){listing.append(i.getAddress()).append("  ").append(i.toString());for(Address dest:i.getFlows()){Function callee=getFunctionAt(dest);if(callee!=null)listing.append(" ; ").append(callee.getName());}listing.append('\n');}
    Files.writeString(out.resolve(String.format("state_%04d.asm",index)),listing.toString());
    Function view=currentProgram.getFunctionManager().createFunction("LV_state_view_"+index,entry,body,SourceType.USER_DEFINED);DecompInterface dec=new DecompInterface();JsonObject result=new JsonObject();result.addProperty("state",index);result.addProperty("entry",entry.toString());result.addProperty("body_bytes",body.getNumAddresses());result.add("code_relative_ranges",ranges);
    try{
     dec.openProgram(currentProgram);DecompileResults r=dec.decompileFunction(view,15,monitor);result.addProperty("decompiled",r.decompileCompleted());result.addProperty("error",r.getErrorMessage());
     if(r.decompileCompleted())Files.writeString(cPath,"/* Analysis fragment entered through LV13 dispatcher, not a native callable function.\n * EBP holds the runtime data-space pointer; EAX holds dispatcher argument 2.\n * The dispatcher has already saved six registers on the stack. Apparent stack\n * parameters, inferred return types and ABI in this view are not recovered signatures.\n * Unknown callee prototypes can omit real arguments from the C; consult the paired ASM.\n * State index "+index+", original address "+entry+". Native bytes unchanged. */\n"+r.getDecompiledFunction().getC());
    }finally{dec.dispose();currentProgram.getFunctionManager().removeFunction(entry);}
    report.add(result);
   }
  }finally{run.setBody(original);}
  byte[] after=new byte[code.length];currentProgram.getMemory().getBytes(toAddr(base),after);if(!Arrays.equals(code,after))throw new Exception("State views changed native bytes");
  Files.writeString(out.resolve("report.json"),new GsonBuilder().setPrettyPrinting().create().toJson(report));println("VI_STATE_VIEWS_OK "+report);
 }
}
