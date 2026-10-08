// Apply a verified LV13 relocation plan to a freshly imported original raw code BIN.
// Original script; semantics derived from local lvrt.dll RVA 0x170690.
// Never executes any target code.
// @category LabVIEW
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class ImportLabVIEW13 extends GhidraScript {
    private static String hash(byte[] b) throws Exception {
        StringBuilder s=new StringBuilder();
        for(byte v:MessageDigest.getInstance("SHA-256").digest(b)) s.append(String.format("%02x",v&255));
        return s.toString();
    }
    private static long num(JsonObject o,String k){return o.get(k).getAsLong();}
    private static String str(JsonObject o,String k){return o.get(k).getAsString();}
    private static String safe(String s){return s.replaceAll("[^A-Za-z0-9_]","_");}
    public void run() throws Exception {
        String[] args=getScriptArgs();
        File planFile=args.length>0?new File(args[0]):askFile("Select LabVIEW plan.json","Import");
        JsonObject plan=JsonParser.parseString(Files.readString(planFile.toPath())).getAsJsonObject();
        if(plan.get("schema").getAsInt()!=1) throw new IOException("Unsupported plan schema");
        if(!currentProgram.getLanguageID().toString().equals("x86:LE:32:default")) throw new IOException("Expected x86:LE:32:default");
        long base=num(plan,"base");int length=plan.get("code_size").getAsInt();
        if(currentProgram.getMemory().getBlock(toAddr(base))==null || !currentProgram.getMemory().getBlock(toAddr(base)).getStart().equals(toAddr(base))) throw new IOException("Import original BIN at plan base 0x"+Long.toHexString(base));
        Memory mem=currentProgram.getMemory();byte[] before=new byte[length];
        mem.getBytes(toAddr(base),before);
        if(!hash(before).equals(str(plan,"source_sha256"))) throw new IOException("Code hash mismatch: expected ORIGINAL unpatched BIN");
        if(!hash(Files.readAllBytes(Path.of(str(plan,"runtime")))).equals(str(plan,"runtime_sha256"))) throw new IOException("Runtime hash mismatch");
        if(currentProgram.getListing().getInstructions(true).hasNext()) throw new IOException("Use a fresh import; decline automatic analysis before running this script");
        // Preflight all old words and resources before changing the program.
        for(JsonElement e:plan.getAsJsonArray("changes")) {
            JsonObject c=e.getAsJsonObject();long off=num(c,"offset");
            if(off<0||off+4>length||Integer.toUnsignedLong(mem.getInt(toAddr(base+off)))!=num(c,"old")) throw new IOException("Patch precondition failed at "+off);
        }
        // Keep the exact bytes that passed preflight. Reopening a source file after
        // hashing it would allow changed bytes to enter the archive unnoticed.
        ArrayList<byte[]> resourceBytes=new ArrayList<>();
        HashSet<String> resourceNames=new HashSet<>();long resourceBase=0x50000000L;
        long runtimeLow=Long.MAX_VALUE,runtimeHigh=0;
        for(JsonElement target:plan.getAsJsonArray("targets")){
            long at=num(target.getAsJsonObject(),"address");runtimeLow=Math.min(runtimeLow,at&~4095L);runtimeHigh=Math.max(runtimeHigh,(at+4096)&~4095L);
        }
        for(JsonElement e:plan.getAsJsonArray("resources")) {
            JsonObject r=e.getAsJsonObject();String name=safe(str(r,"label"));
            if(name.isEmpty()||!resourceNames.add(name)||mem.getBlock(name)!=null)throw new IOException("Duplicate/invalid resource archive name: "+name);
            byte[] data=Files.readAllBytes(Path.of(str(r,"path")));
            if(data.length==0||!hash(data).equals(str(r,"sha256")))throw new IOException("Resource hash mismatch/empty archive: "+name);
            if(r.has("size")&&num(r,"size")!=data.length)throw new IOException("Resource archive source extent mismatch: "+name);
            if(r.has("address")&&num(r,"address")!=resourceBase)throw new IOException("Resource archive address differs from canonical allocation: "+name);
            long end=resourceBase+data.length;
            if(end>0x60000000L)throw new IOException("Resource archive overlaps reserved metadata addresses: "+name);
            Address first=toAddr(resourceBase),last=toAddr(end-1);
            for(MemoryBlock existing:mem.getBlocks())if(existing.getStart().getAddressSpace().equals(first.getAddressSpace())&&existing.getStart().compareTo(last)<=0&&existing.getEnd().compareTo(first)>=0)throw new IOException("Resource archive overlaps existing memory: "+name);
            if(runtimeLow<end&&runtimeHigh>resourceBase)throw new IOException("Resource archive overlaps runtime targets: "+name);
            resourceBytes.add(data);resourceBase=(end+0xfffffL)&~0xfffffL;
        }
        int tx=currentProgram.startTransaction("Import verified LabVIEW resources and relocations");boolean success=false;
        try {
            for(JsonElement e:plan.getAsJsonArray("changes")) {
                JsonObject c=e.getAsJsonObject();Address at=toAddr(base+num(c,"offset"));
                mem.setInt(at,(int)num(c,"new"));
                setEOLComment(at,"LV13 "+str(c,"kind")+"; record "+num(c,"record")+"; ident 0x"+Long.toHexString(num(c,"ident"))+(c.has("symbol")?" -> "+str(c,"symbol"):""));
            }
            byte[] after=new byte[length];mem.getBytes(toAddr(base),after);
            if(!hash(after).equals(str(plan,"patched_sha256")))throw new IOException("Patched hash mismatch");
            JsonArray targets=plan.getAsJsonArray("targets");
            if(targets.size()>0){
                long low=Long.MAX_VALUE,high=0;
                for(JsonElement e:targets){long a=num(e.getAsJsonObject(),"address");low=Math.min(low,a&~4095L);high=Math.max(high,(a+4096)&~4095L);}
                MemoryBlock block=mem.createUninitializedBlock("LVRT_symbolic_targets",toAddr(low),high-low,false);
                block.setRead(true);block.setWrite(false);block.setExecute(true);
                block.setComment("Analysis-only uninitialized placeholders at verified preferred-base LVRT addresses. No runtime bytes or invented instructions. Functions thunk to externals; prototypes unresolved.");
                for(JsonElement e:targets){
                    JsonObject t=e.getAsJsonObject();Address a=toAddr(num(t,"address"));String name=safe(str(t,"name"));
                    ExternalLocation loc=currentProgram.getExternalManager().addExtFunction("lvrt.dll",name,a,SourceType.USER_DEFINED);
                    Function f=currentProgram.getFunctionManager().createFunction(name,a,new AddressSet(a),SourceType.USER_DEFINED);
                    f.setThunkedFunction(loc.getFunction());
                    setPlateComment(a,"Verified LVRT address; IDs "+t.get("aliases")+". Prototype not recovered. Runtime SHA256 "+str(plan,"runtime_sha256"));
                }
            }
            resourceBase=0x50000000L;int resourceIndex=0;
            for(JsonElement e:plan.getAsJsonArray("resources")){
                JsonObject r=e.getAsJsonObject();byte[] data=resourceBytes.get(resourceIndex++);
                MemoryBlock block=mem.createInitializedBlock(safe(str(r,"label")),toAddr(resourceBase),new ByteArrayInputStream(data),data.length,monitor,false);
                block.setRead(true);block.setWrite(false);block.setExecute(false);
                block.setComment("Analysis-only archive at an artificial address; NOT the runtime data space. Source: "+str(r,"path"));
                createBookmark(toAddr(resourceBase),"LabVIEW resource",str(r,"path"));resourceBase=(resourceBase+data.length+0xfffff)&~0xfffffL;
            }
            for(JsonElement e:plan.getAsJsonArray("entries")){
                JsonObject entry=e.getAsJsonObject();Address a=toAddr(base+num(entry,"offset"));disassemble(a);
                Function f=getFunctionAt(a);if(f==null)f=createFunction(a,safe(str(entry,"name")));
                if(f==null)throw new IOException("Could not create entry function at "+a);
                f.setName(safe(str(entry,"name")),SourceType.USER_DEFINED);
                setPlateComment(a,"LabVIEW callback: "+str(entry,"evidence"));
            }
            for(JsonElement e:plan.getAsJsonArray("unresolved")){
                JsonObject u=e.getAsJsonObject();Address a=u.has("offset")?toAddr(base+num(u,"offset")):toAddr(base);
                createBookmark(a,"UNRESOLVED LabVIEW relocation",u.toString());
            }
            setPlateComment(toAddr(base),"LabVIEW 13 analysis-only import of "+str(plan,"vi")+". Decoder header is zeroed; verified offset-40 entry bytes are restored where applicable. Runtime patches resolved; dynamic VI/data-space binding is not reconstructed. Plan: "+planFile);
            success=true;
        } finally {currentProgram.endTransaction(tx,success);}
        analyzeAll(currentProgram);
        println("Applied "+plan.getAsJsonArray("changes").size()+" writes; unresolved records: "+plan.getAsJsonArray("unresolved").size());
        DecompInterface decompiler=new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);int ok=0,failed=0;
            File output=new File(planFile.getParentFile(),"decompiled");output.mkdirs();
            for(JsonElement e:plan.getAsJsonArray("entries")){
                JsonObject en=e.getAsJsonObject();Function f=getFunctionAt(toAddr(base+num(en,"offset")));
                DecompileResults r=decompiler.decompileFunction(f,60,monitor);
                if(r.decompileCompleted()){
                    Files.writeString(new File(output,safe(str(en,"name"))+".c").toPath(),"/* Ghidra analysis output. Runtime prototypes and dynamic data-space binding unresolved. */\n"+r.getDecompiledFunction().getC());ok++;
                }else{Files.writeString(new File(output,safe(str(en,"name"))+".error.txt").toPath(),r.getErrorMessage());failed++;}
            }
            String result="decompiled="+ok+" failed="+failed+"\n";println(result);Files.writeString(new File(planFile.getParentFile(),"ghidra-validation.txt").toPath(),result);
        } finally {decompiler.dispose();}
    }
}
