// Synthetic archive preservation checks; no application inputs or target execution.
// @category LabVIEW.Tests
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;

public class TestResourceArchives extends GhidraScript {
    private String plan,validator;
    private void audit(String file)throws Exception {
        runScript(validator,new String[]{file,"audit-only"});
    }
    private void reject(String mode,String expected)throws Exception {
        Memory memory=currentProgram.getMemory();MemoryBlock block=memory.getBlock(toAddr(0x50000000L));
        byte[] original=new byte[(int)block.getSize()];memory.getBytes(block.getStart(),original);
        String name=block.getName(),comment=block.getComment();
        try {
            switch(mode) {
                case "corrupt":memory.setByte(block.getStart(),(byte)(memory.getByte(block.getStart())^1));break;
                case "missing":memory.removeBlock(block,monitor);break;
                case "writable":block.setWrite(true);break;
                case "executable":block.setExecute(true);break;
                case "unreadable":block.setRead(false);break;
                case "renamed":block.setName("Different_archive");break;
                case "split":memory.split(block,block.getEnd());break;
                default:throw new IllegalArgumentException(mode);
            }
            try {
                audit(plan);
            } catch(Exception error) {
                StringBuilder messages=new StringBuilder();for(Throwable cause=error;cause!=null;cause=cause.getCause())messages.append(cause.getMessage()).append('\n');
                if(messages.indexOf(expected)<0)throw new IOException("Wrong rejection for "+mode+": "+messages,error);
                println("RESOURCE_NEGATIVE_OK "+mode);return;
            }
            throw new IOException("Archive corruption was accepted: "+mode);
        } finally {
            // Nested Ghidra scripts share their caller's outer transaction, so a
            // nested rollback cannot isolate these tests. Restore each mutation
            // explicitly, then prove that the baseline still passes.
            switch(mode) {
                case "corrupt":memory.setByte(toAddr(0x50000000L),original[0]);break;
                case "missing":
                    block=memory.createInitializedBlock(name,toAddr(0x50000000L),new ByteArrayInputStream(original),original.length,monitor,false);
                    block.setRead(true);block.setWrite(false);block.setExecute(false);block.setComment(comment);break;
                case "writable":block.setWrite(false);break;
                case "executable":block.setExecute(false);break;
                case "unreadable":block.setRead(true);break;
                case "renamed":block.setName(name);break;
                case "split":memory.join(memory.getBlock(toAddr(0x50000000L)),memory.getBlock(toAddr(0x50000000L+original.length-1)));break;
            }
            audit(plan);
        }
    }
    public void run()throws Exception {
        String[] arguments=getScriptArgs();plan=arguments[0];validator=arguments[1];
        audit(plan);
        // Verify old plans on the first pass while their source files are present.
        if(arguments.length>2&&arguments[2].equals("legacy")) {
            JsonObject legacy=JsonParser.parseString(Files.readString(Path.of(plan))).getAsJsonObject();
            for(JsonElement element:legacy.getAsJsonArray("resources")) {
                element.getAsJsonObject().remove("size");element.getAsJsonObject().remove("address");
            }
            Path old=Path.of(plan).resolveSibling("legacy-plan.json");Files.writeString(old,legacy.toString());audit(old.toString());
            println("RESOURCE_LEGACY_OK");
        }
        reject("corrupt","Resource archive hash mismatch");
        reject("missing","Resource archive block missing");
        reject("writable","Resource archive permissions mismatch");
        reject("executable","Resource archive permissions mismatch");
        reject("unreadable","Resource archive permissions mismatch");
        reject("renamed","Resource archive identity/extent mismatch");
        reject("split","Resource archive identity/extent mismatch");
        audit(plan);println("RESOURCE_ARCHIVES_TEST_OK 7");
    }
}
