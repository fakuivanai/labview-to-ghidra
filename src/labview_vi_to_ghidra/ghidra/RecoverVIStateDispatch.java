// Original LV13 return-dispatch recovery, derived from the eight local VICD emitters.
// Changes analysis metadata only; never patches native instruction bytes.
// @category LabVIEW
import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.*;

public class RecoverVIStateDispatch extends GhidraScript {
  long n(JsonObject o, String key) {
    return o.get(key).getAsLong();
  }

  public void run() throws Exception {
    Path path = Path.of(getScriptArgs()[0]);
    JsonObject p = JsonParser.parseString(Files.readString(path)).getAsJsonObject();
    long base = n(p, "base");
    JsonArray report = new JsonArray();
    byte[] before = new byte[(int) n(p, "code_size")];
    currentProgram.getMemory().getBytes(toAddr(base), before);
    for (JsonElement e : p.getAsJsonArray("dispatchers")) {
      JsonObject d = e.getAsJsonObject();
      Address entry = toAddr(base + n(d, "entry")),
          branch = toAddr(base + n(d, "branch")),
          dispatch = toAddr(base + n(d, "dispatch")),
          epilogue = toAddr(base + n(d, "end"));
      Function f = getFunctionAt(entry);
      if (f == null) throw new Exception("Missing RunProc");
      Instruction ins = getInstructionAt(branch);
      if (ins == null || !ins.getMnemonicString().equals("RET"))
        throw new Exception("Dispatcher RET missing");
      if (f.isThunk()) f.setThunkedFunction(null);
      // Ordinary analysis may have made separate functions for the prologue/epilogue.
      for (Address a : new Address[] {dispatch, epilogue}) {
        Function owner = getFunctionAt(a);
        if (owner != null && !owner.equals(f))
          currentProgram.getFunctionManager().removeFunction(a);
      }
      ins.setFlowOverride(FlowOverride.BRANCH);
      ArrayList<Address> dests = new ArrayList<>();
      int index = 0;
      for (JsonElement t : d.getAsJsonArray("targets")) {
        Address a = toAddr(base + t.getAsLong()), word = toAddr(base + n(d, "table") + 4L * index);
        if (word.add(currentProgram.getMemory().getInt(word)).compareTo(a) != 0)
          throw new Exception("Table destination mismatch");
        dests.add(a);
        currentProgram
            .getReferenceManager()
            .addMemoryReference(branch, a, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
        currentProgram
            .getReferenceManager()
            .addMemoryReference(word, a, RefType.DATA, SourceType.USER_DEFINED, 0);
        createLabel(a, String.format("LV_state_%04d", index), false);
        setEOLComment(word, "state " + index + ": signed displacement from this word to " + a);
        if (getInstructionAt(word) != null)
          throw new Exception("Dispatcher table was disassembled as code");
        if (getDataAt(word) == null) createData(word, DWordDataType.dataType);
        index++;
      }
      for (Address a : new HashSet<Address>(dests)) disassemble(a);
      // Follow real instruction edges, excluding call targets. Do not assign intervening
      // embedded tables, separate callbacks, or subroutines to RunProc by address range.
      AddressSet body = new AddressSet();
      ArrayDeque<Address> queue = new ArrayDeque<>();
      queue.add(entry);
      queue.add(dispatch);
      queue.addAll(dests);
      while (!queue.isEmpty()) {
        monitor.checkCancelled();
        Address a = queue.remove();
        if (body.contains(a)) continue;
        if (a.getOffset() < base || a.getOffset() >= base + n(p, "code_size"))
          throw new Exception("State flow escapes VI: " + a);
        Instruction i = getInstructionAt(a);
        if (i == null) throw new Exception("Missing reachable instruction " + a);
        body.addRange(a, i.getMaxAddress());
        if (i.getFallThrough() != null) queue.add(i.getFallThrough());
        if (i.getFlowType().isJump()) for (Address target : i.getFlows()) queue.add(target);
      }
      for (Function other : currentProgram.getFunctionManager().getFunctions(true))
        if (!other.equals(f) && body.intersects(other.getBody()))
          throw new Exception("State body overlaps separate function " + other);
      f.setBody(body);
      new JumpTable(branch, dests, true, 0).writeOverride(f);
      setPlateComment(
          branch,
          "Verified LV13 state dispatch: RET consumes the pushed table destination. Analysis BRANCH"
              + " override; bytes unchanged. Original state index is the third stack argument. See"
              + " plan.json for exact state-index mapping; decompiler case labels need not be state"
              + " indices.");
      JsonObject r = new JsonObject();
      r.addProperty("states", dests.size());
      r.addProperty("unique_targets", new HashSet<Address>(dests).size());
      r.addProperty("body_bytes", body.getNumAddresses());
      DecompInterface dec = new DecompInterface();
      try {
        dec.openProgram(currentProgram);
        DecompileResults result = dec.decompileFunction(f, 45, monitor);
        r.addProperty("decompiled", result.decompileCompleted());
        r.addProperty("error", result.getErrorMessage());
        Path output = path.resolveSibling("decompiled");
        Files.createDirectories(output);
        Files.deleteIfExists(output.resolve("RunProc.c"));
        if (result.decompileCompleted()) {
          String c = result.getDecompiledFunction().getC();
          Files.writeString(
              output.resolve("RunProc.c"),
              "/* Recovered dispatcher; case labels are not guaranteed to be original state"
                  + " indices. */\n"
                  + c);
          r.addProperty("c_characters", c.length());
        } else
          Files.writeString(
              output.resolve("RunProc.error.txt"),
              "Dispatcher destinations and function body recovered; whole-function decompilation"
                  + " failed: "
                  + result.getErrorMessage());
      } finally {
        dec.dispose();
      }
      report.add(r);
    }
    byte[] after = new byte[before.length];
    currentProgram.getMemory().getBytes(toAddr(base), after);
    if (!Arrays.equals(before, after))
      throw new Exception("Dispatcher recovery changed code bytes");
    Files.writeString(
        path.resolveSibling("dispatcher-recovery.json"),
        new GsonBuilder().setPrettyPrinting().create().toJson(report));
    println("VI_DISPATCH_OK " + report);
  }
}
