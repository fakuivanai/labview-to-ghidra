// Original importer of recorded/anchored VI facts. No executable bytes or ABI edits.
// @category LabVIEW
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.GzfExporter;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ImportVIFacts extends GhidraScript {
  final CategoryPath CAT = new CategoryPath("/LabVIEW/Recorded_facts");
  Map<Integer, JsonObject> defs = new HashMap<>();
  Map<Integer, DataType> built = new HashMap<>();
  DataTypeManager dtm;
  long base;
  JsonObject p;

  String safe(String s) {
    return s.replaceAll("[^A-Za-z0-9_]", "_");
  }

  String str(JsonObject o, String k) {
    return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : "";
  }

  long n(JsonObject o, String k) {
    return o.get(k).getAsLong();
  }

  String hash(byte[] b) throws Exception {
    StringBuilder s = new StringBuilder();
    for (byte x : MessageDigest.getInstance("SHA-256").digest(b))
      s.append(String.format("%02x", x & 255));
    return s.toString();
  }

  String signatures() {
    StringBuilder s = new StringBuilder();
    for (Function f : currentProgram.getFunctionManager().getFunctions(true))
      s.append(f.getEntryPoint()).append(':').append(f.getSignature()).append('\n');
    return s.toString();
  }

  DataType primitive(String kind) {
    switch (kind) {
      case "Boolean":
      case "NumUInt8":
        return ByteDataType.dataType;
      case "NumInt8":
        return SignedByteDataType.dataType;
      case "NumUInt16":
        return UnsignedShortDataType.dataType;
      case "NumInt16":
        return ShortDataType.dataType;
      case "NumUInt32":
        return UnsignedIntegerDataType.dataType;
      case "NumInt32":
        return IntegerDataType.dataType;
      case "NumUInt64":
        return UnsignedLongLongDataType.dataType;
      case "NumInt64":
        return LongLongDataType.dataType;
      case "NumFloat32":
        return FloatDataType.dataType;
      case "NumFloat64":
        return DoubleDataType.dataType;
      default:
        return null;
    }
  }

  DataType type(int id) throws Exception {
    if (built.containsKey(id)) return built.get(id);
    JsonObject d = defs.get(id);
    int size = (int) n(d, "size");
    if (size <= 0) throw new Exception("Unexpected zero-sized type use");
    String name = "T_" + id;
    DataType value = null;
    String rep = str(d, "representation");
    if (rep.equals("scalar")) value = primitive(str(d, "scalar"));
    if (rep.equals("packed_cluster")) {
      StructureDataType st = new StructureDataType(CAT, name, size);
      st.setDescription("Packed layout under the anchored LV13 build profile; " + str(d, "source"));
      for (JsonElement e : d.getAsJsonArray("children")) {
        JsonObject c = e.getAsJsonObject();
        if (n(c, "size") > 0)
          st.replaceAtOffset(
              (int) n(c, "offset"),
              type((int) n(c, "id")),
              (int) n(c, "size"),
              safe(str(c, "name")),
              "Explicit child order; profile-computed byte offset");
      }
      value = st;
    } else if (rep.equals("repeat") || rep.equals("typedef")) {
      JsonObject c = d.getAsJsonArray("children").get(0).getAsJsonObject();
      DataType child = type((int) n(c, "id"));
      value =
          rep.equals("repeat")
              ? new ArrayDataType(child, (int) n(d, "count"), child.getLength())
              : child;
    }
    if (value == null) value = new ArrayDataType(Undefined1DataType.dataType, size, 1);
    if (!rep.equals("packed_cluster")) value = new TypedefDataType(CAT, name, value);
    value = dtm.resolve(value, DataTypeConflictHandler.DEFAULT_HANDLER);
    if (value.getLength() != size) throw new Exception("Type extent mismatch " + id);
    built.put(id, value);
    return value;
  }

  String ringName(JsonObject r) {
    return "Ring_"
        + safe(str(r, "uid"))
        + "_"
        + safe(
            r.getAsJsonArray("labels").size() > 0
                ? r.getAsJsonArray("labels").get(0).getAsString()
                : "unnamed");
  }

  boolean ebpInvariant(Function f, JsonObject dispatcher) {
    Address ebp = currentProgram.getRegister("EBP").getAddress();
    long prologue = base + n(dispatcher, "dispatch") + 1,
        epilogue = base + n(dispatcher, "end") + 5;
    for (Instruction i : currentProgram.getListing().getInstructions(f.getBody(), true))
      for (PcodeOp op : i.getPcode()) {
        Varnode output = op.getOutput();
        if (output != null
            && output.isRegister()
            && output.getAddress().equals(ebp)
            && i.getAddress().getOffset() != prologue
            && i.getAddress().getOffset() != epilogue) return false;
      }
    return true;
  }

  boolean frameValid(JsonObject frame, Function run) throws Exception {
    long start = base + n(frame, "start");
    JsonArray ins = frame.getAsJsonArray("instructions");
    long end = base + n(ins.get(ins.size() - 1).getAsJsonObject(), "offset");
    for (JsonElement el : ins) {
      JsonObject row = el.getAsJsonObject();
      Address at = toAddr(base + n(row, "offset"));
      Instruction i = getInstructionAt(at);
      if (i == null || !run.getBody().contains(at)) return false;
      StringBuilder hex = new StringBuilder();
      for (byte b : i.getBytes()) hex.append(String.format("%02x", b & 255));
      if (!hex.toString().equals(str(row, "hex"))) return false;
      if (at.getOffset() != start)
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(at))
          if (ref.getReferenceType().isFlow()
              && (ref.getFromAddress().getOffset() < start
                  || ref.getFromAddress().getOffset() > end)) return false;
    }
    return true;
  }

  String control(long index) {
    TreeSet<String> found = new TreeSet<>();
    for (JsonElement e : p.getAsJsonArray("controls")) {
      JsonObject c = e.getAsJsonObject();
      if (n(c, "index") == index) found.add(str(c, "label") + " (" + str(c, "type") + ")");
    }
    return found.size() == 1 ? found.first() : "label unresolved/ambiguous";
  }

  void add(Map<Address, LinkedHashSet<String>> comments, Address at, String text) {
    comments.computeIfAbsent(at, k -> new LinkedHashSet<>()).add(text);
  }

  public void run() throws Exception {
    Path file = Path.of(getScriptArgs()[0]), dir = file.getParent();
    String mode = getScriptArgs().length > 1 ? getScriptArgs()[1] : "apply";
    boolean apply = mode.equals("apply");
    byte[] blob = Files.readAllBytes(file);
    p = JsonParser.parseString(new String(blob, StandardCharsets.UTF_8)).getAsJsonObject();
    base = n(p, "base");
    byte[] code = new byte[(int) n(p, "code_size")];
    currentProgram.getMemory().getBytes(toAddr(base), code);
    if (!hash(code).equals(str(p, "patched_sha256")))
      throw new Exception("Facts code hash mismatch");
    String signaturesBefore = signatures();
    dtm = currentProgram.getDataTypeManager();
    JsonObject layout = p.getAsJsonObject("layout");
    boolean anchored = str(layout, "status").equals("anchored_profile");
    for (JsonElement e : layout.getAsJsonArray("types")) {
      JsonObject d = e.getAsJsonObject();
      defs.put((int) n(d, "id"), d);
    }
    Path bindingsFile = dir.resolve("facts-bindings.json");
    JsonObject binding = new JsonObject();
    if (apply) {
      for (Map.Entry<String, JsonElement> source : p.getAsJsonObject("sources").entrySet())
        if (!hash(Files.readAllBytes(Path.of(source.getKey())))
            .equals(source.getValue().getAsString()))
          throw new Exception("Facts source hash mismatch");
      if (anchored) {
        StructureDataType ds =
            new StructureDataType(CAT, "VI_DS_AnchoredProfile", (int) n(layout, "extent"));
        ds.setDescription(
            "Empirical LV13 i386 packed layout, checked against independent saved offset anchors,"
                + " including DCO flags and the narrowly supported DSINIT form. NOT runtime"
                + " allocation or initialized bytes. Opaque slots have unknown pointees; defaults"
                + " are saved values only.");
        for (JsonElement e : layout.getAsJsonArray("rows")) {
          JsonObject r = e.getAsJsonObject();
          if (n(r, "size") == 0) continue;
          ds.replaceAtOffset(
              (int) n(r, "offset"),
              type((int) n(r, "flat_id")),
              (int) n(r, "size"),
              safe(str(r, "name")),
              r.toString());
        }
        dtm.resolve(ds, DataTypeConflictHandler.DEFAULT_HANDLER);
      }
      for (JsonElement e : p.getAsJsonArray("rings")) {
        JsonObject r = e.getAsJsonObject();
        if (!str(r, "status").equals("recorded")) continue;
        EnumDataType en = new EnumDataType(CAT, ringName(r), (int) n(r, "size"));
        en.setDescription(
            "Recorded sparse ring values for panel UID "
                + str(r, "uid")
                + ". Not automatically assigned to a native field.");
        int i = 0;
        for (JsonElement z : r.getAsJsonArray("entries")) {
          JsonObject v = z.getAsJsonObject();
          en.add("item_" + (i++) + "_" + safe(str(v, "label")), n(v, "value"), str(v, "label"));
        }
        dtm.resolve(en, DataTypeConflictHandler.DEFAULT_HANDLER);
      }
      MemoryBlock b =
          currentProgram
              .getMemory()
              .createInitializedBlock(
                  "LV_RECORDED_FACTS_NOT_RUNTIME",
                  toAddr(0x68000000L),
                  new ByteArrayInputStream(blob),
                  blob.length,
                  monitor,
                  false);
      b.setRead(true);
      b.setWrite(false);
      b.setExecute(false);
      b.setComment("Analysis archive of facts.json, not runtime memory or initialized data space.");
      createLabel(b.getStart(), "LV_recorded_facts_JSON", true);
      setPlateComment(
          b.getStart(),
          "Facts SHA256 "
              + hash(blob)
              + "; inspect facts.json for provenance and unresolved cases.");
      Map<Address, LinkedHashSet<String>> comments = new TreeMap<>();
      Map<Long, LinkedHashSet<String>> offsets = new HashMap<>();
      for (JsonElement e : p.getAsJsonArray("offset_facts")) {
        JsonObject r = e.getAsJsonObject();
        offsets.computeIfAbsent(n(r, "offset"), k -> new LinkedHashSet<>()).add(str(r, "text"));
      }
      JsonArray callResults = new JsonArray(), contexts = new JsonArray();
      for (JsonElement de : p.getAsJsonArray("dispatchers")) {
        JsonObject dispatcher = de.getAsJsonObject();
        Function run = getFunctionAt(toAddr(base + n(dispatcher, "entry")));
        boolean verified = anchored && run != null && ebpInvariant(run, dispatcher);
        JsonObject context = new JsonObject();
        context.addProperty("entry", n(dispatcher, "entry"));
        context.addProperty("ebp_data_space_invariant", verified);
        contexts.add(context);
        if (!verified) continue;
        for (Instruction i : currentProgram.getListing().getInstructions(run.getBody(), true))
          for (int op = 0; op < i.getNumOperands(); op++) {
            Object[] objects = i.getOpObjects(op);
            if (objects.length != 2
                || !(objects[0] instanceof Register)
                || !((Register) objects[0]).getName().equals("EBP")
                || !(objects[1] instanceof Scalar)) continue;
            long offset = ((Scalar) objects[1]).getSignedValue();
            if (offsets.containsKey(offset))
              for (String fact : offsets.get(offset))
                add(comments, i.getAddress(), "LV recorded fact: " + fact);
          }
        for (JsonElement ce : p.getAsJsonArray("calls")) {
          JsonObject c = ce.getAsJsonObject();
          Address at = toAddr(base + n(c, "offset"));
          JsonObject result = new JsonObject();
          result.addProperty("offset", n(c, "offset"));
          TreeMap<String, JsonObject> valid = new TreeMap<>();
          for (JsonElement fe : c.getAsJsonArray("candidates")) {
            JsonObject f = fe.getAsJsonObject();
            if (frameValid(f, run)) valid.put(f.get("args").toString(), f);
          }
          boolean accepted = valid.size() == 1;
          result.addProperty("accepted", accepted);
          result.addProperty(
              "reason",
              accepted
                  ? "Instruction boundaries, bytes, RunProc/EBP context and incoming flows verified"
                  : "No unique frame after Ghidra boundary/flow verification");
          if (accepted) {
            JsonArray args = valid.firstEntry().getValue().getAsJsonArray("args");
            long index = args.get(1).getAsJsonArray().get(1).getAsLong(),
                source = args.get(2).getAsJsonArray().get(1).getAsLong();
            String message =
                "LV verified call frame: WriteDCOTransferData; DCO "
                    + index
                    + " "
                    + control(index)
                    + "; source pointer DS+0x"
                    + Long.toHexString(source)
                    + "; args="
                    + args
                    + ". Saved defaults do NOT prove the current value; no callee prototype"
                    + " installed.";
            add(comments, at, message);
            if (offsets.containsKey(source))
              for (String fact : offsets.get(source)) add(comments, at, "LV source fact: " + fact);
            result.add("args", args);
            result.addProperty("dco", index);
            result.addProperty("source_ds", source);
          }
          callResults.add(result);
        }
      }
      JsonArray savedComments = new JsonArray();
      for (Map.Entry<Address, LinkedHashSet<String>> entry : comments.entrySet()) {
        String before = getPreComment(entry.getKey());
        String text =
            (before == null || before.isEmpty() ? "" : before + "\n")
                + String.join("\n", entry.getValue());
        setPreComment(entry.getKey(), text);
        JsonObject c = new JsonObject();
        c.addProperty("offset", entry.getKey().getOffset() - base);
        c.addProperty("text", text);
        savedComments.add(c);
      }
      binding.add("comments", savedComments);
      binding.add("calls", callResults);
      binding.add("contexts", contexts);
      binding.addProperty("facts_sha256", hash(blob));
      Files.writeString(
          bindingsFile, new GsonBuilder().setPrettyPrinting().create().toJson(binding));
      if (!signaturesBefore.equals(signatures()))
        throw new Exception("Facts changed function signatures");
    } else binding = JsonParser.parseString(Files.readString(bindingsFile)).getAsJsonObject();
    if (!str(binding, "facts_sha256").equals(hash(blob)))
      throw new Exception("Facts binding hash mismatch");
    byte[] saved = new byte[blob.length];
    currentProgram.getMemory().getBytes(toAddr(0x68000000L), saved);
    if (!Arrays.equals(blob, saved)) throw new Exception("Saved facts archive differs");
    MemoryBlock archive = currentProgram.getMemory().getBlock(toAddr(0x68000000L));
    if (archive.isWrite()
        || archive.isExecute()
        || !archive.isRead()
        || archive.getSize() != blob.length)
      throw new Exception("Wrong facts archive permissions/extent");
    int fields = 0, enums = 0, enumValues = 0;
    if (anchored) {
      Structure ds = (Structure) dtm.getDataType(CAT, "VI_DS_AnchoredProfile");
      if (ds == null || ds.getLength() != n(layout, "extent"))
        throw new Exception("Missing/wrong DS extent");
      for (JsonElement e : layout.getAsJsonArray("rows")) {
        JsonObject r = e.getAsJsonObject();
        if (n(r, "size") == 0) continue;
        DataTypeComponent c = ds.getComponentAt((int) n(r, "offset"));
        if (c == null
            || c.getOffset() != n(r, "offset")
            || c.getLength() != n(r, "size")
            || !safe(str(r, "name")).equals(c.getFieldName())
            || !c.getDataType().getName().equals("T_" + n(r, "flat_id")))
          throw new Exception("DS field mismatch " + r);
        fields++;
      }
      for (JsonObject d : defs.values()) {
        if (n(d, "size") == 0) continue;
        DataType t = dtm.getDataType(CAT, "T_" + n(d, "id"));
        if (t == null || t.getLength() != n(d, "size"))
          throw new Exception("Native type mismatch " + n(d, "id"));
        String rep = str(d, "representation");
        if (!rep.equals("packed_cluster")) {
          if (!(t instanceof TypeDef)) throw new Exception("Missing fact typedef");
          DataType underlying = ((TypeDef) t).getDataType();
          DataType primitive = primitive(str(d, "scalar"));
          if (rep.equals("scalar") && primitive != null) {
            if (!underlying.isEquivalent(primitive))
              throw new Exception("Primitive type mismatch " + n(d, "id"));
          } else if (rep.equals("typedef")) {
            JsonObject child = d.getAsJsonArray("children").get(0).getAsJsonObject();
            if (!underlying.getName().equals("T_" + n(child, "id")))
              throw new Exception("Typedef child mismatch");
          } else {
            if (!(underlying instanceof Array)) throw new Exception("Missing fact array");
            Array array = (Array) underlying;
            if (rep.equals("repeat")) {
              JsonObject child = d.getAsJsonArray("children").get(0).getAsJsonObject();
              if (array.getNumElements() != n(d, "count")
                  || !array.getDataType().getName().equals("T_" + n(child, "id")))
                throw new Exception("Repeat type mismatch");
            } else if (array.getNumElements() != n(d, "size")
                || !array.getDataType().isEquivalent(Undefined1DataType.dataType))
              throw new Exception("Opaque extent/type mismatch");
          }
        }
        if (rep.equals("packed_cluster")) {
          Structure st = (Structure) t;
          for (JsonElement e : d.getAsJsonArray("children")) {
            JsonObject c = e.getAsJsonObject();
            if (n(c, "size") == 0) continue;
            DataTypeComponent field = st.getComponentAt((int) n(c, "offset"));
            if (field == null
                || field.getOffset() != n(c, "offset")
                || field.getLength() != n(c, "size")
                || !field.getDataType().getName().equals("T_" + n(c, "id"))
                || !safe(str(c, "name")).equals(field.getFieldName()))
              throw new Exception("Aggregate child mismatch");
          }
        }
      }
    }
    for (JsonElement e : p.getAsJsonArray("rings")) {
      JsonObject r = e.getAsJsonObject();
      if (!str(r, "status").equals("recorded")) continue;
      ghidra.program.model.data.Enum en =
          (ghidra.program.model.data.Enum) dtm.getDataType(CAT, ringName(r));
      if (en == null || en.getLength() != n(r, "size")) throw new Exception("Missing ring enum");
      int i = 0;
      for (JsonElement z : r.getAsJsonArray("entries")) {
        JsonObject v = z.getAsJsonObject();
        if (en.getValue("item_" + (i++) + "_" + safe(str(v, "label"))) != n(v, "value"))
          throw new Exception("Ring value mismatch");
        enumValues++;
      }
      enums++;
    }
    for (JsonElement e : binding.getAsJsonArray("comments")) {
      JsonObject c = e.getAsJsonObject();
      if (!str(c, "text").equals(getPreComment(toAddr(base + n(c, "offset")))))
        throw new Exception("Lost native fact annotation");
    }
    byte[] after = new byte[code.length];
    currentProgram.getMemory().getBytes(toAddr(base), after);
    if (!Arrays.equals(code, after)) throw new Exception("Facts changed native code");
    int accepted = 0;
    for (JsonElement e : binding.getAsJsonArray("calls"))
      if (e.getAsJsonObject().get("accepted").getAsBoolean()) accepted++;
    JsonObject audit = new JsonObject();
    audit.addProperty("facts_sha256", hash(blob));
    audit.addProperty("bindings_sha256", hash(Files.readAllBytes(bindingsFile)));
    audit.addProperty("code_sha256", hash(code));
    audit.addProperty(
        "function_signatures_sha256", hash(signatures().getBytes(StandardCharsets.UTF_8)));
    audit.addProperty("layout_status", str(layout, "status"));
    audit.addProperty("fields", fields);
    audit.addProperty("ring_enums", enums);
    audit.addProperty("ring_values", enumValues);
    audit.addProperty("annotated_instructions", binding.getAsJsonArray("comments").size());
    audit.addProperty("verified_control_writes", accepted);
    audit.addProperty("unresolved_control_writes", p.getAsJsonArray("calls").size() - accepted);
    audit.addProperty("mode", mode);
    if (mode.equals("export"))
      if (!new GzfExporter()
          .export(dir.resolve("analysis.gzf").toFile(), currentProgram.getDomainFile(), monitor))
        throw new Exception("Facts export failed");
    Files.writeString(
        dir.resolve("facts-audit-" + mode + ".json"),
        new GsonBuilder().setPrettyPrinting().create().toJson(audit));
    println("VI_FACTS_OK " + audit);
  }
}
