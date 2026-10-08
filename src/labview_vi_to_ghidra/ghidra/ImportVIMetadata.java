// Metadata mapping authored for this analysis; field semantics/provenance in metadata.json.
// @category LabVIEW
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.GzfExporter;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
public class ImportVIMetadata extends GhidraScript {
 final CategoryPath CAT=new CategoryPath("/LabVIEW/VI_metadata");
 String safe(String s){return s.replaceAll("[^A-Za-z0-9_]","_");}
 String hash(byte[] b)throws Exception{StringBuilder s=new StringBuilder();for(byte x:MessageDigest.getInstance("SHA-256").digest(b))s.append(String.format("%02x",x&255));return s.toString();}
 DataType scalar(String s){switch(s){case "Boolean":case "NumUInt8":return ByteDataType.dataType;case "NumInt8":return SignedByteDataType.dataType;case "NumInt16":return ShortDataType.dataType;case "NumUInt16":return UnsignedShortDataType.dataType;case "NumInt32":return IntegerDataType.dataType;case "NumUInt32":return UnsignedIntegerDataType.dataType;case "NumInt64":return LongLongDataType.dataType;case "NumUInt64":return UnsignedLongLongDataType.dataType;case "NumFloat32":return FloatDataType.dataType;case "NumFloat64":return DoubleDataType.dataType;default:throw new IllegalArgumentException(s);}}
 String signatures(){StringBuilder s=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))s.append(f.getEntryPoint()).append(':').append(f.getSignature()).append('\n');return s.toString();}
 public void run()throws Exception{
  Path file=Path.of(getScriptArgs()[0]);Path dir=file.getParent();JsonObject p=JsonParser.parseString(Files.readString(file)).getAsJsonObject();
  JsonObject relocation=JsonParser.parseString(Files.readString(Path.of(p.get("relocation_plan").getAsString()))).getAsJsonObject();
  byte[] code=new byte[relocation.get("code_size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(relocation.get("base").getAsLong()),code);
  if(!hash(code).equals(relocation.get("patched_sha256").getAsString()))throw new IOException("Code hash mismatch");
  byte[] blob=Files.readAllBytes(Path.of(p.get("blob").getAsString()));if(!hash(blob).equals(p.get("blob_sha256").getAsString()))throw new IOException("Metadata hash mismatch");
  boolean apply=getScriptArgs().length==1;String signaturesBefore=signatures();DataTypeManager dtm=currentProgram.getDataTypeManager();
  if(apply){
   for(Map.Entry<String,JsonElement> source:p.getAsJsonObject("sources").entrySet())if(!hash(Files.readAllBytes(Path.of(source.getKey()))).equals(source.getValue().getAsString()))throw new IOException("Source changed");
   int end=0;for(JsonElement e:p.getAsJsonArray("fields")){JsonObject f=e.getAsJsonObject();end=Math.max(end,f.get("offset").getAsInt()+f.get("size").getAsInt());}
   StructureDataType ds=new StructureDataType(CAT,"VI_DataSpace_Partial",end);
   ds.setDescription("Extracted DCO default/transfer offsets only. Gaps unknown; size is LOWER BOUND, not full DS size. Not bound to native callback parameters. Logical aggregates remain opaque. See metadata.json for decoder provenance.");
   for(JsonElement e:p.getAsJsonArray("fields")){
    JsonObject f=e.getAsJsonObject();int size=f.get("size").getAsInt();DataType t=new ArrayDataType(Undefined1DataType.dataType,size,1);
    if(!f.get("type").isJsonNull()){String kind=f.get("type").getAsString();t=dtm.resolve(new TypedefDataType(CAT,"LV_"+kind,scalar(kind)),DataTypeConflictHandler.DEFAULT_HANDLER);}
    ds.replaceAtOffset(f.get("offset").getAsInt(),t,size,safe(f.get("name").getAsString()),f.get("comment").getAsString());
   }
   dtm.addDataType(ds,DataTypeConflictHandler.DEFAULT_HANDLER);
   EnumDataType offsets=new EnumDataType(CAT,"VI_SavedDSOffsets",4);
   for(JsonElement e:p.getAsJsonArray("offsets")){JsonObject o=e.getAsJsonObject();offsets.add(safe(o.get("name").getAsString())+"_at_"+Long.toHexString(o.get("offset").getAsLong()),o.get("offset").getAsLong(),o.get("source").getAsString());}
   dtm.addDataType(offsets,DataTypeConflictHandler.DEFAULT_HANDLER);
   MemoryBlock block=currentProgram.getMemory().createInitializedBlock("LV_METADATA_INDEX_NOT_RUNTIME",toAddr(0x60000000L),new ByteArrayInputStream(blob),blob.length,monitor,false);
   block.setRead(true);block.setWrite(false);block.setExecute(false);block.setComment("Artificial address for searchable extracted JSON records. NOT runtime data-space bytes or native pointers.");
   for(JsonElement e:p.getAsJsonArray("records")){
    JsonObject r=e.getAsJsonObject();var addr=toAddr(0x60000000L+r.get("offset").getAsLong());String label=safe("META_"+r.get("kind").getAsString()+"_"+r.get("key").getAsString());
    currentProgram.getListing().createData(addr,StringDataType.dataType,r.get("size").getAsInt());createLabel(addr,label,true);setPlateComment(addr,"Extracted metadata; artificial storage only. "+r.toString());
    currentProgram.getBookmarkManager().setBookmark(addr,"Info","LabVIEW metadata",label);
   }
   if(!signaturesBefore.equals(signatures()))throw new IOException("Unexpected callback signature change");
  }
  Structure ds=(Structure)dtm.getDataType(CAT,"VI_DataSpace_Partial");if(ds==null)throw new IOException("Missing DS type");
  int scalarCount=0;for(JsonElement e:p.getAsJsonArray("fields")){JsonObject f=e.getAsJsonObject();DataTypeComponent c=ds.getComponentAt(f.get("offset").getAsInt());if(c==null||c.getOffset()!=f.get("offset").getAsInt()||c.getLength()!=f.get("size").getAsInt()||!safe(f.get("name").getAsString()).equals(c.getFieldName()))throw new IOException("Field mismatch "+f);if(!f.get("type").isJsonNull()){scalarCount++;if(!c.getDataType().getName().equals("LV_"+f.get("type").getAsString()))throw new IOException("Scalar type mismatch");}}
  byte[] saved=new byte[blob.length];currentProgram.getMemory().getBytes(toAddr(0x60000000L),saved);if(!Arrays.equals(blob,saved))throw new IOException("Saved metadata differs");
  for(JsonElement e:p.getAsJsonArray("records")){JsonObject r=e.getAsJsonObject();Data d=getDataAt(toAddr(0x60000000L+r.get("offset").getAsLong()));if(d==null||d.getLength()!=r.get("size").getAsInt())throw new IOException("Record missing");}
  JsonObject audit=new JsonObject();audit.addProperty("code_sha256",hash(code));audit.addProperty("metadata_sha256",hash(saved));audit.addProperty("records",p.getAsJsonArray("records").size());audit.addProperty("fields",p.getAsJsonArray("fields").size());audit.addProperty("scalar_fields",scalarCount);audit.addProperty("function_signatures_sha256",hash(signatures().getBytes(java.nio.charset.StandardCharsets.UTF_8)));audit.addProperty("mode",apply?"apply":getScriptArgs()[1]);
  if(!apply&&getScriptArgs()[1].equals("export")){if(!new GzfExporter().export(dir.resolve("analysis.gzf").toFile(),currentProgram.getDomainFile(),monitor))throw new IOException("Export failed");}
  Files.writeString(dir.resolve("audit-"+(apply?"apply":getScriptArgs()[1])+".json"),new GsonBuilder().setPrettyPrinting().create().toJson(audit));println("VI_METADATA_OK "+audit);
 }
}
