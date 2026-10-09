"""Derive the supported LV13 callback map from a user-supplied runtime DLL.
Static inspection only. The runtime fingerprint and addresses are build-specific.
"""

from pathlib import Path
import argparse, struct, json, re, hashlib, collections

if __package__:
    from .toolchain import RUNTIME_SHA256, acquire_job
else:
    from toolchain import RUNTIME_SHA256, acquire_job


def recover(runtime):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EAX
    import pefile

    P = Path(runtime).expanduser().resolve()
    b = P.read_bytes()
    if hashlib.sha256(b).hexdigest() != RUNTIME_SHA256:
        raise ValueError(
            "Unsupported runtime build; re-derive addresses before proceeding"
        )
    pe = pefile.PE(data=b)
    base = pe.OPTIONAL_HEADER.ImageBase
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    read = lambda v, n: pe.get_data(v - base, n)
    u32 = lambda v: struct.unpack("<I", read(v, 4))[0]

    def cstr(v):
        return read(v, 512).split(b"\0")[0].decode("ascii", "replace")

    def insns(v, n=128):
        return list(md.disasm(read(v, n), v))

    def return_constant(v):
        i = insns(v, 10)
        if (
            i[0].mnemonic == "mov"
            and i[0].op_str.startswith("eax, ")
            and i[0].operands[1].type == X86_OP_IMM
            and i[1].mnemonic == "ret"
        ):
            return i[0].operands[1].imm
        if (
            i[0].mnemonic == "xor"
            and i[0].op_str == "eax, eax"
            and i[1].mnemonic == "ret"
        ):
            return 0
        raise ValueError(("constant getter", hex(v)))

    # Index absolute immediate stores. Accept later only when the complete containing
    # straight-line initializer decodes from an aligned start and includes the store.
    stores = collections.defaultdict(list)
    for m in re.finditer(b"\xc7\x05", b):
        o = m.start()
        if o + 10 > len(b):
            continue
        va = base + pe.get_rva_from_offset(o)
        dest, value = struct.unpack_from("<II", b, o + 2)
        if not base <= dest < base + pe.OPTIONAL_HEADER.SizeOfImage:
            continue
        stores[dest].append((va, value))

    def valid_store(va):
        # Initializers are aligned and separated by INT3 or return. Decode from the
        # nearest padded boundary, requiring a continuous instruction stream to store.
        off = pe.get_offset_from_rva(va - base)
        lo = max(0, off - 65536)
        p = b.rfind(b"\xc3\xcc", lo, off)
        if p < 0:
            return False, None
        start = p + 1
        while start < len(b) and b[start] == 0xCC:
            start += 1
        sv = base + pe.get_rva_from_offset(start)
        if sv % 16:
            return False, None
        for i in md.disasm(b[start : off + 10], sv):
            if i.address == va and i.mnemonic == "mov" and i.size == 10:
                return True, sv
        return False, None

    # Provider initialized by 0x30484850: [0x30cebdd4]=0x30aaba1c,
    # [0x30cebdd8]=0x30cebdd4. Its virtual getters return constant code pointers.
    # Pinned build only; preserve the exact evidence for dynamic-initializer slots.
    provider_vtable = 0x30AABA1C
    provider_init = read(0x30484850, 0x8A)
    assert bytes.fromhex("c705d4bdce301cbaaa30") in provider_init
    assert bytes.fromhex("c705d8bdce30d4bdce30") in provider_init
    dynamic_stores = {}
    legacy_ins = insns(0x30A32F50, 0xB28)
    for k, i in enumerate(legacy_ins):
        if i.mnemonic != "mov" or len(i.operands) != 2:
            continue
        dst, src = i.operands
        if (
            dst.type != X86_OP_MEM
            or dst.mem.base
            or src.type != X86_OP_REG
            or src.reg != X86_REG_EAX
        ):
            continue
        window = legacy_ins[max(0, k - 10) : k]
        if not any(j.mnemonic == "call" and j.op_str == "0x304848e0" for j in window):
            continue
        gets = [
            j
            for j in window
            if j.mnemonic == "mov" and j.op_str.startswith("eax, dword ptr [edx")
        ]
        if len(gets) != 1:
            continue
        slot = gets[0].operands[1].mem.disp
        getter = u32(provider_vtable + slot)
        target = return_constant(getter)
        dynamic_stores[dst.mem.disp] = {
            "instruction": i.address,
            "initializer": 0x30A32F50,
            "provider": 0x30484850,
            "provider_vtable": provider_vtable,
            "vtable_offset": slot,
            "getter": getter,
            "target": target,
        }
    mods = []
    # Registration routine reads module-object globals immediately before each call.
    for i in insns(0x306CC470, 0x213):
        if (
            i.mnemonic != "mov"
            or len(i.operands) != 2
            or i.operands[1].type != X86_OP_MEM
            or i.operands[1].mem.base
        ):
            continue
        g = i.operands[1].mem.disp
        if g not in stores:
            continue
        candidates = [(va, val) for va, val in stores[g] if valid_store(va)[0]]
        assert len(candidates) == 1, (hex(g), candidates)
        va, obj = candidates[0]
        block = read(va - 52, 62)
        # The two object stores occur in this exact module-init basic block.
        objstores = {
            d: v
            for d, v in (
                struct.unpack_from("<II", block, m.start() + 2)
                for m in re.finditer(b"\xc7\x05", block)
            )
        }
        vt = objstores[obj]
        table = objstores[obj + 4]
        module = return_constant(u32(vt))
        name = cstr(return_constant(u32(vt + 8)))
        lookup = u32(vt + 16)
        instructions = insns(lookup, 100)
        limit = None
        for j in instructions:
            if (
                j.mnemonic == "cmp"
                and len(j.operands) == 2
                and j.operands[1].type == X86_OP_IMM
            ):
                limit = j.operands[1].imm
                break
            if (
                j.mnemonic == "mov"
                and j.op_str.startswith("esi, ")
                and j.operands[1].type == X86_OP_IMM
            ):
                limit = j.operands[1].imm
            if j.mnemonic == "ret":
                break
        assert limit is not None and 0 <= limit < 4096, (module, name, hex(lookup))
        functions = []
        for idx in range(limit + 1):
            slot = table + idx * 4
            target = u32(slot)
            updates = []
            for at, val in stores.get(slot, []):
                ok, start = valid_store(at)
                if ok:
                    updates.append(
                        {"instruction": at, "initializer": start, "target": val}
                    )
            distinct = {x["target"] for x in updates}
            assert len(distinct) <= 1, ("ambiguous", hex(slot), updates)
            if updates:
                target = updates[0]["target"]
            provider_update = dynamic_stores.get(slot)
            if provider_update:
                assert not updates
                target = provider_update["target"]
            target_section = (
                pe.get_section_by_rva(target - base)
                if base <= target < base + pe.OPTIONAL_HEADER.SizeOfImage
                else None
            )
            executable = bool(
                target_section and target_section.Characteristics & 0x20000000
            )
            functions.append(
                {
                    "executable": executable,
                    "index": idx,
                    "ident": (module << 16) | idx,
                    "target": target,
                    "table_slot": slot,
                    "static_updates": updates,
                    "provider_update": provider_update,
                    "unimplemented": target in [0, 0x306CA5C0],
                }
            )
        mods.append(
            {
                "module": module,
                "name": name,
                "global": g,
                "object": obj,
                "vtable": vt,
                "table": table,
                "lookup": lookup,
                "limit": limit,
                "initializer": valid_store(va)[1],
                "functions": functions,
            }
        )
    exports = collections.defaultdict(list)
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            exports[base + e.address].append(e.name.decode("ascii", "replace"))
    for m in mods:
        for f in m["functions"]:
            f["export_names"] = exports.get(f["target"], [])
    out = {
        "runtime": str(P),
        "sha256": hashlib.sha256(b).hexdigest(),
        "image_base": base,
        "machine": pe.FILE_HEADER.Machine,
        "version": "13.0.0.4046",
        "resolver": 0x306CA700,
        "patch_handler": 0x30170690,
        "modules": mods,
    }
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--runtime", type=Path, required=True, help="LV13.0.0.4046 i386 lvrt.dll"
    )
    ap.add_argument(
        "--output", type=Path, required=True, help="new callback map JSON file"
    )
    args = ap.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists():
        ap.error("Output already exists; choose a new callback map file")
    if not args.runtime.expanduser().is_file():
        ap.error("Runtime DLL does not exist")
    try:
        lock, limits = acquire_job()
    except (ValueError, OSError) as e:
        ap.error(str(e))
    try:
        result = recover(args.runtime)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2))
        print(
            json.dumps(
                {
                    "output": str(output),
                    "runtime_sha256": result["sha256"],
                    "modules": len(result["modules"]),
                    "callbacks": sum(len(m["functions"]) for m in result["modules"]),
                },
                indent=2,
            )
        )
    finally:
        lock.close()


if __name__ == "__main__":
    main()
