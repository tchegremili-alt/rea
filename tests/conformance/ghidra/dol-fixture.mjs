import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);

// Linker-script layout (dol-fixture.ld). Fixed here so the converter and checks agree.
export const DOL_FIXTURE_TAIL_ADDRESS = 0x80013030;
const DOL_BSS_START = 0x80013008;
// The DOL has one BSS range. It is widened to 8 bytes into the tail segment, so it
// partly overlaps data slot 1 and keeps a gap at 0x80013018..0x80013030.
const DOL_BSS_END = DOL_FIXTURE_TAIL_ADDRESS + 8;
const DOL_HEADER_SIZE = 0x100;
const DOL_TEXT_MAX = 7;
const DOL_DATA_MAX = 11;
const MEMORY_START = 0x8000_0000;
const PT_LOAD = 1;
const PF_X = 1;

/** Convert a static big-endian ELF32 PowerPC image with PT_LOAD segments into a DOL. */
export function convertElfToDol(elf, { bss }) {
  if (elf.readUInt32BE(0) !== 0x7f454c46) throw new Error("not an ELF file");
  if (elf[4] !== 1 || elf[5] !== 2)
    throw new Error("expected ELF32 big-endian");
  if (elf.readUInt16BE(18) !== 20) throw new Error("expected PowerPC machine");
  const entry = elf.readUInt32BE(0x18);
  const phoff = elf.readUInt32BE(0x1c);
  const phentsize = elf.readUInt16BE(0x2a);
  const phnum = elf.readUInt16BE(0x2c);
  const texts = [];
  const datas = [];
  for (let i = 0; i < phnum; i++) {
    const base = phoff + i * phentsize;
    if (elf.readUInt32BE(base) !== PT_LOAD) continue;
    const offset = elf.readUInt32BE(base + 4);
    const vaddr = elf.readUInt32BE(base + 8);
    const filesz = elf.readUInt32BE(base + 16);
    const flags = elf.readUInt32BE(base + 24);
    if (vaddr < MEMORY_START)
      throw new Error(`PT_LOAD below 0x80000000: 0x${vaddr.toString(16)}`);
    if (filesz === 0) continue;
    const slot = {
      address: vaddr,
      bytes: elf.subarray(offset, offset + filesz),
    };
    (flags & PF_X ? texts : datas).push(slot);
  }
  if (texts.length > DOL_TEXT_MAX) throw new Error("too many text sections");
  if (datas.length > DOL_DATA_MAX) throw new Error("too many data sections");
  const header = Buffer.alloc(DOL_HEADER_SIZE);
  const chunks = [];
  let cursor = DOL_HEADER_SIZE;
  const place = (offsetBase, addressBase, sizeBase, slots) =>
    slots.forEach((slot, index) => {
      const pad = (32 - (cursor % 32)) % 32;
      if (pad) chunks.push(Buffer.alloc(pad));
      cursor += pad;
      header.writeUInt32BE(cursor, offsetBase + index * 4);
      header.writeUInt32BE(slot.address, addressBase + index * 4);
      header.writeUInt32BE(slot.bytes.length, sizeBase + index * 4);
      chunks.push(slot.bytes);
      cursor += slot.bytes.length;
    });
  place(0x00, 0x48, 0x90, texts);
  place(0x1c, 0x64, 0xac, datas);
  header.writeUInt32BE(bss.address, 0xd8);
  header.writeUInt32BE(bss.size, 0xdc);
  header.writeUInt32BE(entry, 0xe0);
  return Buffer.concat([header, ...chunks]);
}

/**
 * Build the source-owned DOL fixture: ELF at 0x80003100 via the linker script, then
 * converted to a DOL whose single BSS range overlaps data slot 1 and keeps a gap.
 * The fixture is never executed.
 */
export async function buildGameCubeDolFixture(directory) {
  const compiler = process.env.REA_PPC_CLANG ?? "clang";
  const target = "powerpc-unknown-linux-gnu";
  const here = (path) => fileURLToPath(new URL(path, import.meta.url));
  const sources = [
    here("../c/ppc.c"),
    here("../c/dol.c"),
    here("./ppc-probe.S"),
  ];
  const linkerScript = here("./dol-fixture.ld");
  const elfPath = join(directory, `${target}.dol-source.elf`);
  const dolPath = join(directory, `${target}.dol`);
  const args = [
    `--target=${target}`,
    "-mcpu=750",
    "-fno-pic",
    "-fuse-ld=lld",
    "-nostdlib",
    "-static",
    "-O0",
    "-g",
    `-Wl,-T,${linkerScript}`,
    "-Wl,-e,rea_ppc_entry",
    "-Wl,--build-id=none",
    ...sources,
    "-o",
    elfPath,
  ];
  const version = await execute(compiler, ["--version"], { timeout: 10000 });
  await execute(compiler, args, { timeout: 60000 });
  const elf = await readFile(elfPath);
  const dol = convertElfToDol(elf, {
    bss: { address: DOL_BSS_START, size: DOL_BSS_END - DOL_BSS_START },
  });
  await writeFile(dolPath, dol);
  const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
  return {
    path: dolPath,
    elf_path: elfPath,
    sha256: sha(dol),
    elf_sha256: sha(elf),
    bss: { address: DOL_BSS_START, size: DOL_BSS_END - DOL_BSS_START },
    compiler: version.stdout.trim(),
    arguments: args,
  };
}
