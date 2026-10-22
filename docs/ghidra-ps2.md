# PlayStation 2 EE static ELF analysis through Ghidra

This specialization builds on [generic MIPS support](ghidra-mips.md) the same
way the [PSP profile](ghidra-psp.md) does. It reuses REA's CLI/MCP, Ghidra
bridge, Evidence and snapshot workflows. Emotion Engine instructions, the
R5900 register model and calling conventions remain owned by
[ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded).

## Initial boundary

The initial profile is limited to Linux x64, little-endian ELF32 `ET_EXEC`,
`EM_MIPS` with the machine field `EF_MIPS_MACH_5900` (`e_flags & 0x00ff0000 ==
0x00920000`), the ISA level `EF_MIPS_ARCH_3`, the ABI field `EABI64` (or none),
optionally `NOREORDER`, and no other header bits. That is what ee-gcc writes
for a retail executable (for example `e_flags = 0x20924000`). The profile
requires an inspected ELF whose declaration tables carry no MIPS ABI flags
record and no GNU MIPS attributes; a producer that writes either needs its
own verification. Other hosts and flag combinations are refused, not
inferred. File names do not identify a PlayStation 2 target.

IRX modules, relocatable or shared images, ISO containers, overlays and
emulation are outside this first profile.

## Bring your own compatible extension

Install the extension in the selected Ghidra distribution at
`$GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra-emotionengine-reloaded`, with
its `Module.manifest`, `extension.properties`, language files
(`emotionengine.ldefs`, `r5900.slaspec`, `r5900.pspec`, `r5900.cspec`) and
JAR. REA never downloads, installs, rebuilds or vendors it. The extension's
`version` property must name the selected Ghidra version (the project's
releases ship one archive per Ghidra version).

REA fingerprints the installed files before resolving the analysis profile
and checks the identity again immediately before launch, exactly as for the
PSP extension (bounded inspection, no symlinks, content identity rather than a
signature). Missing prerequisites return `EE_EXTENSION_UNAVAILABLE` with an
installation hint.

## Language selection

The profile pins `r5900:LE:32:default` with the `default` compiler
specification (`language_selection: provider-pinned-v1`, lane
`ps2-elf32-exec-eabi64-r5900-v1`) and passes it to the standard ELF loader; a
caller-selected `REA_GHIDRA_LANGUAGE_ID` is refused for this lane because the
generic MIPS languages do not decode the R5900's 128-bit and COP2
instructions. Decompiled output for those instructions follows the
extension's definitions and is an approximation, which every result's
limitations state.

## Ordinary public interfaces

```bash
rea analyze /absolute/path/to/SCES_511.90 --provider ghidra --json
rea decompile /absolute/path/to/SCES_511.90 sceGsSyncPath --provider ghidra
```

MCP uses `open_binary` with an absolute path and `provider_id: "ghidra"`, then
the ordinary inventory and function operations.
