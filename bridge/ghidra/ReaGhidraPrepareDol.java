import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Rebuild a GameCube/Wii DOL memory map from the section table REA's TypeScript
 * admission wrote. BinaryLoader maps the whole file once at address 0; this
 * script replaces that block with text, data, and BSS blocks at their load addresses.
 */
public final class ReaGhidraPrepareDol extends GhidraScript {
    private static final class Section {
        final String kind;
        final int index;
        final long fileOffset;
        final long address;
        final long size;

        Section(String kind, int index, long fileOffset, long address, long size) {
            this.kind = kind;
            this.index = index;
            this.fileOffset = fileOffset;
            this.address = address;
            this.size = size;
        }
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException(
                "GameCube DOL preparation requires exactly one section table path"
            );
        }
        if (!currentProgram.getExecutableFormat().equals("Raw Binary") ||
            !currentProgram.getLanguageID().getIdAsString().startsWith("PowerPC:BE:32:")) {
            throw new IllegalArgumentException(
                "GameCube DOL preparation requires a BinaryLoader import in big-endian 32-bit PowerPC"
            );
        }
        Path tablePath = Path.of(arguments[0]);
        if (!Files.isRegularFile(tablePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("GameCube DOL section table is not a regular file");
        }

        List<Section> sections = new ArrayList<>();
        long bssAddress = -1;
        long bssSize = -1;
        long entry = -1;
        for (String line : Files.readAllLines(tablePath)) {
            String[] fields = line.trim().split("\\s+");
            switch (fields[0]) {
                case "section" -> {
                    requireFields(fields, 6, line);
                    sections.add(new Section(
                        fields[1],
                        Integer.parseInt(fields[2]),
                        Long.decode(fields[3]),
                        Long.decode(fields[4]),
                        Long.decode(fields[5])
                    ));
                }
                case "bss" -> {
                    requireFields(fields, 3, line);
                    bssAddress = Long.decode(fields[1]);
                    bssSize = Long.decode(fields[2]);
                }
                case "entry" -> {
                    requireFields(fields, 2, line);
                    entry = Long.decode(fields[1]);
                }
                default -> throw new IllegalArgumentException("Unknown GameCube DOL table line: " + line);
            }
        }
        if (sections.isEmpty() || bssAddress < 0 || entry < 0) {
            throw new IllegalArgumentException("GameCube DOL section table is incomplete");
        }

        Memory memory = currentProgram.getMemory();
        List<FileBytes> files = memory.getAllFileBytes();
        if (files.size() != 1) {
            throw new IllegalStateException("GameCube DOL preparation requires exactly one imported file image");
        }
        FileBytes fileBytes = files.get(0);
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Remove the whole-file block before creating section blocks, so no two blocks claim one address.
        for (MemoryBlock block : memory.getBlocks()) {
            for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                if (source.getFileBytes().isPresent() && source.getFileBytes().get().equals(fileBytes)) {
                    memory.removeBlock(block, monitor);
                    break;
                }
            }
        }

        for (Section section : sections) {
            if (section.fileOffset + section.size > fileBytes.getSize()) {
                throw new IllegalArgumentException(
                    "GameCube DOL " + section.kind + " " + section.index + " exceeds the imported file"
                );
            }
            boolean text = section.kind.equals("text");
            if (!text && !section.kind.equals("data")) {
                throw new IllegalArgumentException("Unknown GameCube DOL section kind: " + section.kind);
            }
            MemoryBlock block = memory.createInitializedBlock(
                "." + section.kind + section.index,
                space.getAddress(section.address),
                fileBytes,
                section.fileOffset,
                section.size,
                false
            );
            block.setRead(true);
            block.setWrite(!text);
            block.setExecute(text);
        }

        // BSS may overlap data sections (.sdata/.sdata2), so map it only into the uncovered gaps.
        if (bssSize > 0) {
            List<long[]> gaps = new ArrayList<>();
            gaps.add(new long[] {bssAddress, bssAddress + bssSize});
            for (Section section : sections) {
                if (section.kind.equals("data")) {
                    gaps = subtract(gaps, section.address, section.address + section.size);
                }
            }
            int gapIndex = 0;
            for (long[] gap : gaps) {
                if (gap[1] <= gap[0]) continue;
                MemoryBlock block = memory.createUninitializedBlock(
                    ".bss" + gapIndex++,
                    space.getAddress(gap[0]),
                    gap[1] - gap[0],
                    false
                );
                block.setRead(true);
                block.setWrite(true);
                block.setExecute(false);
            }
        }

        Address entryAddress = space.getAddress(entry);
        MemoryBlock entryBlock = memory.getBlock(entryAddress);
        if (entryBlock == null || !entryBlock.isExecute()) {
            throw new IllegalArgumentException("GameCube DOL entry must lie in an executable section");
        }
        addEntryPoint(entryAddress);
        if (!disassemble(entryAddress) || createFunction(entryAddress, "__start") == null) {
            throw new IllegalStateException("GameCube DOL entry cannot be decoded as a function");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA raw binary prepared", true);
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA GameCube DOL prepared", true);
    }

    private static void requireFields(String[] fields, int count, String line) {
        if (fields.length != count) {
            throw new IllegalArgumentException("Malformed GameCube DOL table line: " + line);
        }
    }

    /** Remove the half-open range [start, end) from every gap, keeping the remainders. */
    private static List<long[]> subtract(List<long[]> gaps, long start, long end) {
        List<long[]> remaining = new ArrayList<>();
        for (long[] gap : gaps) {
            if (end <= gap[0] || start >= gap[1]) {
                remaining.add(gap);
                continue;
            }
            if (gap[0] < start) remaining.add(new long[] {gap[0], start});
            if (end < gap[1]) remaining.add(new long[] {end, gap[1]});
        }
        return remaining;
    }
}
