/** Build a minimal valid DOL: one text section at 0x80003100 with a 32-byte body. */
export const buildGamecubeDol = (
  options: {
    readonly entryPoint?: number;
    readonly textAddress?: number;
  } = {},
): Buffer => {
  const textAddress = options.textAddress ?? 0x8000_3100;
  const text = Buffer.from("4e800020".repeat(8), "hex");
  const header = Buffer.alloc(0x100);
  header.writeUInt32BE(0x100, 0x00); // text slot 0 file offset
  header.writeUInt32BE(textAddress, 0x48); // text slot 0 load address
  header.writeUInt32BE(text.length, 0x90); // text slot 0 size
  header.writeUInt32BE(options.entryPoint ?? textAddress, 0xe0); // entry point
  return Buffer.concat([header, text]);
};
