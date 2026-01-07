# Sharingan IDA Plugin

Assist IDA users with deobfuscation and string/data decryption through a drag-and-drop recipe workflow. Plugin was developed to streamline the reverse engineering workflow by bridging the gap between complex obfuscation and encrypted string through two core strategies:

- **Automation**

  - Clean up code without the headache: It automatically handles common obfuscation patterns for you. If you run into something new, you can easily plug in your own custom module to deal with it.
  - Stop chasing encoded strings: Instead of decrypting strings one by one, let the plugin find and decode them for you. It even drops the results directly into IDA comments so you’re never out of the loop.

* **Visualization**

  - See exactly what changed: No more guessing—Sharingan highlights the "before" and "after" so you can see exactly how the code was cleaned up at a glance.
  - Mix and match your modules: Think of each module as a layer. You can toggle them on or off to see how different deobfuscation steps affect the code without committing to anything.
  - Never lose your place: It uses clear color-coding for obfuscated areas, making it much easier to keep you navigate even in massive, messy binaries.

## Features



- **Easy UI**: Borrowed the drag-and-drop idea from CyberChef to keep things smooth and simple.
- **Dual mode pipeline**: switch between deobfuscation and decryption.
- **Built-in ingredients**: deobfuscators (`apihammering`, `dbjmp`, `deadif`, `deadloop`, `propagate`, `substitute`) and decryptors (`aes`, `rc4`, `xor`, `xorstr`, `base64`, `add`, `des`, `rol`, `sub`).
- **Bookmark-driven ranges**: add manual or scanned ranges to process; focusing on small code-block before apply those deobfucation methods to whole binary.
- **Highlight difference**: review assembly or decompiler diffs in the after committing changes; compact mode hides the disassembler pane when space is tight.
- **Right-click helpers**: from IDA’s disassembly view quickly Select a range to deobfuscate, Exclude (revert) a patch, or Filter to inject a substitute module.
- **Hints and overlap detection**: colorize found obfuscated regions by modules to focus results; overlapping obfuscated regions are highlighted for quick triage.
- **String finding**: Find all available string from static strings, stack strings, tight strings base-on ascii and unicode pattern.
- **String decryption**: Select potential encrypted strings to apply desired decryption methods. Preview it before comment results in strings' addresses.

## Requirements

- IDA Pro 9.x with Hex-Rays installed (pseudocode preview relies on `ida_hexrays`).
- Install Python 3.12 or later and all packages in requirements.txt


## Usage

![UI of Sharingan](images/components.png)

1. Launch via `Alt+F9` or `Edit → Plugins → Sharingan`.
2. In **Operation**, choose the mode (Deobfuscation/Decryption) and drag-and-drop ingredients into **Recipe**.
3. Select a range in IDA and use the disassembly right-click menu to **Bookmark** it (or **Filter** to add a substitute; **Exclude** to revert a false positive). Bookmarks appear in the combo box and are persisted per-IDB. In additional to, selecting mode display to switch view assembly/decompiler/string.
4. Toggle options in **Recipe**:
   - `Compact`: hide the disassembler/decompiler pane for side-by-side layouts.
   - `Auto patch`: apply patches automatically when preview.
   - `All binary`: operate on the entire binary instead of a selection.
5. Click **Preview** to show the found obfuscated regions in the docked `asm_view` (ASM or Hex-Rays). Use **Reset** to clear scanning entries; **Delete** to remove ingredients from the recipe; **Resolve** to mark selected region from Bookmark as done and delete it. After ensuring the found regions are corrent, use **Cook** to apply patches and display changes before/after.
6. Each tab represents a region. There is a button new tab to handle many different regions. 

## Technique Details

### Deobfuscation

![Feature diff](images/diff.png)

- `APIHammering`: 32-bit only; locates dummy WinAPI and NOPs the call plus its argument pushes.
- `DBJmp`: finds stacked JMPs that land on the same target, rewrites them into a single branch, and cleans overlapping junk bytes.
- `DeadIf`: uses Hex-Rays to spot constant numeric IF conditions; NOPs the compare/jump pair and the unreachable then/else blocks.
- `DeadLoop`: Hex-Rays-driven scan for constant-condition loops; strips loop blocks to remove dead control flow. Only support remove loop body currently.
- `Propagate`: emulates indirect jmp/call chains with Unicorn to recover real targets and drops a comment with the resolved address.
- `Substitute`: user-provided start/end and replacement assembly; searches matching byte patterns in-range, assembles the patch, and pads with NOP as needed.

### Decryption

- Pipeline: drag decryptors into `Recipe`, select strings, and `Preview/Cook` to apply sequentially.
- Byte ops: `Xor`, `XorStr` (repeating key), `Add`, `Sub`, `Rol` (byte-wise rotate).
- Ciphers: `RC4`, `AES` (ECB/CBC with IV), `DES` (ECB/CBC); keys/IVs are padded or truncated to valid sizes.
- Encoding: `Base64` with automatic padding fixups for truncated inputs.

## Acknowledgement
FLOSS, CyberChef, patching
