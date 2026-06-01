# Ghidra's Paradise

Paradise is a Ghidra extension that adds an IDA-like pseudocode, graph, and inspection workflow on top of Ghidra's native decompiler. It is built for fast reverse-engineering review: cleaner C-like output, function tabs, diagram navigation, xrefs, strings, encoded-string detection, URL/path/shell inspection, local variables, cleanup reporting, triage hints, and export tools live in one dockable workflow.

Paradise does not replace Ghidra's decompiler. It uses Ghidra as the source of truth and keeps cleanup transforms display/export-only unless you explicitly run an edit action such as rename, type, or comment.

## Features

- IDA-like pseudocode provider with line numbers, token coloring, current-line highlight, brace matching, search, go-to, smart copy, tabs, and close buttons.
- Clean C mode for deterministic display/export cleanup:
  - stdint-style primitive aliases such as `uint64_t` and `uint8_t`
  - varargs wrapper cleanup for printf/scanf-style wrappers
  - call argument trimming for detected wrappers
  - stack canary cleanup
  - loop, condition, cast, literal, and compound-assignment cleanup
  - optional local alias display
- Symbol preservation by default: Paradise does not rewrite Ghidra `FUN_*` or `DAT_*` names into IDA-style `sub_*`, `byte_*`, or `qword_*` names.
- IDA-style diagram view with basic-block windows, colored control-flow edges, string/comment annotations, edge hover highlighting, and PNG/SVG export.
- Function diagram and whole-binary diagram entry points from the `Paradise` menu.
- Listing and decompiler synchronization: selecting addresses in Listing or Decompile can move the Paradise pseudocode view.
- Docked analysis tabs:
  - `Xrefs`
  - `Locals`
  - `Trace`
  - `Calls`
  - `Strings` with overview, per-encoding result tabs, filters, and usage navigation
  - `Diff`
  - `Drafts`
  - `Suggestions`
  - `Triage`
  - `Cleanups`
- Encoded string detection for Base64, repeated Base64 decode chains, hex, URL percent encoding, Base32, UTF-16LE, and UTF-16BE. Detected string tabs appear only when that encoding is present, with decode counts shown when applicable.
- Pseudocode context-menu decoding via `Decode from...` with auto and explicit decode choices.
- String-table context actions for `Goto usage` and `Goto string`.
- Paradise Inspector dockable window for decoded URL, path, shell-operation, and executable-launch review:
  - scans the active function or whole binary
  - decodes strings before matching
  - detects URLs, host/path patterns, Windows drive paths, UNC paths, environment paths, Unix paths, and relative paths
  - detects shell launchers and command strings such as PowerShell, `cmd /c`, `sh -c`, `bash -c`, `ls -al`, `rm -rf`, `curl`, `wget`, `certutil`, `bitsadmin`, and related command utilities
  - detects executable launch strings such as `C:\ProgramData\run.exe --command2`, `./file`, and `./file --help`
  - groups repeated findings with a `Count` column when merge mode is enabled
  - supports Overview, URLs, Paths, Shell, and Execute tabs with filters, configurable columns, CSV export, and usage navigation
  - shows per-finding detail tabs for Overview, decoded Value, Source/encoding metadata, and individual uses
  - uses responsive detail tables with wrapped values, address `Goto` actions, and Value-tab copy actions
  - `Goto usage` focuses the pseudocode line by address, original encoded text, or decoded text
- Variable trace view that follows the current pseudocode line and shows static/symbolic value estimates where possible.
- Suggestions and triage views for review targets such as suspicious XOR operations, call-heavy functions, string-heavy functions, and likely entry logic.
- Cleanups view showing which cleanup rules affected the current pseudocode.
- Export current function or all non-external functions as C-like pseudocode, with optional metadata JSON.
- Redesigned settings dialog with a sidebar navigator, bold page headers, grouped controls, visible analysis tab selection, cleanup rules, export mode, and layout reset.

## Requirements

- Ghidra 12.1
- A JDK supported by your Ghidra installation
- macOS, Linux, or Windows supported by Ghidra

The repository is currently developed against the Homebrew Ghidra 12.1 layout on macOS, but the extension uses the standard Ghidra extension build system.

## Build

Set `GHIDRA_INSTALL_DIR` to your Ghidra installation, or pass it with `-P`.  

```sh
/opt/homebrew/Cellar/ghidra/12.1/libexec/support/gradle/gradlew \
  -PGHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1/libexec \
  clean buildExtension
```
**This path is machine-specific.**
It depends on your OS, install method, Ghidra version, and local install location. The Homebrew path above is only an example; use the directory on your system that contains `support/buildExtension.gradle`.

The built extension zip is written to `dist/`.

## Install

1. Open Ghidra.
2. Choose `File > Install Extensions...`.
3. Add the Paradise zip from `dist/`.
4. Restart Ghidra.
5. Enable the extension from `File > Configure` if Ghidra prompts you.

After installation, the main actions are available from the top-level `Paradise` menu.

## Usage

Open a program in CodeBrowser and use:

- `Paradise > Pseudocode > Decompile` to open the current function in Paradise Pseudocode.
- `Paradise > Diagram > Open Function Diagram` to open the current function graph.
- `Paradise > Diagram > Open Binary Diagram` to open a binary-level overview.
- `Paradise > Inspect > Scan Function Inspector` to scan the current function for decoded URLs, paths, shell operations, and executable launches.
- `Paradise > Inspect > Scan Binary Inspector` to scan the whole binary for decoded URLs, paths, shell operations, and executable launches.
- `Paradise > Options > Settings` to configure display, navigation, cleanup, Inspector, export, and visible analysis tabs.
- `Paradise > Export > Export Current Function` or `Export All Functions` to write cleaned C-like output.

Paradise also exposes provider-local toolbar buttons in the Pseudocode and Diagram windows. Hover a toolbar icon in Ghidra to see the action name.

In the Pseudocode viewer, right-click selected text or a string literal and use `Decode from...` to decode common encodings. In the `Strings` analysis tab, Paradise shows `Overview` plus per-detected-type subtabs such as `Base64`, `Hex`, `URL`, `Base32`, `UTF-16LE`, and `UTF-16BE`. Each string table has a filter field, and row context menus can jump to the usage in pseudocode or to the string data address.

Use `Paradise Inspector` when you want a focused review surface for network, filesystem, shell-operation, and executable-launch artifacts. The Inspector scans plain strings and decoded strings, then lists matching URLs, paths, command text, and launch strings. Right-click a row or press `Enter` to jump to the usage; decoded rows retain the original encoded source so navigation can still focus the line that contains the encoded literal.

Selecting an Inspector row opens a detail area below the list. In `Screen` mode, detail tabs show a short Overview, decoded Value, Source/encoding metadata, and recorded Uses. Address rows include `Goto` buttons, while the Value tab includes `Copy` buttons for decoded and original values. Long values wrap inside responsive tables and expand row height instead of overflowing the panel. Source details separate encoding info, string/use locations, and raw data.

## Hotkeys

| Action | macOS | Linux/Windows |
| --- | --- | --- |
| Decompile current function | `Cmd+Shift+D` | `F5` |
| Toggle Paradise Pseudocode | `Tab` | `Tab` |
| Back / Forward | `Cmd+Left` / `Cmd+Right` | `Alt+Left` / `Alt+Right` |
| Back or close | `Esc` | `Esc` |
| Search pseudocode | `Cmd+F` or `/` | `Ctrl+F` or `/` |
| Find next | `F3` | `F3` |
| Rename | `N` | `N` |
| Retype / signature | `Y` | `Y` |
| Comment | `;` | `;` |
| Show xrefs | `X` | `X` |
| Trace variable | `T` | `T` |
| Follow selected token | `Enter` | `Enter` |
| Jump to disassembly | `Space` | `Space` |
| Go to | `G` | `G` |

Hotkeys can be disabled from Paradise settings.

## Settings

Open `Paradise > Options > Settings`.

The settings window uses a left sidebar instead of top tabs, so selected section labels stay readable across Ghidra themes. Each page has a bold header and grouped controls.

- `General`: hotkeys, Listing sync, external-location follow, matching-token highlighting, callee/xref navigation behavior, detected-main opening, and decompiler timeout.
- `Pseudocode`: theme preset, font size, gutter, line numbers, token addresses, current-line highlight, and brace matching.
- `Views`: choose which bottom analysis tabs are visible.
- `Inspector`: show or hide the URL/path/shell Inspector window, merge repeated Inspector rows, choose the Inspector detail renderer, and choose which Inspector table columns are visible.
- `Cleanup`: enable or disable individual Clean C cleanup families, type aliases, and address comments.
- `Export`: one combined C file or one file per function, plus optional metadata JSON.
- `Layout`: reset Paradise pane, tab, theme, and cleanup defaults.

## Cleanup Policy

Clean C mode is intentionally conservative.

- It is meant to improve review readability, not to mutate Ghidra's database.
- It preserves Ghidra-emitted function and data names unless the user explicitly renames something.
- It records applied cleanup rules in the `Cleanups` tab.
- It keeps exports deterministic by using the same cleanup path as the display view.

Some cleanup and trace results are heuristic. Treat them as review assistance, not as a substitute for manual analysis.

## Repository Layout

```text
src/main/java/paradise/
  ParadisePlugin.java               Main plugin, menu actions, settings, exports
  ParadiseDecompilerProvider.java   Paradise Pseudocode provider and analysis tabs
  ParadiseDecompilerEngine.java     Decompiler wrapper and Clean C cleanup pass
  ParadiseGraphProvider.java        IDA-style diagram provider
  ParadiseFindProvider.java         Paradise Inspector dockable window
  ParadiseFindScanner.java          URL/path/shell inspection scanner
  ParadiseDecodeUtil.java           Encoded string decoding helpers
  ParadiseStringUtil.java           String discovery and rendering helpers
  ParadiseXrefRow.java              Xref table model row

extension.properties                Ghidra extension metadata
build.gradle                        Ghidra extension build configuration
Module.manifest                     Ghidra module manifest
```

## Development Notes

The extension is optimized for review workflow experiments around Ghidra's `DecompInterface`. New cleanup rules should stay deterministic and should not perform database edits. If a feature needs a Ghidra database mutation, keep it behind an explicit user action.

Paradise is still under active development, and contributions, bug reports, and pull requests are welcome.
