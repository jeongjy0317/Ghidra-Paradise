# Ghidra's Paradise

Paradise is a Ghidra extension that adds an IDA-like pseudocode and graph workflow on top of Ghidra's native decompiler. It is built for fast reverse-engineering review: cleaner C-like output, function tabs, diagram navigation, xrefs, strings, local variables, cleanup reporting, triage hints, and export tools live in one dockable workflow.

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
  - `Strings`
  - `Diff`
  - `Drafts`
  - `Suggestions`
  - `Triage`
  - `Cleanups`
- Variable trace view that follows the current pseudocode line and shows static/symbolic value estimates where possible.
- Suggestions and triage views for review targets such as suspicious XOR operations, call-heavy functions, string-heavy functions, and likely entry logic.
- Cleanups view showing which cleanup rules affected the current pseudocode.
- Export current function or all non-external functions as C-like pseudocode, with optional metadata JSON.
- Tabbed settings dialog for general behavior, pseudocode display, visible analysis views, cleanup rules, export mode, and layout reset.

## Requirements

- Ghidra 12.1
- A JDK supported by your Ghidra installation
- macOS, Linux, or Windows supported by Ghidra

The repository is currently developed against the Homebrew Ghidra 12.1 layout on macOS, but the extension uses the standard Ghidra extension build system.

## Build

Set `GHIDRA_INSTALL_DIR` to your Ghidra installation, or pass it with `-P`.
This path is machine-specific. It depends on your OS, install method, Ghidra version, and local install location. The Homebrew path below is only an example; use the directory on your system that contains `support/buildExtension.gradle`.

```sh
/opt/homebrew/Cellar/ghidra/12.1/libexec/support/gradle/gradlew \
  -PGHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1/libexec \
  clean buildExtension
```

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
- `Paradise > Options > Settings` to configure display, cleanup, export, and visible analysis tabs.
- `Paradise > Export > Export Current Function` or `Export All Functions` to write cleaned C-like output.

Paradise also exposes provider-local toolbar buttons in the Pseudocode and Diagram windows. Hover a toolbar icon in Ghidra to see the action name.

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

- `General`: hotkeys, Listing sync, external-location follow, xref behavior.
- `Pseudocode`: timeout, font size, gutter, line numbers, token addresses, current-line highlight, brace matching, new-tab callee behavior, use highlighting.
- `Views`: choose which bottom analysis tabs are visible.
- `Cleanup`: enable or disable individual Clean C cleanup families.
- `Export`: one combined C file or one file per function, plus optional metadata JSON.
- `Layout`: reset Paradise layout defaults.

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
  ParadiseStringUtil.java           String discovery and rendering helpers
  ParadiseXrefRow.java              Xref table model row

extension.properties                Ghidra extension metadata
build.gradle                        Ghidra extension build configuration
Module.manifest                     Ghidra module manifest
testbed/                            Local decompile/export test artifacts
```

## Development Notes

The extension is optimized for review workflow experiments around Ghidra's `DecompInterface`. New cleanup rules should stay deterministic and should not perform database edits. If a feature needs a Ghidra database mutation, keep it behind an explicit user action.

Paradise is still under active development, and contributions, bug reports, and pull requests are welcome.
