# IPS Reader

A Windows app (WPF, .NET 8) for opening and analyzing iOS crash reports (`.ips`, `.crash`).

## Features

- **Summary**: app, version, device (marketing name), iOS version, exception and an **automatic diagnosis**:
  - invalid memory access (`EXC_BAD_ACCESS`: null pointer, deallocated object, PAC, protected memory)
  - Swift runtime errors (force unwrap of nil, index out of range, overflow, `as!`, `try!`, `fatalError`)
  - uncaught Objective-C/C++ exceptions, heap corruption, assertions
  - watchdog `0x8badf00d`, `0xdead10cc`, overheating, force quit, and why the main thread was blocked
  - Jetsam (memory), code signing, missing libraries, infinite recursion, kernel panics
  - **suspect frame**: the first frame of the app's own code in the stack
  - a ready-made `atos` command when the app's frames are not symbolicated
- **Threads**: every thread plus the *Last Exception Backtrace*, with the app's code highlighted, an "App code only" filter and the registers.
- **Text Report**: the JSON report converted to the classic Apple format, with search (Ctrl+F) and export (Ctrl+S).
- **Binary Images** and formatted **Raw JSON**.
- Drag & drop, opening from the command line, and an **Associate .ips files** button to open them with a double click
  (registers the association for the current user only, under `HKCU\Software\Classes`).

Supported formats: modern `.ips` (iOS 15+, JSON header + JSON body), older `.ips` (JSON header + text), plain-text `.crash`.

## Running

```powershell
dotnet run                   # development
dotnet run -- path\file.ips  # open a file directly
```

## Building the executable

```powershell
# ARM64 PCs (e.g. Snapdragon) with the .NET 8 Desktop Runtime installed: ~0.3 MB exe
dotnet publish -c Release -r win-arm64 --self-contained false -p:PublishSingleFile=true -p:DebugType=none -o publish\arm64

# Fully self-contained (~68 MB), runs on any Windows x64 PC (and on ARM64 under emulation)
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -o publish\x64-standalone
```

Note: a framework-dependent `win-x64` exe does **not** start on Windows ARM64 when only the ARM64 .NET runtime is installed.

## Layout

| Path | Contents |
|---|---|
| `Core/IpsParser.cs` | Reads the JSON `.ips` format |
| `Core/LegacyParser.cs` | Reads the text format (`.crash`, older `.ips`) |
| `Core/CrashAnalyzer.cs` | Diagnosis rules |
| `Core/ReportFormatter.cs` | Conversion to an Apple-style text report |
| `ReportViewModel.cs`, `MainWindow.xaml` | User interface |
| `samples/` | Sample reports for testing |
| `Assets/app.ico` | App icon (16–256 px) |
| `tools/make-icon.ps1` | Regenerates the icon: `.\tools\make-icon.ps1 -OutIco Assets\app.ico` |

The `Core` folder does not depend on WPF, so it can be reused in a CLI or in tests.
