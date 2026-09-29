using System.Text;

namespace IpsReader.Core;

/// <summary>Converts a JSON IPS report into the classic, human-readable Apple crash report text format.</summary>
public static class ReportFormatter
{
    public static string FrameLine(FrameInfo f) =>
        $"{f.Index,-4}{f.ImageName,-32}\t{f.AddressHex} {f.SymbolDisplay}";

    public static string TerminationLine(CrashReport r)
    {
        var parts = new List<string>();
        if (r.TerminationNamespace is not null) parts.Add(r.TerminationNamespace);
        if (r.TerminationCode is ulong c) parts.Add(c < 0x10000 ? c.ToString() : $"0x{c:x}");
        if (!string.IsNullOrEmpty(r.TerminationIndicator)) parts.Add(r.TerminationIndicator);
        return string.Join(" ", parts);
    }

    public static string ToText(CrashReport r)
    {
        if (r.Body is null && r.IsLegacyText) return r.LegacyText ?? r.RawText;

        var sb = new StringBuilder();
        void L(string key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value)) sb.AppendLine($"{key + ":",-21}{value}");
        }

        L("Incident Identifier", r.IncidentId);
        L("CrashReporter Key", r.CrashReporterKey);
        L("Hardware Model", r.ModelCode);
        L("Process", r.ProcessName is null ? null : r.Pid is null ? r.ProcessName : $"{r.ProcessName} [{r.Pid}]");
        L("Path", r.ProcessPath);
        L("Identifier", r.BundleId);
        L("Version", r.AppVersion is null ? null : r.BuildVersion is null ? r.AppVersion : $"{r.AppVersion} ({r.BuildVersion})");
        L("Code Type", r.CpuType);
        L("Role", r.Role);
        L("Parent Process", r.ParentProcess);
        sb.AppendLine();
        L("Date/Time", r.Timestamp);
        L("Launch Time", r.LaunchTime);
        L("OS Version", r.OsVersion);
        L("Release Type", r.ReleaseType);
        L("Report Type", r.BugTypeName);
        sb.AppendLine();

        if (r.ExceptionType is not null)
        {
            L("Exception Type", r.ExceptionSignal is null ? r.ExceptionType : $"{r.ExceptionType} ({r.ExceptionSignal})");
            L("Exception Subtype", r.ExceptionSubtype);
            L("Exception Message", r.ExceptionMessage);
            L("Exception Codes", r.ExceptionCodes);
        }
        L("Termination Reason", TerminationLine(r));
        if (!string.IsNullOrWhiteSpace(r.TerminationReasons))
            sb.AppendLine(r.TerminationReasons);
        L("Terminating Process", r.TerminatingProcess);
        sb.AppendLine();

        if (r.ExceptionName is not null || r.ExceptionReason is not null)
        {
            L("Exception Name", r.ExceptionName);
            L("Exception Reason", r.ExceptionReason);
            sb.AppendLine();
        }

        if (r.FaultingThread is int ft)
        {
            sb.AppendLine($"Triggered by Thread:  {ft}");
            sb.AppendLine();
        }

        if (r.Asi.Count > 0)
        {
            sb.AppendLine("Application Specific Information:");
            foreach (var line in r.Asi) sb.AppendLine(line);
            sb.AppendLine();
        }

        if (!string.IsNullOrWhiteSpace(r.PanicString))
        {
            sb.AppendLine("Panic String:");
            sb.AppendLine(r.PanicString);
            sb.AppendLine();
        }

        if (r.ExceptionBacktrace is { } leb)
        {
            sb.AppendLine("Last Exception Backtrace:");
            foreach (var f in leb.Frames) sb.AppendLine(FrameLine(f));
            sb.AppendLine();
        }

        foreach (var t in r.Threads)
        {
            if (t.Name is not null) sb.AppendLine($"Thread {t.Index} name:   {t.Name}");
            if (t.Queue is not null) sb.AppendLine($"Thread {t.Index} name:   Dispatch queue: {t.Queue}");
            sb.AppendLine(t.Triggered ? $"Thread {t.Index} Crashed:" : $"Thread {t.Index}:");
            foreach (var f in t.Frames) sb.AppendLine(FrameLine(f));
            sb.AppendLine();
        }

        if (r.CrashedThread is { Registers.Count: > 0 } crashed)
        {
            var arch = r.CpuType?.Contains("ARM", StringComparison.OrdinalIgnoreCase) == true ? "ARM" : "X86";
            sb.AppendLine($"Thread {crashed.Index} crashed with {arch} Thread State (64-bit):");
            for (int i = 0; i < crashed.Registers.Count; i += 4)
            {
                var row = crashed.Registers.Skip(i).Take(4).Select(reg => $"{reg.Name,6}: {reg.Value}");
                sb.AppendLine("  " + string.Join("  ", row));
            }
            sb.AppendLine();
        }

        if (r.Images.Count > 0)
        {
            sb.AppendLine("Binary Images:");
            foreach (var img in r.Images.Where(i => i.Base != 0 || i.Size != 0))
            {
                var uuid = img.Uuid.Replace("-", "").ToLowerInvariant();
                sb.AppendLine($"{img.BaseHex,18} - {img.EndHex,18} {img.Name} {img.Arch}  <{uuid}> {img.Path}");
            }
            sb.AppendLine();
        }

        if (r.Threads.Count == 0 && r.PanicString is null && r.Body is not null)
            sb.AppendLine("(This report contains no threads: see the Raw JSON tab for the full content.)");

        return sb.ToString();
    }
}
