using System.Text.Json.Nodes;

namespace IpsReader.Core;

public sealed class BinaryImage
{
    public ulong Base { get; init; }
    public ulong Size { get; init; }
    public string Name { get; init; } = "???";
    public string Arch { get; init; } = "";
    public string Uuid { get; init; } = "";
    public string Path { get; init; } = "";
    public bool IsApp { get; set; }

    public ulong End => Size > 0 ? Base + Size - 1 : Base;
    public string BaseHex => $"0x{Base:x}";
    public string EndHex => $"0x{End:x}";
}

public sealed class FrameInfo
{
    public int Index { get; init; }
    public string ImageName { get; init; } = "???";
    public ulong Address { get; init; }
    public ulong ImageOffset { get; init; }
    public string Symbol { get; init; } = "";
    public string? SourceLocation { get; init; }
    public bool IsAppCode { get; init; }
    public bool IsSymbolicated { get; init; }
    public BinaryImage? Image { get; init; }

    public string AddressHex => $"0x{Address:x16}";
    public string SymbolDisplay => SourceLocation is null ? Symbol : $"{Symbol} ({SourceLocation})";
}

public sealed class RegisterInfo
{
    public string Name { get; init; } = "";
    public string Value { get; init; } = "";
    public string Note { get; init; } = "";
}

public sealed class ThreadInfo
{
    public int Index { get; init; }
    public string? Id { get; init; }
    public string? Name { get; set; }
    public string? Queue { get; set; }
    public bool Triggered { get; set; }
    public bool IsExceptionBacktrace { get; init; }
    public List<FrameInfo> Frames { get; init; } = [];
    public List<RegisterInfo> Registers { get; init; } = [];

    public string DisplayTitle => IsExceptionBacktrace ? "Last Exception Backtrace" : $"Thread {Index}";

    public string DisplaySubtitle
    {
        get
        {
            if (IsExceptionBacktrace) return "Where the exception was thrown";
            var parts = new[] { Name, Queue }.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct();
            var text = string.Join(" · ", parts);
            return text.Length > 0 ? text : $"{Frames.Count} frames";
        }
    }

    public string Badge => Triggered ? "CRASH" : IsExceptionBacktrace ? "EXCEPTION" : "";
    public bool HasBadge => Badge.Length > 0;
    public string BadgeColor => Triggered ? "#D93025" : "#E37400";
}

public sealed class CrashReport
{
    public string? FilePath { get; set; }
    public string RawText { get; set; } = "";
    public JsonNode? Header { get; set; }
    public JsonNode? Body { get; set; }
    public bool IsLegacyText { get; set; }
    public string? LegacyText { get; set; }

    public string? BugType { get; set; }
    public string? AppName { get; set; }
    public string? AppVersion { get; set; }
    public string? BuildVersion { get; set; }
    public string? BundleId { get; set; }
    public string? OsVersion { get; set; }
    public string? ReleaseType { get; set; }
    public string? Timestamp { get; set; }
    public string? LaunchTime { get; set; }
    public string? IncidentId { get; set; }
    public string? CrashReporterKey { get; set; }
    public string? ModelCode { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string? Pid { get; set; }
    public string? ParentProcess { get; set; }
    public string? CpuType { get; set; }
    public string? Role { get; set; }

    public string? ExceptionType { get; set; }
    public string? ExceptionSignal { get; set; }
    public string? ExceptionSubtype { get; set; }
    public string? ExceptionCodes { get; set; }
    public string? ExceptionMessage { get; set; }

    public string? TerminationNamespace { get; set; }
    public ulong? TerminationCode { get; set; }
    public string? TerminationIndicator { get; set; }
    public string? TerminationReasons { get; set; }
    public string? TerminatingProcess { get; set; }

    /// <summary>Name/reason of an uncaught ObjC/C++ exception (exceptionReason field, iOS 15+).</summary>
    public string? ExceptionName { get; set; }
    public string? ExceptionReason { get; set; }

    public List<string> Asi { get; } = [];
    public int? FaultingThread { get; set; }
    public List<ThreadInfo> Threads { get; } = [];
    public ThreadInfo? ExceptionBacktrace { get; set; }
    public List<BinaryImage> Images { get; } = [];
    public string? PanicString { get; set; }

    public ThreadInfo? CrashedThread =>
        FaultingThread is int i && i >= 0 && i < Threads.Count ? Threads[i] : Threads.FirstOrDefault(t => t.Triggered);

    public string BugTypeName => BugType switch
    {
        "109" => "Crash (legacy format)",
        "309" => "Crash",
        "288" => "Stackshot / hang",
        "298" => "Jetsam (out of memory)",
        "210" => "Kernel panic",
        "211" => "Analytics log",
        null => IsLegacyText ? "Crash (text)" : "Unknown",
        _ => $"bug_type {BugType}",
    };
}

public enum FindingLevel { Critical, Warning, Info, Tip }

public sealed class Finding(FindingLevel level, string title, string text, string? code = null)
{
    public FindingLevel Level { get; } = level;
    public string Title { get; } = title;
    public string Text { get; } = text;
    public string? Code { get; } = code;
    public bool HasCode => !string.IsNullOrEmpty(Code);
    public bool HasText => !string.IsNullOrEmpty(Text);

    public string Accent => Level switch
    {
        FindingLevel.Critical => "#D93025",
        FindingLevel.Warning => "#E37400",
        FindingLevel.Info => "#1A73E8",
        _ => "#188038",
    };

    public string LevelLabel => Level switch
    {
        FindingLevel.Critical => "LIKELY CAUSE",
        FindingLevel.Warning => "WARNING",
        FindingLevel.Info => "INFO",
        _ => "TIP",
    };
}

public sealed class CrashAnalysis
{
    public string Category { get; set; } = "";
    public string Headline { get; set; } = "";
    public List<Finding> Findings { get; } = [];
    public FrameInfo? SuspectFrame { get; set; }
    public ThreadInfo? SuspectThread { get; set; }
    public bool IsCritical => Findings.Any(f => f.Level == FindingLevel.Critical);
}
