using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using IpsReader.Core;

namespace IpsReader;

public sealed class ReportViewModel
{
    static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public ReportViewModel(CrashReport report, CrashAnalysis analysis)
    {
        Report = report;
        Analysis = analysis;

        if (report.ExceptionBacktrace is not null) Threads.Add(report.ExceptionBacktrace);
        Threads.AddRange(report.Threads);
        InitialThread = analysis.SuspectThread ?? report.CrashedThread ?? Threads.FirstOrDefault();

        ReportText = ReportFormatter.ToText(report);
        RawJson = BuildRawJson(report);
        Info = BuildInfo(report);

        var stackThread = InitialThread;
        if (stackThread is not null)
        {
            StackTitle = $"Stack — {stackThread.DisplayTitle}" + (stackThread.Triggered ? " (crashed)" : "");
            StackPreview = string.Join("\n", stackThread.Frames.Take(25).Select(ReportFormatter.FrameLine))
                           + (stackThread.Frames.Count > 25 ? $"\n… {stackThread.Frames.Count - 25} more frames in the Threads tab" : "");
        }
    }

    public CrashReport Report { get; }
    public CrashAnalysis Analysis { get; }
    public List<ThreadInfo> Threads { get; } = [];
    public ThreadInfo? InitialThread { get; }
    public List<BinaryImage> Images => Report.Images;
    public List<KeyValuePair<string, string>> Info { get; }
    public string ReportText { get; }
    public string RawJson { get; }
    public string StackTitle { get; } = "";
    public string StackPreview { get; } = "";
    public bool HasStack => StackPreview.Length > 0;

    public string Title
    {
        get
        {
            var name = Report.AppName ?? Report.ProcessName ?? Path.GetFileName(Report.FilePath) ?? "Report";
            return Report.AppVersion is null ? name : $"{name}  {Report.AppVersion}" + (Report.BuildVersion is null ? "" : $" ({Report.BuildVersion})");
        }
    }

    public string Subtitle => string.Join("  ·  ", new[]
    {
        Report.BundleId, DeviceModels.Describe(Report.ModelCode), Report.OsVersion, Report.Timestamp,
    }.Where(s => !string.IsNullOrWhiteSpace(s)));

    public string HeadlineBackground => Analysis.IsCritical ? "#FDECEA" : "#E8F0FE";
    public string HeadlineColor => Analysis.IsCritical ? "#B3261E" : "#1A56DB";
    public string ThreadsHeader => $"Threads ({Report.Threads.Count})";
    public string ImagesHeader => $"Binary Images ({Report.Images.Count})";

    static List<KeyValuePair<string, string>> BuildInfo(CrashReport r)
    {
        var list = new List<KeyValuePair<string, string>>();
        void Add(string k, string? v) { if (!string.IsNullOrWhiteSpace(v)) list.Add(new(k, v)); }

        Add("Application", r.AppName);
        Add("Version", r.AppVersion is null ? null : r.BuildVersion is null ? r.AppVersion : $"{r.AppVersion} ({r.BuildVersion})");
        Add("Bundle ID", r.BundleId);
        Add("Device", DeviceModels.Describe(r.ModelCode));
        Add("OS version", r.OsVersion);
        Add("Crash date/time", r.Timestamp);
        Add("Process launch", r.LaunchTime);
        Add("Process", r.ProcessName is null ? null : r.Pid is null ? r.ProcessName : $"{r.ProcessName} [{r.Pid}]");
        Add("Architecture", r.CpuType);
        Add("Role", r.Role);
        Add("Exception", r.ExceptionType is null ? null : r.ExceptionSignal is null ? r.ExceptionType : $"{r.ExceptionType} ({r.ExceptionSignal})");
        Add("Subtype", r.ExceptionSubtype);
        Add("Codes", r.ExceptionCodes);
        Add("Termination", ReportFormatter.TerminationLine(r));
        if (r.CrashedThread is { } t)
            Add("Crashed thread", (t.Name ?? t.Queue) is { } label ? $"{t.Index} — {label}" : $"{t.Index}");
        Add("Report type", r.BugTypeName);
        Add("Incident ID", r.IncidentId);
        Add("Path", r.ProcessPath);
        return list;
    }

    static string BuildRawJson(CrashReport r)
    {
        if (r.Header is null && r.Body is null)
            return "(This file contains no JSON: it is a plain-text crash report. See the \"Text Report\" tab.)";
        var sb = new StringBuilder();
        if (r.Header is not null)
        {
            sb.AppendLine("// ── Header ──");
            sb.AppendLine(r.Header.ToJsonString(PrettyJson));
            sb.AppendLine();
        }
        if (r.Body is not null)
        {
            sb.AppendLine("// ── Report body ──");
            sb.AppendLine(r.Body.ToJsonString(PrettyJson));
        }
        return sb.ToString();
    }

    public string DiagnosisText()
    {
        var sb = new StringBuilder();
        sb.AppendLine(Title);
        sb.AppendLine(Subtitle);
        sb.AppendLine();
        sb.AppendLine($"Diagnosis: {Analysis.Headline}");
        sb.AppendLine();
        foreach (var kv in Info) sb.AppendLine($"{kv.Key + ":",-20} {kv.Value}");
        sb.AppendLine();
        foreach (var f in Analysis.Findings)
        {
            sb.AppendLine($"[{f.LevelLabel}] {f.Title}");
            if (f.HasText) sb.AppendLine(f.Text);
            if (f.HasCode) sb.AppendLine(f.Code);
            sb.AppendLine();
        }
        if (HasStack)
        {
            sb.AppendLine(StackTitle);
            sb.AppendLine(StackPreview);
        }
        return sb.ToString();
    }
}
