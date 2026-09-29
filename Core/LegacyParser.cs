using System.Text.RegularExpressions;

namespace IpsReader.Core;

/// <summary>Extracts data from the text crash report format (.crash files and pre-iOS 15 .ips).</summary>
internal static partial class LegacyParser
{
    [GeneratedRegex(@"^(?<k>[A-Za-z][A-Za-z /]*?):\s+(?<v>.+)$")]
    private static partial Regex KeyValue();

    [GeneratedRegex(@"^Thread (?<n>\d+) name:\s*(?<name>.*)$")]
    private static partial Regex ThreadName();

    [GeneratedRegex(@"^Thread (?<n>\d+)(?<c> Crashed)?:\s*$")]
    private static partial Regex ThreadStart();

    [GeneratedRegex(@"^Thread \d+ crashed with .*State")]
    private static partial Regex RegistersStart();

    [GeneratedRegex(@"(?<k>\w+):\s+(?<v>0x[0-9a-fA-F]+)")]
    private static partial Regex RegisterPair();

    [GeneratedRegex(@"^(?<i>\d+)\s+(?<img>.+?)\s+(?<addr>0x[0-9a-fA-F]+)\s+(?<sym>.*)$")]
    private static partial Regex FrameLine();

    [GeneratedRegex(@"^\s*(?<b>0x[0-9a-fA-F]+)\s*-\s*(?<e>0x[0-9a-fA-F]+)\s+\+?(?<name>\S+)\s+(?<arch>\S+)\s+<(?<uuid>[0-9a-fA-F-]+)>\s+(?<path>.*)$")]
    private static partial Regex ImageLine();

    [GeneratedRegex(@"Namespace\s+(?<ns>\w+),\s*Code\s+(?<code>\S+)")]
    private static partial Regex TerminationNs();

    [GeneratedRegex(@"^(?<name>.*?)\s*\[(?<pid>\d+)\]")]
    private static partial Regex NameAndPid();

    public static void Fill(CrashReport r, string text)
    {
        var lines = text.Replace("\r\n", "\n").Split('\n');
        var names = new Dictionary<int, string>();
        ThreadInfo? current = null;
        var threads = new List<ThreadInfo>();
        var registers = new List<RegisterInfo>();
        var images = new List<BinaryImage>();
        string mode = "header";
        bool inAsi = false;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd();

            if (line.StartsWith("Binary Images:")) { mode = "images"; continue; }
            if (mode == "images")
            {
                var im = ImageLine().Match(line);
                if (im.Success)
                {
                    ulong b = Js.ParseNumber(im.Groups["b"].Value) ?? 0;
                    ulong e = Js.ParseNumber(im.Groups["e"].Value) ?? b;
                    images.Add(new BinaryImage
                    {
                        Base = b,
                        Size = e >= b ? e - b + 1 : 0,
                        Name = im.Groups["name"].Value,
                        Arch = im.Groups["arch"].Value,
                        Uuid = im.Groups["uuid"].Value,
                        Path = im.Groups["path"].Value.Trim(),
                    });
                }
                continue;
            }

            if (line.StartsWith("Last Exception Backtrace:"))
            {
                current = new ThreadInfo { Index = -1, IsExceptionBacktrace = true };
                r.ExceptionBacktrace = current;
                mode = "thread";
                continue;
            }

            var tn = ThreadName().Match(line);
            if (tn.Success) { names[int.Parse(tn.Groups["n"].Value)] = tn.Groups["name"].Value.Trim(); continue; }

            var ts = ThreadStart().Match(line);
            if (ts.Success)
            {
                int n = int.Parse(ts.Groups["n"].Value);
                current = new ThreadInfo { Index = n, Triggered = ts.Groups["c"].Success };
                if (names.TryGetValue(n, out var nm))
                {
                    if (nm.StartsWith("Dispatch queue:")) current.Queue = nm["Dispatch queue:".Length..].Trim();
                    else current.Name = nm;
                }
                threads.Add(current);
                mode = "thread";
                continue;
            }

            if (RegistersStart().IsMatch(line)) { mode = "registers"; continue; }

            if (mode == "registers")
            {
                if (line.Length == 0) { mode = "none"; continue; }
                foreach (Match m in RegisterPair().Matches(line))
                    registers.Add(new RegisterInfo { Name = m.Groups["k"].Value, Value = m.Groups["v"].Value });
                continue;
            }

            if (mode == "thread" && current is not null)
            {
                if (line.Length == 0) { current = null; mode = "none"; continue; }
                var fm = FrameLine().Match(line);
                if (fm.Success)
                {
                    var sym = fm.Groups["sym"].Value.Trim();
                    current.Frames.Add(new FrameInfo
                    {
                        Index = int.Parse(fm.Groups["i"].Value),
                        ImageName = fm.Groups["img"].Value.Trim(),
                        Address = Js.ParseNumber(fm.Groups["addr"].Value) ?? 0,
                        Symbol = sym,
                        IsSymbolicated = !sym.StartsWith("0x"),
                    });
                }
                continue;
            }

            if (line.StartsWith("Application Specific Information:")) { inAsi = true; continue; }
            if (inAsi)
            {
                if (line.Length == 0) inAsi = false;
                else r.Asi.Add(line.Trim());
                continue;
            }

            if (mode != "header") continue;
            var kv = KeyValue().Match(line);
            if (kv.Success) ApplyHeaderField(r, kv.Groups["k"].Value.Trim(), kv.Groups["v"].Value.Trim());
        }

        var appDir = IpsParser.AppBundleDir(r.ProcessPath);
        foreach (var img in images)
            img.IsApp = IpsParser.IsAppImage(img.Path, img.Name, appDir, r.ProcessName);
        if (r.Images.Count == 0) r.Images.AddRange(images);

        if (r.Threads.Count > 0) return; // structured JSON data takes precedence

        var all = new List<ThreadInfo>(threads);
        if (r.ExceptionBacktrace is not null) all.Add(r.ExceptionBacktrace);
        foreach (var th in all)
            for (int i = 0; i < th.Frames.Count; i++)
                th.Frames[i] = LinkImage(th.Frames[i], images, r.ProcessName);

        r.Threads.AddRange(threads.OrderBy(t => t.Index));
        if (r.FaultingThread is int ft && r.Threads.FirstOrDefault(t => t.Index == ft) is { } crashed)
            crashed.Triggered = true;
        var target = r.Threads.FirstOrDefault(t => t.Triggered);
        if (target is not null && target.Registers.Count == 0) target.Registers.AddRange(registers);
    }

    static FrameInfo LinkImage(FrameInfo f, List<BinaryImage> images, string? procName)
    {
        var img = images.FirstOrDefault(im => f.Address >= im.Base && f.Address <= im.End)
                  ?? images.FirstOrDefault(im => im.Name == f.ImageName);
        return new FrameInfo
        {
            Index = f.Index,
            ImageName = f.ImageName,
            Address = f.Address,
            ImageOffset = img is null ? 0 : f.Address - img.Base,
            Symbol = f.Symbol,
            IsSymbolicated = f.IsSymbolicated,
            Image = img,
            IsAppCode = img?.IsApp ?? (f.ImageName == procName),
        };
    }

    static void ApplyHeaderField(CrashReport r, string key, string value)
    {
        switch (key)
        {
            case "Incident Identifier": r.IncidentId ??= value; break;
            case "CrashReporter Key": r.CrashReporterKey ??= value; break;
            case "Hardware Model": r.ModelCode ??= value; break;
            case "Process":
                var np = NameAndPid().Match(value);
                if (np.Success) { r.ProcessName ??= np.Groups["name"].Value; r.Pid ??= np.Groups["pid"].Value; }
                else r.ProcessName ??= value;
                r.AppName ??= r.ProcessName;
                break;
            case "Path": r.ProcessPath ??= value; break;
            case "Identifier": r.BundleId ??= value; break;
            case "Version":
                var vm = Regex.Match(value, @"^(?<v>.*?)\s*\((?<b>.*)\)$");
                if (vm.Success) { r.AppVersion ??= vm.Groups["v"].Value; r.BuildVersion ??= vm.Groups["b"].Value; }
                else r.AppVersion ??= value;
                break;
            case "Code Type": r.CpuType ??= value; break;
            case "Role": r.Role ??= value; break;
            case "Parent Process": r.ParentProcess ??= value; break;
            case "Date/Time": r.Timestamp ??= value; break;
            case "Launch Time": r.LaunchTime ??= value; break;
            case "OS Version": r.OsVersion ??= value; break;
            case "Release Type": r.ReleaseType ??= value; break;
            case "Exception Type":
                var em = Regex.Match(value, @"^(?<t>\S+)\s*(\((?<s>[^)]*)\))?");
                r.ExceptionType ??= em.Groups["t"].Value;
                if (em.Groups["s"].Success) r.ExceptionSignal ??= em.Groups["s"].Value;
                break;
            case "Exception Subtype": r.ExceptionSubtype ??= value; break;
            case "Exception Codes": r.ExceptionCodes ??= value; break;
            case "Exception Message":
            case "Exception Note": r.ExceptionMessage ??= value; break;
            case "Termination Reason":
                var tm = TerminationNs().Match(value);
                if (tm.Success)
                {
                    r.TerminationNamespace ??= tm.Groups["ns"].Value;
                    r.TerminationCode ??= Js.ParseNumber(tm.Groups["code"].Value);
                }
                else
                {
                    var parts = value.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0) r.TerminationNamespace ??= parts[0];
                    if (parts.Length > 1) r.TerminationCode ??= Js.ParseNumber(parts[1]);
                    if (parts.Length > 2) r.TerminationIndicator ??= parts[2];
                }
                break;
            case "Termination Description": r.TerminationReasons ??= value; break;
            case "Terminating Process": r.TerminatingProcess ??= value; break;
            case "Triggered by Thread":
            case "Crashed Thread":
                if (int.TryParse(value.Split(' ')[0], out var ft)) r.FaultingThread ??= ft;
                break;
        }
    }
}
