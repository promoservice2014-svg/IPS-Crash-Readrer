using System.Text.Json;
using System.Text.Json.Nodes;
using static IpsReader.Core.Js;

namespace IpsReader.Core;

/// <summary>
/// Reads Apple .ips files. Modern format (iOS 15+): a one-line JSON header followed by a JSON body.
/// Older format: a JSON header line followed by the report as plain text. Plain-text .crash files
/// are accepted too.
/// </summary>
public static class IpsParser
{
    static readonly JsonDocumentOptions DocOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    public static CrashReport Load(string path)
    {
        var report = Parse(File.ReadAllText(path));
        report.FilePath = path;
        return report;
    }

    public static CrashReport Parse(string text)
    {
        var r = new CrashReport { RawText = text };
        var t = text.TrimStart('﻿', ' ', '\t', '\r', '\n');
        JsonNode? header = null, body = null;
        string? legacy = null;

        if (t.StartsWith('{'))
        {
            int nl = t.IndexOf('\n');
            string first = (nl < 0 ? t : t[..nl]).Trim();
            string rest = nl < 0 ? "" : t[(nl + 1)..].Trim();

            header = TryParse(first);
            if (header is null)
            {
                body = TryParse(t); // a single multi-line JSON document
            }
            else if (rest.Length == 0)
            {
                if (header["threads"] is not null || header["exception"] is not null)
                    (body, header) = (header, null);
            }
            else if (rest.StartsWith('{'))
            {
                body = TryParse(rest);
            }
            else
            {
                legacy = rest;
            }
        }
        else
        {
            legacy = t;
        }

        r.Header = header;
        r.Body = body;
        if (header is not null || body is not null)
            FillFromJson(r, header, body);

        if (legacy is not null)
        {
            r.IsLegacyText = true;
            r.LegacyText = legacy;
            LegacyParser.Fill(r, legacy);
        }

        return r;
    }

    static JsonNode? TryParse(string json)
    {
        try { return JsonNode.Parse(json, documentOptions: DocOptions); }
        catch (JsonException) { return null; }
    }

    static void FillFromJson(CrashReport r, JsonNode? h, JsonNode? b)
    {
        var bundle = b?["bundleInfo"];
        var os = b?["osVersion"];

        r.BugType = S(h, "bug_type") ?? S(b, "bug_type");
        r.AppName = S(h, "app_name") ?? S(b, "procName") ?? S(h, "name");
        r.AppVersion = S(h, "app_version") ?? S(bundle, "CFBundleShortVersionString");
        r.BuildVersion = S(h, "build_version") ?? S(bundle, "CFBundleVersion");
        r.BundleId = S(h, "bundleID") ?? S(bundle, "CFBundleIdentifier");
        r.OsVersion = S(h, "os_version")
                      ?? (os is JsonObject ? $"{S(os, "train")} ({S(os, "build")})" : S(b, "osVersion"));
        r.ReleaseType = S(os, "releaseType");
        r.Timestamp = S(h, "timestamp") ?? S(b, "captureTime");
        r.IncidentId = S(h, "incident_id") ?? S(b, "incident");
        r.CrashReporterKey = S(b, "crashReporterKey");
        r.ModelCode = S(b, "modelCode") ?? S(b, "product");
        r.ProcessName = S(b, "procName") ?? r.AppName;
        r.ProcessPath = S(b, "procPath");
        r.Pid = S(b, "pid");
        r.CpuType = S(b, "cpuType");
        r.Role = S(b, "procRole");
        r.LaunchTime = S(b, "procLaunch");
        var parent = S(b, "parentProc");
        if (parent is not null)
            r.ParentProcess = S(b, "parentPid") is string ppid ? $"{parent} [{ppid}]" : parent;

        var ex = b?["exception"];
        r.ExceptionType = S(ex, "type");
        r.ExceptionSignal = S(ex, "signal");
        r.ExceptionSubtype = S(ex, "subtype");
        r.ExceptionCodes = S(ex, "codes");
        r.ExceptionMessage = S(ex, "message");

        var term = b?["termination"];
        r.TerminationNamespace = S(term, "namespace");
        r.TerminationCode = U(term?["code"]);
        r.TerminationIndicator = S(term, "indicator");
        if (term?["reasons"] is JsonArray reasons)
            r.TerminationReasons = string.Join("\n", reasons.Select(Str).Where(s => s is not null));
        else
            r.TerminationReasons = S(term, "details") ?? S(term, "reason");
        var byProc = S(term, "byProc");
        if (byProc is not null)
            r.TerminatingProcess = S(term, "byPid") is string bpid ? $"{byProc} [{bpid}]" : byProc;

        var exReason = b?["exceptionReason"];
        r.ExceptionName = S(exReason, "name");
        r.ExceptionReason = S(exReason, "reason") ?? S(exReason, "composed_message");

        if (b?["asi"] is JsonObject asi)
        {
            foreach (var (lib, val) in asi)
            {
                if (val is JsonArray arr)
                    foreach (var item in arr) { if (Str(item) is string s) r.Asi.Add($"{lib}: {s}"); }
                else if (Str(val) is string s)
                    r.Asi.Add($"{lib}: {s}");
            }
        }

        r.PanicString = S(b, "panicString") ?? S(b, "panic_string");
        r.FaultingThread = I(b?["faultingThread"]);

        ParseImages(r, b);

        if (b?["threads"] is JsonArray threads)
        {
            for (int i = 0; i < threads.Count; i++)
            {
                var tn = threads[i];
                var th = new ThreadInfo
                {
                    Index = i,
                    Id = S(tn, "id"),
                    Name = S(tn, "name"),
                    Queue = S(tn, "queue"),
                    Triggered = B(tn?["triggered"]) || r.FaultingThread == i,
                    Frames = ParseFrames(tn?["frames"] as JsonArray, r.Images),
                    Registers = ParseRegisters(tn?["threadState"]),
                };
                r.Threads.Add(th);
            }
        }

        if (b?["lastExceptionBacktrace"] is JsonArray leb && leb.Count > 0)
        {
            r.ExceptionBacktrace = new ThreadInfo
            {
                Index = -1,
                IsExceptionBacktrace = true,
                Frames = ParseFrames(leb, r.Images),
            };
        }
    }

    static void ParseImages(CrashReport r, JsonNode? b)
    {
        if (b?["usedImages"] is not JsonArray imgs) return;
        var appDir = AppBundleDir(r.ProcessPath);

        foreach (var n in imgs)
        {
            var path = S(n, "path");
            var name = S(n, "name") ?? (path is not null ? path[(path.LastIndexOf('/') + 1)..] : "???");
            r.Images.Add(new BinaryImage
            {
                Base = U(n?["base"]) ?? 0,
                Size = U(n?["size"]) ?? 0,
                Name = name,
                Arch = S(n, "arch") ?? "",
                Uuid = S(n, "uuid") ?? "",
                Path = path ?? "",
                IsApp = IsAppImage(path, name, appDir, r.ProcessName),
            });
        }
    }

    internal static string? AppBundleDir(string? procPath)
    {
        if (procPath is null) return null;
        int idx = procPath.IndexOf(".app/", StringComparison.OrdinalIgnoreCase);
        return idx >= 0 ? procPath[..(idx + 5)] : null;
    }

    internal static bool IsAppImage(string? path, string name, string? appDir, string? procName)
    {
        if (string.IsNullOrEmpty(path))
            return procName is not null && name == procName;
        if (appDir is not null)
            return path.StartsWith(appDir, StringComparison.OrdinalIgnoreCase);
        return path.Contains("/Bundle/Application/", StringComparison.OrdinalIgnoreCase)
               || (procName is not null && name == procName);
    }

    static List<FrameInfo> ParseFrames(JsonArray? arr, List<BinaryImage> images)
    {
        var frames = new List<FrameInfo>();
        if (arr is null) return frames;

        for (int i = 0; i < arr.Count; i++)
        {
            var n = arr[i];
            var img = I(n?["imageIndex"]) is int k && k >= 0 && k < images.Count ? images[k] : null;
            ulong offset = U(n?["imageOffset"]) ?? 0;
            ulong baseAddr = img?.Base ?? 0;
            string? sym = S(n, "symbol");
            ulong? loc = U(n?["symbolLocation"]);

            string symbolText = sym is not null
                ? (loc is ulong l ? $"{sym} + {l}" : sym)
                : $"0x{baseAddr:x} + {offset}";

            string? source = S(n, "sourceFile") is string file
                ? (S(n, "sourceLine") is string line ? $"{file}:{line}" : file)
                : null;

            frames.Add(new FrameInfo
            {
                Index = i,
                ImageName = img?.Name ?? "???",
                Address = baseAddr + offset,
                ImageOffset = offset,
                Symbol = symbolText,
                SourceLocation = source,
                IsAppCode = img?.IsApp ?? false,
                IsSymbolicated = sym is not null,
                Image = img,
            });
        }
        return frames;
    }

    static List<RegisterInfo> ParseRegisters(JsonNode? state)
    {
        var list = new List<RegisterInfo>();
        if (state is JsonObject o) AddRegisters(list, o, "");
        return list;
    }

    static void AddRegisters(List<RegisterInfo> list, JsonObject o, string prefix)
    {
        foreach (var (key, val) in o)
        {
            if (key == "flavor") continue;
            if (val is JsonArray arr)
            {
                for (int j = 0; j < arr.Count; j++) list.Add(Register($"{prefix}{key}{j}", arr[j]));
            }
            else if (val is JsonObject obj)
            {
                if (obj.ContainsKey("value")) list.Add(Register(prefix + key, obj));
                else AddRegisters(list, obj, prefix + key + ".");
            }
        }
    }

    static RegisterInfo Register(string name, JsonNode? n)
    {
        ulong? v = n is JsonObject ? U(n["value"]) : U(n);
        return new RegisterInfo
        {
            Name = name,
            Value = v is ulong u ? $"0x{u:x16}" : "",
            Note = S(n, "symbol") ?? S(n, "description") ?? "",
        };
    }
}
