using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static IpsReader.Core.Js;

namespace IpsReader.Core;

/// <summary>Heuristics that turn raw crash data into a readable diagnosis.</summary>
public static partial class CrashAnalyzer
{
    [GeneratedRegex(@"\bat (0x[0-9a-fA-F]+)")]
    private static partial Regex FaultAddress();

    [GeneratedRegex(@"Swift runtime failure:\s*(?<msg>.+?)(\s\+\s\d+)?$")]
    private static partial Regex SwiftFailure();

    static readonly Dictionary<ulong, (string Title, string Text)> TerminationCodes = new()
    {
        [0x8badf00d] = ("Watchdog: the app was unresponsive (0x8badf00d)",
            "The system killed the app because the main thread was blocked for too long " +
            "(during launch, returning to the foreground, moving to the background or handling a system event). " +
            "Check the Thread 0 stack: synchronous networking, disk I/O, locks, heavy computation or a deadlock on the main thread."),
        [0xdead10cc] = ("File or database locked during suspension (0xdead10cc)",
            "The app was suspended while holding a lock on a file or SQLite database in a shared container " +
            "(App Group). Release locks before going to the background, or use beginBackgroundTask to finish the work."),
        [0xbaaaaaad] = ("System stackshot (0xbaaaaaad)",
            "Not a real crash: a snapshot of all processes requested by the user or the system (e.g. side button + volume)."),
        [0xbad22222] = ("VoIP app terminated (0xbad22222)",
            "The system killed a VoIP app because it resumed too frequently."),
        [0xc00010ff] = ("Terminated due to overheating (0xc00010ff)",
            "The system killed the app because of a thermal event: the device was too hot. " +
            "It may depend on the environment, but check for excessive CPU/GPU usage."),
        [0xdeadfa11] = ("Force quit by the user (0xdeadfa11)",
            "The user force-quit the app (e.g. by holding the power button while it was unresponsive). " +
            "This often means the app was hung: check the main thread."),
        [0x2bad45ec] = ("Security violation (0x2bad45ec)",
            "The system killed the app because of a security violation, for example trying to draw " +
            "to the screen when not allowed (screen locked)."),
    };

    public static CrashAnalysis Analyze(CrashReport r)
    {
        var a = new CrashAnalysis { Category = r.BugTypeName.ToUpperInvariant() };

        switch (r.BugType)
        {
            case "298": AnalyzeJetsam(r, a); break;
            case "210": AnalyzePanic(r, a); break;
            default: AnalyzeCrash(r, a); break;
        }

        if (string.IsNullOrEmpty(a.Headline))
        {
            a.Headline = a.Findings.FirstOrDefault(f => f.Level == FindingLevel.Critical)?.Title
                         ?? (r.ExceptionType is not null ? $"{r.ExceptionType} ({r.ExceptionSignal})" : "No crash cause identified");
        }
        return a;
    }

    static void AnalyzeCrash(CrashReport r, CrashAnalysis a)
    {
        var type = r.ExceptionType ?? "";
        var sig = r.ExceptionSignal ?? "";
        var sub = r.ExceptionSubtype ?? "";
        var crashed = r.CrashedThread;
        var asiAll = string.Join("\n", r.Asi);

        var topFrames = (crashed?.Frames ?? []).Take(10).ToList();
        if (r.ExceptionBacktrace is not null) topFrames.AddRange(r.ExceptionBacktrace.Frames.Take(10));
        bool Top(params string[] needles) =>
            topFrames.Any(f => needles.Any(n => f.Symbol.Contains(n, StringComparison.OrdinalIgnoreCase)));

        // 1. Known termination codes (watchdog, locks, thermal...)
        if (r.TerminationCode is ulong code && TerminationCodes.TryGetValue(code, out var known))
        {
            a.Findings.Add(new(FindingLevel.Critical, known.Title, known.Text));
            if (code is 0x8badf00d or 0xdeadfa11 && r.Threads.Count > 0)
                a.SuspectThread = r.Threads[0];
        }

        // 2. Exception type
        switch (type)
        {
            case "EXC_BAD_ACCESS":
                AnalyzeBadAccess(r, a, sub, Top);
                break;

            case "EXC_CRASH":
                if (sig == "SIGABRT") AnalyzeAbort(r, a, asiAll, Top);
                else if (sig == "SIGKILL" && !a.IsCritical)
                    a.Findings.Add(new(FindingLevel.Critical, "Process killed by the system (SIGKILL)",
                        "The operating system killed the process. The termination reason below explains why " +
                        "(watchdog, memory, code signing, etc.)."));
                else if (sig == "SIGTERM")
                    a.Findings.Add(new(FindingLevel.Warning, "Termination request (SIGTERM)",
                        "The process received an orderly shutdown request (e.g. app update or reboot)."));
                else if (!a.IsCritical)
                    a.Findings.Add(new(FindingLevel.Critical, $"Process crash ({sig})", "The process terminated abnormally."));
                break;

            case "EXC_BREAKPOINT":
            case "EXC_BAD_INSTRUCTION":
                AnalyzeTrap(r, a, type, asiAll, topFrames, Top);
                break;

            case "EXC_GUARD":
                a.Findings.Add(new(FindingLevel.Critical, "Guarded resource violation (EXC_GUARD)",
                    "The process misused a resource protected by the system, for example by closing a " +
                    "file descriptor owned by a framework (GUARD_TYPE_FD) or tampering with a guarded Mach port." +
                    (sub.Length > 0 ? $"\nDetail: {sub}" : "")));
                break;

            case "EXC_RESOURCE":
                var what = sub.Contains("MEMORY", StringComparison.OrdinalIgnoreCase) ? "memory limit"
                         : sub.Contains("CPU", StringComparison.OrdinalIgnoreCase) ? "CPU usage limit"
                         : sub.Contains("WAKEUPS", StringComparison.OrdinalIgnoreCase) ? "thread wakeups limit"
                         : sub.Contains("IO", StringComparison.OrdinalIgnoreCase) ? "disk writes limit"
                         : "resource limit";
                a.Findings.Add(new(FindingLevel.Critical, $"Exceeded the {what} (EXC_RESOURCE)",
                    $"The system detected excessive resource usage. {sub}".Trim()));
                break;

            case "EXC_ARITHMETIC":
                a.Findings.Add(new(FindingLevel.Critical, "Arithmetic error (EXC_ARITHMETIC)",
                    "Typically an integer division by zero in C/C++/Objective-C code."));
                break;

            case "":
                break;

            default:
                if (!a.IsCritical)
                    a.Findings.Add(new(FindingLevel.Warning, $"Exception {type} ({sig})", sub));
                break;
        }

        // 3. Termination namespace
        switch (r.TerminationNamespace?.ToUpperInvariant())
        {
            case "CODESIGNING":
                a.Findings.Add(new(FindingLevel.Critical, "Invalid code signature",
                    "The system rejected code with an invalid signature. Check the provisioning profile, " +
                    "the entitlements, and that the app or its frameworks were not modified after signing."));
                break;
            case "DYLD":
                a.Findings.Add(new(FindingLevel.Critical, "Missing or unloadable dynamic library",
                    "The dynamic linker could not load a library at launch. Make sure frameworks are " +
                    "embedded with 'Embed & Sign' and compatible with the device's iOS version."));
                break;
            case "JETSAM":
            case "MEMORYSTATUS":
                a.Findings.Add(new(FindingLevel.Critical, "Terminated due to memory pressure",
                    "The system killed the app because it used too much memory or the device ran out of memory."));
                break;
            case "WATCHDOG":
                if (!a.IsCritical)
                    a.Findings.Add(new(FindingLevel.Critical, "Watchdog: process hung",
                        "The process was unresponsive and was killed by the system watchdog."));
                break;
        }

        // 4. Infinite recursion
        if (crashed is { Frames.Count: >= 200 })
        {
            var top = crashed.Frames.GroupBy(f => f.Symbol).OrderByDescending(g => g.Count()).First();
            if (top.Count() >= 50)
                a.Findings.Add(new(FindingLevel.Warning, "Possible infinite recursion (stack overflow)",
                    $"The crashed thread has {crashed.Frames.Count} frames and \"{top.Key}\" repeats {top.Count()} times. " +
                    "A function that calls itself without an exit condition exhausts the stack."));
        }

        // 5. Additional information
        if (a.SuspectThread is { Frames.Count: > 0 } blocked)
            AddBlockingHint(blocked, a);
        if (!string.IsNullOrWhiteSpace(r.TerminationReasons))
            a.Findings.Add(new(FindingLevel.Info, "Termination reason",
                ReportFormatter.TerminationLine(r), r.TerminationReasons));
        if (!string.IsNullOrEmpty(r.ExceptionMessage))
            a.Findings.Add(new(FindingLevel.Info, "Exception message", r.ExceptionMessage));
        if (r.Asi.Count > 0)
            a.Findings.Add(new(FindingLevel.Info, "Application Specific Information",
                "Messages logged by libraries at the time of the crash:", asiAll));

        FindSuspect(r, a);
        AddSymbolicationTip(r, a);
    }

    static void AnalyzeBadAccess(CrashReport r, CrashAnalysis a, string sub, Func<string[], bool> top)
    {
        ulong? addr = FaultAddress().Match(sub) is { Success: true } m ? ParseNumber(m.Groups[1].Value) : null;
        string addrText = addr is ulong v ? $"0x{v:x}" : "unknown";

        if (sub.Contains("pointer authentication", StringComparison.OrdinalIgnoreCase))
            a.Findings.Add(new(FindingLevel.Critical, "Pointer Authentication (PAC) failure",
                "A corrupted or incorrectly signed pointer was used. Typical of use-after-free, overwritten " +
                "memory, or pointers to objects/functions that are no longer valid."));
        else if (addr is < 0x10000)
            a.Findings.Add(new(FindingLevel.Critical, "Null pointer dereference",
                $"Access to address {addrText}, near NULL. A null pointer or reference was used " +
                "(e.g. an uninitialized C/C++ object, a null UnsafePointer, an unowned/unsafe reference to a released object). " +
                "A non-zero address means a field of a structure pointed to by NULL was being read."));
        else if (top(["objc_msgSend", "objc_retain", "objc_release", "objc_autorelease", "swift_retain",
                      "swift_release", "swift_unknownObjectRetain", "objc_loadWeak", "swift_unknownObjectRelease"]))
            a.Findings.Add(new(FindingLevel.Critical, "Access to an already deallocated object (zombie)",
                $"The crash happens during retain/release or a message send, at address {addrText}: an object was " +
                "used after being freed (over-release, unowned/unsafe reference, race condition). " +
                "Reproduce with Zombie Objects and Address Sanitizer enabled in Xcode."));
        else if (sub.Contains("KERN_PROTECTION_FAILURE", StringComparison.OrdinalIgnoreCase))
            a.Findings.Add(new(FindingLevel.Critical, "Access to protected memory",
                $"Attempt to write to read-only memory or execute non-executable memory ({addrText}). " +
                "It can also indicate a stack overflow (hitting the stack guard page)."));
        else if (sub.Contains("EXC_ARM_DA_ALIGN", StringComparison.OrdinalIgnoreCase))
            a.Findings.Add(new(FindingLevel.Critical, "Misaligned memory access",
                "Read or write at an incorrectly aligned address (C code with pointer casts)."));
        else
            a.Findings.Add(new(FindingLevel.Critical, "Access to an invalid memory address",
                $"Address {addrText} is not mapped. Typical causes: uninitialized or corrupted pointer, " +
                "use-after-free, buffer overflow, concurrent access from multiple threads without synchronization."));

        a.Findings.Add(new(FindingLevel.Tip, "How to reproduce it",
            "In Xcode (Scheme → Diagnostics) enable Address Sanitizer, Thread Sanitizer and Zombie Objects: " +
            "they turn most of these crashes into a precise error pointing at the offending line of code."));
    }

    static void AnalyzeAbort(CrashReport r, CrashAnalysis a, string asiAll, Func<string[], bool> top)
    {
        if (r.ExceptionName is not null || r.ExceptionReason is not null)
            a.Findings.Add(new(FindingLevel.Critical, $"Uncaught exception: {r.ExceptionName ?? "NSException"}",
                r.ExceptionReason ?? "", null));
        else if (r.ExceptionBacktrace is not null || top(["objc_exception_throw"]))
            a.Findings.Add(new(FindingLevel.Critical, "Uncaught Objective-C exception",
                "An NSException was not caught (e.g. NSArray index out of range, nil key in NSDictionary, " +
                "unrecognized selector, layout constraints). See the \"Last Exception Backtrace\" for the exact location."));
        else if (top(["__cxa_throw", "std::terminate", "std::__terminate", "demangling_terminate_handler"]))
            a.Findings.Add(new(FindingLevel.Critical, "Uncaught C++ exception",
                "A C++ exception was thrown and not caught, causing std::terminate()."));
        else if (asiAll.Contains("malloc", StringComparison.OrdinalIgnoreCase)
                 || top(["malloc_error_break", "malloc_vreport", "BUG_IN_CLIENT_OF_LIBMALLOC", "nanov2_", "free_small_botch"]))
            a.Findings.Add(new(FindingLevel.Critical, "Heap corruption",
                "The memory allocator detected an error: double free, freeing an invalid pointer, or a buffer " +
                "overflow that overwrote allocator metadata. Use Address Sanitizer to find it."));
        else if (asiAll.Contains("Assertion failed", StringComparison.OrdinalIgnoreCase) || top(["__assert_rtn"]))
            a.Findings.Add(new(FindingLevel.Critical, "Assertion failed",
                "A condition checked with assert() was not satisfied."));
        else
            a.Findings.Add(new(FindingLevel.Critical, "Call to abort()",
                "The process terminated itself. This is often the result of an uncaught exception, an " +
                "assertion, or an error detected by a system library: check the Application Specific Information."));
    }

    static readonly (string Needle, string Meaning)[] SwiftMessages =
    [
        ("implicitly unwrapping", "An implicitly unwrapped Optional (Type!) was nil, e.g. an @IBOutlet that is not connected."),
        ("found nil while unwrapping", "Force unwrap (!) of an Optional that was nil."),
        ("Index out of range", "Array accessed with an index out of bounds."),
        ("arithmetic overflow", "Integer arithmetic overflow (e.g. addition or multiplication beyond Int.max)."),
        ("Division by zero", "Integer division by zero."),
        ("lowerBound <= upperBound", "A Range was created with a lower bound greater than its upper bound."),
        ("unowned reference", "Access to an unowned reference whose object was already deallocated."),
        ("Could not cast value", "Forced cast (as!) to an incompatible type."),
        ("Not enough bits", "Numeric conversion out of range (e.g. Int(someDouble) with a value too large or NaN)."),
        ("Unexpectedly found nil", "Force unwrap (!) of an Optional that was nil."),
    ];

    static void AnalyzeTrap(CrashReport r, CrashAnalysis a, string type, string asiAll,
        List<FrameInfo> topFrames, Func<string[], bool> top)
    {
        string? swiftMsg = topFrames
            .Select(f => SwiftFailure().Match(f.Symbol))
            .FirstOrDefault(m => m.Success)?.Groups["msg"].Value;
        string haystack = (swiftMsg ?? "") + "\n" + asiAll;
        var meaning = SwiftMessages.FirstOrDefault(s => haystack.Contains(s.Needle, StringComparison.OrdinalIgnoreCase)).Meaning;

        if (swiftMsg is not null || meaning is not null)
        {
            a.Findings.Add(new(FindingLevel.Critical, "Swift runtime error",
                (meaning ?? "The Swift runtime stopped the program because of an invalid operation.") +
                (swiftMsg is not null ? $"\nMessage: \"{swiftMsg}\"" : "")));
        }
        else if (top(["swift_unexpectedError"]))
            a.Findings.Add(new(FindingLevel.Critical, "try! received an error",
                "A try! expression threw an error: use do/catch or try? to handle it."));
        else if (top(["swift_dynamicCastFailure"]))
            a.Findings.Add(new(FindingLevel.Critical, "Forced cast failed (as!)",
                "A forced cast to an incompatible type failed: use as? and handle the nil case."));
        else if (top(["_assertionFailure", "fatalError", "preconditionFailure", "assertionFailure"]))
            a.Findings.Add(new(FindingLevel.Critical, "Swift fatalError / precondition",
                "The code called fatalError(), preconditionFailure(), or a precondition was not satisfied."));
        else if (asiAll.Contains("BUG IN CLIENT OF LIBDISPATCH", StringComparison.OrdinalIgnoreCase))
            a.Findings.Add(new(FindingLevel.Critical, "Incorrect use of GCD (libdispatch)",
                "libdispatch detected invalid usage, e.g. dispatch_sync onto the current queue (deadlock), " +
                "an unbalanced dispatch_group_leave, or a queue released while suspended."));
        else if (asiAll.Contains("BUG IN CLIENT OF", StringComparison.OrdinalIgnoreCase))
            a.Findings.Add(new(FindingLevel.Critical, "Invalid use of a system API",
                "A system library detected incorrect use of its API (see the Application Specific Information)."));
        else
            a.Findings.Add(new(FindingLevel.Critical, $"Runtime trap ({type})",
                "The program executed a trap instruction. In Swift the most common causes are: force unwrap of nil, " +
                "array index out of range, arithmetic overflow, failed forced cast (as!), try! with an error, " +
                "fatalError/precondition. Look at the first app frame in the crashed thread."));
    }

    static readonly (string[] Symbols, string Meaning)[] BlockingCalls =
    [
        (["psynch_mutexwait", "pthread_mutex_lock", "os_unfair_lock", "__ulock_wait"],
            "was waiting for a lock (mutex / os_unfair_lock) probably held by another thread: possible deadlock or contention."),
        (["semaphore_wait", "dispatch_semaphore_wait", "_dispatch_sema4_wait", "dispatch_group_wait"],
            "was blocked on a semaphore or dispatch_group_wait: it waits synchronously for asynchronous work."),
        (["_dispatch_sync_f_slow", "__DISPATCH_WAIT_FOR_QUEUE__", "_dispatch_sync_wait"],
            "was blocked in dispatch_sync on another busy queue."),
        (["psynch_cvwait", "pthread_cond_wait"],
            "was waiting on a condition variable."),
        (["NSURLConnection sendSynchronousRequest", "dataWithContentsOfURL", "stringWithContentsOfURL", "initWithContentsOfURL"],
            "was performing a synchronous network request."),
        (["sqlite3_step", "sqlite3_exec", "fsync", "__open", "read", "__pread", "write"],
            "was doing synchronous disk or database I/O."),
    ];

    static void AddBlockingHint(ThreadInfo thread, CrashAnalysis a)
    {
        var top = thread.Frames.Take(12).ToList();
        foreach (var (symbols, meaning) in BlockingCalls)
        {
            var hit = top.FirstOrDefault(f => symbols.Any(s => SymbolMatches(f.Symbol, s)));
            if (hit is null) continue;
            a.Findings.Add(new(FindingLevel.Warning, $"{thread.DisplayTitle} is blocked",
                $"At the time of termination the thread {meaning}",
                $"#{hit.Index}  {hit.ImageName}  {hit.SymbolDisplay}"));
            return;
        }
    }

    /// <summary>Compares function names ignoring leading underscores and offsets ("__open + 8" ≈ "open").</summary>
    static bool SymbolMatches(string symbol, string wanted)
    {
        var name = symbol.Split(" + ")[0].TrimStart('_');
        if (name.StartsWith("-[") || name.StartsWith("+["))
            return name.Contains(wanted, StringComparison.Ordinal);
        wanted = wanted.TrimStart('_');
        return name == wanted || name.StartsWith(wanted + "_", StringComparison.Ordinal);
    }

    static void FindSuspect(CrashReport r, CrashAnalysis a)
    {
        var candidates = new List<ThreadInfo>();
        if (a.SuspectThread is not null) candidates.Add(a.SuspectThread);
        if (r.ExceptionBacktrace is not null) candidates.Add(r.ExceptionBacktrace);
        if (r.CrashedThread is not null) candidates.Add(r.CrashedThread);

        foreach (var t in candidates)
        {
            var f = t.Frames.FirstOrDefault(fr => fr.IsAppCode && !fr.Symbol.StartsWith("Swift runtime failure"));
            if (f is null) continue;
            a.SuspectFrame = f;
            a.SuspectThread ??= t;
            a.Findings.Add(new(FindingLevel.Warning, "Suspect location in the app's code",
                $"First frame of the app's own code in {t.DisplayTitle} (frame #{f.Index}). " +
                "This is where to start investigating.",
                $"{f.ImageName}  {f.SymbolDisplay}"));
            return;
        }

        if (r.CrashedThread is not null)
        {
            a.SuspectThread ??= r.CrashedThread;
            a.Findings.Add(new(FindingLevel.Info, "No app frames in the crashed thread",
                "The crash happens entirely in system code. The cause is often an object passed incorrectly " +
                "to a framework, an asynchronous callback, or a UI operation off the main thread: check the other threads."));
        }
    }

    static void AddSymbolicationTip(CrashReport r, CrashAnalysis a)
    {
        var groups = r.Threads.Append(r.ExceptionBacktrace).OfType<ThreadInfo>()
            .SelectMany(t => t.Frames)
            .Where(f => f.IsAppCode && !f.IsSymbolicated && f.Image is not null)
            .GroupBy(f => f.Image!)
            .Take(3)
            .ToList();
        if (groups.Count == 0) return;

        var sb = new StringBuilder();
        foreach (var g in groups)
        {
            var img = g.Key;
            var bundleExt = img.Path.Contains(".framework/") ? "framework" : img.Path.Contains(".appex/") ? "appex" : "app";
            var addrs = string.Join(" ", g.Select(f => $"0x{f.Address:x}").Distinct().Take(15));
            var arch = string.IsNullOrEmpty(img.Arch) ? "arm64" : img.Arch;
            sb.AppendLine($"# {img.Name}  UUID {img.Uuid}");
            sb.AppendLine($"atos -arch {arch} -o {img.Name}.{bundleExt}.dSYM/Contents/Resources/DWARF/{img.Name} -l {img.BaseHex} {addrs}");
        }

        a.Findings.Add(new(FindingLevel.Tip, "Symbolication needed",
            "Some app frames have no function names. Get the dSYM with the same UUID (Xcode Organizer, " +
            "App Store Connect or the build archive) and run on a Mac:",
            sb.ToString().TrimEnd()));
    }

    static void AnalyzeJetsam(CrashReport r, CrashAnalysis a)
    {
        var b = r.Body;
        ulong pageSize = U(b?["memoryStatus"]?["pageSize"]) ?? U(b?["pageSize"]) ?? 16384;
        string Mb(ulong pages) => $"{pages * pageSize / (1024 * 1024)} MB";

        a.Headline = "System out of memory (Jetsam)";
        var largest = S(b, "largestProcess");
        a.Findings.Add(new(FindingLevel.Critical, "System out of memory (Jetsam)",
            "iOS killed one or more processes to free memory." +
            (largest is not null ? $" Process using the most memory: {largest}." : "")));

        if (b?["processes"] is JsonArray procs)
        {
            var list = procs.OfType<JsonObject>().Select(p => new
            {
                Name = S(p, "name") ?? "?",
                Pages = U(p["rpages"]) ?? 0,
                Reason = S(p, "reason"),
            }).ToList();

            var killed = list.Where(p => p.Reason is not null).ToList();
            if (killed.Count > 0)
                a.Findings.Add(new(FindingLevel.Warning, $"Killed processes ({killed.Count})",
                    "Processes terminated by the system and why (per-process-limit = the app exceeded its own limit; " +
                    "vm-pageshortage = the device ran out of memory):",
                    string.Join("\n", killed.Select(p => $"{p.Name,-32} {Mb(p.Pages),10}  {p.Reason}"))));

            var topMem = list.OrderByDescending(p => p.Pages).Take(8).ToList();
            if (topMem.Count > 0)
                a.Findings.Add(new(FindingLevel.Info, "Processes using the most memory", "",
                    string.Join("\n", topMem.Select(p => $"{p.Name,-32} {Mb(p.Pages),10}"))));
        }

        a.Findings.Add(new(FindingLevel.Tip, "How to reduce memory usage",
            "Profile the app with Instruments (Allocations, Leaks), shrink caches of decoded images, " +
            "release resources in didReceiveMemoryWarning and look for retain cycles."));
    }

    static void AnalyzePanic(CrashReport r, CrashAnalysis a)
    {
        a.Headline = "Kernel panic";
        var panic = r.PanicString ?? "";
        var firstLines = string.Join("\n", panic.Split('\n').Take(20));
        a.Findings.Add(new(FindingLevel.Critical, "Kernel panic",
            "The operating system crashed and the device rebooted. This involves the kernel, drivers or hardware " +
            "and is rarely caused directly by an app.", firstLines.Length > 0 ? firstLines : null));
    }
}
