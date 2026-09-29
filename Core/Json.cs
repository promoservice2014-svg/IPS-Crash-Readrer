using System.Globalization;
using System.Text.Json.Nodes;

namespace IpsReader.Core;

/// <summary>Lenient access to JSON values: IPS fields change type and presence across iOS versions.</summary>
internal static class Js
{
    public static string? S(JsonNode? node, string key) =>
        node is JsonObject o && o.TryGetPropertyValue(key, out var v) ? Str(v) : null;

    public static string? Str(JsonNode? v)
    {
        if (v is null) return null;
        if (v is JsonValue jv && jv.TryGetValue<string>(out var s)) return s;
        return v.ToJsonString();
    }

    public static ulong? U(JsonNode? v)
    {
        if (v is not JsonValue jv) return null;
        if (jv.TryGetValue<ulong>(out var u)) return u;
        if (jv.TryGetValue<long>(out var l)) return unchecked((ulong)l);
        if (jv.TryGetValue<double>(out var d)) return (ulong)d;
        if (jv.TryGetValue<string>(out var s)) return ParseNumber(s);
        return null;
    }

    public static int? I(JsonNode? v) => U(v) is ulong u && u <= int.MaxValue ? (int)u : null;

    public static bool B(JsonNode? v) => v is JsonValue jv && jv.TryGetValue<bool>(out var b) && b;

    public static ulong? ParseNumber(string? s)
    {
        s = s?.Trim();
        if (string.IsNullOrEmpty(s)) return null;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h) ? h : null;
        return ulong.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) ? d : null;
    }
}
