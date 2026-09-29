param([string]$OutIco, [string]$PreviewPng)
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

function RoundRect([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function Draw-Icon([int]$S) {
    $bmp = New-Object System.Drawing.Bitmap $S, $S, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)
    $small = $S -le 24

    # Background: rounded square with a blue gradient
    $m = [float]($S * 0.03)
    $bg = RoundRect $m $m ($S - 2 * $m) ($S - 2 * $m) ([float]($S * 0.20))
    $rect = New-Object System.Drawing.RectangleF 0, 0, $S, $S
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, `
        ([System.Drawing.Color]::FromArgb(255, 59, 130, 246)), ([System.Drawing.Color]::FromArgb(255, 30, 58, 138)), 90.0
    $g.FillPath($grad, $bg)

    # Document with folded corner
    $dx = $S * 0.20; $dy = $S * 0.14; $dw = $S * 0.46; $dh = $S * 0.64; $fold = $S * 0.14
    $doc = New-Object System.Drawing.Drawing2D.GraphicsPath
    $pts = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF $dx, $dy),
        (New-Object System.Drawing.PointF ($dx + $dw - $fold), $dy),
        (New-Object System.Drawing.PointF ($dx + $dw), ($dy + $fold)),
        (New-Object System.Drawing.PointF ($dx + $dw), ($dy + $dh)),
        (New-Object System.Drawing.PointF $dx, ($dy + $dh)))
    $doc.AddPolygon($pts)
    $g.FillPath([System.Drawing.Brushes]::White, $doc)
    $foldPts = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF ($dx + $dw - $fold), $dy),
        (New-Object System.Drawing.PointF ($dx + $dw - $fold), ($dy + $fold)),
        (New-Object System.Drawing.PointF ($dx + $dw), ($dy + $fold)))
    $g.FillPolygon((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 191, 219, 254))), $foldPts)

    # Text lines (stack trace), omitted at tiny sizes
    if (-not $small) {
        $lineBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 148, 163, 184))
        $redBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 239, 68, 68))
        $lh = [Math]::Max(1.0, $S * 0.035)
        $widths = @(0.26, 0.20, 0.30, 0.16, 0.24)
        for ($i = 0; $i -lt $widths.Count; $i++) {
            $ly = $dy + $S * 0.13 + $i * $S * 0.085
            $brush = if ($i -eq 2) { $redBrush } else { $lineBrush }
            $g.FillPath($brush, (RoundRect ([float]($dx + $S * 0.06)) ([float]$ly) ([float]($S * $widths[$i])) ([float]$lh) ([float]($lh / 2))))
        }
    }

    # Magnifying glass
    $cx = $S * 0.63; $cy = $S * 0.63; $r = $S * 0.17
    $penW = [float]([Math]::Max(1.5, $S * 0.055))
    $handle = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 15, 23, 42)), ([float]($penW * 1.6))
    $handle.StartCap = 'Round'; $handle.EndCap = 'Round'
    $off = $r * 0.72
    $g.DrawLine($handle, [float]($cx + $off), [float]($cy + $off), [float]($S * 0.88), [float]($S * 0.88))
    $lens = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 239, 68, 68))
    $g.FillEllipse($lens, [float]($cx - $r), [float]($cy - $r), [float](2 * $r), [float](2 * $r))
    $ring = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 15, 23, 42)), $penW
    $g.DrawEllipse($ring, [float]($cx - $r), [float]($cy - $r), [float](2 * $r), [float](2 * $r))

    # Exclamation mark inside the lens
    if ($S -ge 20) {
        $ew = [float]([Math]::Max(1.5, $S * 0.045))
        $g.FillPath([System.Drawing.Brushes]::White, (RoundRect ([float]($cx - $ew / 2)) ([float]($cy - $r * 0.55)) $ew ([float]($r * 0.68)) ([float]($ew / 2))))
        $g.FillEllipse([System.Drawing.Brushes]::White, [float]($cx - $ew / 2), [float]($cy + $r * 0.28), $ew, $ew)
    }

    $g.Dispose()
    return $bmp
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$pngs = @()
foreach ($s in $sizes) {
    $bmp = Draw-Icon $s
    $ms = New-Object System.IO.MemoryStream
    if ($s -ge 256) {
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    } else {
        # Classic 32-bit DIB entry: BITMAPINFOHEADER + bottom-up BGRA pixels + AND mask
        $bw = New-Object System.IO.BinaryWriter $ms
        $maskRow = [int][Math]::Floor(($s + 31) / 32) * 4
        $bw.Write([UInt32]40); $bw.Write([Int32]$s); $bw.Write([Int32](2 * $s))
        $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]0)
        $bw.Write([UInt32]($s * $s * 4 + $maskRow * $s)); $bw.Write([Int32]0); $bw.Write([Int32]0)
        $bw.Write([UInt32]0); $bw.Write([UInt32]0)
        $rect = New-Object System.Drawing.Rectangle 0, 0, $s, $s
        $data = $bmp.LockBits($rect, 'ReadOnly', ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb))
        $row = New-Object byte[] ($s * 4)
        for ($y = $s - 1; $y -ge 0; $y--) {
            [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($data.Scan0.ToInt64() + $y * $data.Stride), $row, 0, $s * 4)
            $bw.Write($row)
        }
        $bmp.UnlockBits($data)
        $bw.Write((New-Object byte[] ($maskRow * $s)))
        $bw.Flush()
    }
    $pngs += , @($s, $ms.ToArray())
    if ($s -eq 256 -and $PreviewPng) { $bmp.Save($PreviewPng) }
    $bmp.Dispose()
}

# ICO container with PNG-compressed entries
$fs = [System.IO.File]::Create($OutIco)
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$pngs.Count)
$offset = 6 + 16 * $pngs.Count
foreach ($e in $pngs) {
    $s = $e[0]; $data = $e[1]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32)
    $w.Write([UInt32]$data.Length); $w.Write([UInt32]$offset)
    $offset += $data.Length
}
foreach ($e in $pngs) { $w.Write([byte[]]$e[1]) }
$w.Close()
"Wrote $OutIco ($((Get-Item $OutIco).Length) bytes)"
