using System.IO;
using System.Text;

namespace Protector.Desktop;

/// <summary>
/// Writes protect job console logs under %AppData%\XopProtector\logs\
/// and optionally mirrors under {@code <outputDir>/Log/}.
/// </summary>
public sealed class ProtectLogWriter : IDisposable
{
    private static readonly string LogsDir = AppDataPaths.LogsDir;

    private readonly object _gate = new();
    private StreamWriter? _writer;

    public string LogPath { get; }
    public static string LogsDirectory => LogsDir;

    public ProtectLogWriter(string inputApkName)
    {
        Directory.CreateDirectory(LogsDir);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var safe = SanitizeFileToken(Path.GetFileNameWithoutExtension(inputApkName));
        if (string.IsNullOrEmpty(safe)) safe = "apk";
        LogPath = Path.Combine(LogsDir, $"{stamp}_{safe}.log");
        _writer = new StreamWriter(new FileStream(LogPath, FileMode.Create, FileAccess.Write, FileShare.Read),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true
        };
        _writer.WriteLine($"# XopProtector log  started={DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        _writer.WriteLine($"# input={inputApkName}");
    }

    public void Append(string stampedLine)
    {
        lock (_gate)
        {
            _writer?.WriteLine(stampedLine);
        }
    }

    /// <summary>Copy current log under {@code <outputDir>/Log/*-protect.log}.</summary>
    public string? MirrorBesideOutput(string outputApk)
    {
        try
        {
            lock (_gate)
            {
                _writer?.Flush();
            }
            if (string.IsNullOrWhiteSpace(outputApk) || !File.Exists(LogPath))
                return null;
            var parent = Path.GetDirectoryName(outputApk);
            if (string.IsNullOrEmpty(parent)) return null;
            var dir = Path.Combine(parent, "Log");
            Directory.CreateDirectory(dir);
            var dest = Path.Combine(dir,
                Path.GetFileNameWithoutExtension(outputApk) + "-protect.log");
            File.Copy(LogPath, dest, overwrite: true);
            return dest;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            try
            {
                _writer?.WriteLine($"# ended={DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                _writer?.Dispose();
            }
            catch
            {
                // ignore
            }
            _writer = null;
        }
    }

    private static string SanitizeFileToken(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
        {
            if (char.IsLetterOrDigit(c) || c is '_' or '-' or '.')
                sb.Append(c);
            else
                sb.Append('_');
        }
        return sb.Length > 80 ? sb.ToString(0, 80) : sb.ToString();
    }
}
