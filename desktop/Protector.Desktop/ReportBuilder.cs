using System.IO;
using System.Text.Json;
using Protector.Desktop.Resources;

namespace Protector.Desktop;

/// <summary>
/// Builds a security-report view model from a successful history record + optional size_report.json.
/// </summary>
public static class ReportBuilder
{
    public static IReadOnlyList<HistoryRecord> SuccessfulJobs() =>
        HistoryStore.Load().Where(r => r.Status == "done").ToList();

    public static ReportDetail Build(HistoryRecord job)
    {
        var sizePath = ResolveSizeReportPath(job);
        SizeReportData? size = null;
        if (!string.IsNullOrEmpty(sizePath) && File.Exists(sizePath))
        {
            try { size = ParseSizeReport(File.ReadAllText(sizePath)); }
            catch { /* ignore bad json */ }
        }

        var checks = BuildChecks(job, size);
        var pass = checks.SelectMany(c => c.Items).Count(i => i.Status == "pass");
        var warn = checks.SelectMany(c => c.Items).Count(i => i.Status == "warn");
        var fail = checks.SelectMany(c => c.Items).Count(i => i.Status == "fail");
        var score = ComputeScore(job, size, fail);

        return new ReportDetail
        {
            Id = job.Id,
            AppName = string.IsNullOrEmpty(job.InputName) ? Path.GetFileName(job.InputPath) : job.InputName,
            Date = string.IsNullOrEmpty(job.FinishedAt) ? job.StartedAt : job.FinishedAt,
            Score = score,
            ScoreLabel = score >= 90 ? Strings.Report_ScoreExcellent
                : score >= 75 ? Strings.Report_ScoreGood
                : Strings.Report_ScoreImprove,
            PassCount = pass,
            WarnCount = warn,
            FailCount = fail,
            InputSize = HistoryStore.FormatBytes(job.InputBytes),
            OutputSize = HistoryStore.FormatBytes(job.OutputBytes),
            Duration = HistoryStore.FormatDuration(job.DurationMs),
            Profile = job.Profile,
            ProtectSo = job.ProtectSo,
            ProtectSoMode = job.ProtectSoMode,
            Signed = job.Signed,
            OutputPath = job.OutputPath,
            SizeReportPath = sizePath,
            SizeSummary = size == null
                ? null
                : string.Format(Strings.Report_SizeSummary, size.InputMb, size.OutputMb, size.DeltaMb, size.DeltaPct),
            Categories = checks
        };
    }

    public static string? ResolveSizeReportPath(HistoryRecord job)
    {
        if (!string.IsNullOrWhiteSpace(job.SizeReport) && File.Exists(job.SizeReport))
            return job.SizeReport;
        if (string.IsNullOrWhiteSpace(job.OutputPath)) return null;
        var outDir = Path.GetDirectoryName(job.OutputPath) ?? "";
        var baseName = Path.GetFileNameWithoutExtension(job.OutputPath) + "-size_report.json";
        var inLog = Path.Combine(outDir, "Log", baseName);
        if (File.Exists(inLog)) return inLog;
        // Legacy: report written beside the APK before Log/ layout.
        var beside = Path.Combine(outDir, baseName);
        return File.Exists(beside) ? beside : job.SizeReport;
    }

    private static int ComputeScore(HistoryRecord job, SizeReportData? size, int fail)
    {
        // Feature-first scoring: more hardening options must not lower the score.
        // Volume warn items (budget/reloc skips) are informational only — they used to
        // subtract warn*3 and made big-APK SO protect look "worse" after adding options.
        var score = 80;

        score += job.Profile switch
        {
            "max" => 10,
            "aggressive" => 8,
            "industry" => 7,
            "balanced" => 5,
            "perf" => 3,
            _ => 3
        };

        if (job.ProtectSo) score += 8;
        else score -= 5;
        if (job.PaymentAutoVmp) score += 2;
        if (job.IndustryAutoVmp) score += 3;
        if (job.DetectProxy) score += 2;
        if (!string.IsNullOrWhiteSpace(job.Channel)) score += 1;
        if (job.Signed) score += 5;

        // Small SO effectiveness bonus (capped); empty encrypt when SO on is a mild ding.
        if (size != null)
        {
            if (size.EncryptedCount > 0) score += 3;
            else if (job.ProtectSo) score -= 2;
            // Soft hint only — budget truncate is common on large apps.
            if (size.BudgetTruncated) score -= 2;
            // Skipped SO coverage: −1 per up-to-5 (budget+reloc), ceil; capped at −5.
            // 1–5 → −1, 6–10 → −2, … (policy skips ignored).
            var skipped = size.SkippedBudget + size.SkippedReloc;
            if (skipped > 0)
                score -= Math.Min(5, (skipped + 4) / 5);
        }

        // Hard failures only (missing output etc.); ignore warn count for score stability.
        score -= fail * 6;

        return Math.Clamp(score, 0, 100);
    }

    private static List<ReportCategory> BuildChecks(HistoryRecord job, SizeReportData? size)
    {
        var code = new ReportCategory
        {
            Title = Strings.Report_CatCode,
            Items =
            {
                new ReportCheck(Strings.Report_DexProtect, "pass", Strings.Report_DexProtectDetail),
                new ReportCheck(Strings.Report_ProfileCheck, "pass",
                    string.Format(Strings.Report_ProfileDetail, job.Profile)),
                job.ProtectSo
                    ? new ReportCheck(Strings.Harden_SoTitle, "pass",
                        string.Format(Strings.Report_SoOnDetail, job.ProtectSoMode))
                    : new ReportCheck(Strings.Harden_SoTitle, "warn", Strings.Report_SoOffDetail),
                new ReportCheck(Strings.Report_ShellInject, "pass", Strings.Report_ShellInjectDetail),
                job.PaymentAutoVmp || job.IndustryAutoVmp
                    ? new ReportCheck(Strings.Report_AutoVmp, "pass",
                        string.Format(Strings.Report_AutoVmpDetail,
                            job.PaymentAutoVmp ? Strings.Meta_On : Strings.Meta_Off,
                            job.IndustryAutoVmp ? Strings.Meta_On : Strings.Meta_Off))
                    : new ReportCheck(Strings.Report_AutoVmp, "warn", Strings.Report_AutoVmpOffDetail),
            }
        };

        var runtime = new ReportCategory
        {
            Title = Strings.Report_CatSign,
            Items =
            {
                job.Signed
                    ? new ReportCheck(Strings.Report_CustomSign, "pass", Strings.Report_CustomSignDetail)
                    : new ReportCheck(Strings.Report_AppSign, "warn", Strings.Report_AppSignWarn),
                new ReportCheck(Strings.Report_OutputArtifact,
                    !string.IsNullOrEmpty(job.OutputPath) && File.Exists(job.OutputPath) ? "pass" : "fail",
                    string.IsNullOrEmpty(job.OutputPath) ? Strings.Report_NoOutputPath : job.OutputPath),
                new ReportCheck(Strings.Report_Duration, "pass", HistoryStore.FormatDuration(job.DurationMs)),
            }
        };

        var volume = new ReportCategory { Title = Strings.Report_CatVolume };
        if (size == null)
        {
            volume.Items.Add(new ReportCheck(Strings.Report_SizeReportName, "warn", Strings.Report_SizeReportMissing));
            volume.Items.Add(new ReportCheck(Strings.Report_PkgSize, "pass",
                $"{HistoryStore.FormatBytes(job.InputBytes)} → {HistoryStore.FormatBytes(job.OutputBytes)}"));
        }
        else
        {
            volume.Items.Add(new ReportCheck(Strings.Report_PkgSizeChange, "pass",
                string.Format(Strings.Report_PkgSizeChangeDetail, size.InputMb, size.OutputMb, size.DeltaMb)));
            volume.Items.Add(size.ProtectSo
                ? new ReportCheck(Strings.Report_SoEncrypt, size.EncryptedCount > 0 ? "pass" : "warn",
                    size.EncryptedCount > 0
                        ? string.Format(Strings.Report_SoEncryptedCount, size.EncryptedCount)
                        : Strings.Report_SoEncryptEmpty)
                : new ReportCheck(Strings.Report_SoEncrypt, "warn", Strings.Report_SoEncryptOff));
            volume.Items.Add(size.BudgetTruncated
                ? new ReportCheck(Strings.Report_Budget, "warn", Strings.Report_BudgetHit)
                : new ReportCheck(Strings.Report_Budget, "pass", Strings.Report_BudgetOk));
            // Informational: keep as pass so large APKs do not flood Warn and look "worse".
            if (size.SkippedPolicy > 0)
                volume.Items.Add(new ReportCheck(Strings.Report_PolicySkip, "pass",
                    string.Format(Strings.Report_PolicySkipDetail, size.SkippedPolicy)));
            if (size.SkippedReloc > 0)
                volume.Items.Add(new ReportCheck(Strings.Report_RelocSkip, "pass",
                    string.Format(Strings.Report_RelocSkipDetail, size.SkippedReloc)));
            if (size.SkippedBudget > 0)
                volume.Items.Add(new ReportCheck(Strings.Report_BudgetSkip, "pass",
                    string.Format(Strings.Report_BudgetSkipDetail, size.SkippedBudget)));
        }

        return new List<ReportCategory> { code, runtime, volume };
    }

    private static SizeReportData ParseSizeReport(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        return new SizeReportData
        {
            InputMb = GetDouble(root, "input_mb"),
            OutputMb = GetDouble(root, "output_mb"),
            DeltaMb = GetDouble(root, "delta_mb"),
            DeltaPct = GetDouble(root, "delta_pct"),
            ProtectSo = root.TryGetProperty("protect_so", out var ps) && ps.ValueKind == JsonValueKind.True,
            BudgetTruncated = root.TryGetProperty("budget_truncated", out var bt) && bt.ValueKind == JsonValueKind.True,
            EncryptedCount = CountArray(root, "so_encrypted"),
            SkippedBudget = CountArray(root, "so_skipped_budget"),
            SkippedPolicy = CountArray(root, "so_skipped_policy"),
            SkippedReloc = CountArray(root, "so_skipped_reloc"),
        };
    }

    private static double GetDouble(JsonElement root, string name) =>
        root.TryGetProperty(name, out var el) && el.TryGetDouble(out var d) ? d : 0;

    private static int CountArray(JsonElement root, string name) =>
        root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Array ? el.GetArrayLength() : 0;

    private sealed class SizeReportData
    {
        public double InputMb { get; set; }
        public double OutputMb { get; set; }
        public double DeltaMb { get; set; }
        public double DeltaPct { get; set; }
        public bool ProtectSo { get; set; }
        public bool BudgetTruncated { get; set; }
        public int EncryptedCount { get; set; }
        public int SkippedBudget { get; set; }
        public int SkippedPolicy { get; set; }
        public int SkippedReloc { get; set; }
    }
}

public sealed class ReportDetail
{
    public string Id { get; set; } = "";
    public string AppName { get; set; } = "";
    public string Date { get; set; } = "";
    public int Score { get; set; }
    public string ScoreLabel { get; set; } = "";
    public int PassCount { get; set; }
    public int WarnCount { get; set; }
    public int FailCount { get; set; }
    public string InputSize { get; set; } = "";
    public string OutputSize { get; set; } = "";
    public string Duration { get; set; } = "";
    public string Profile { get; set; } = "";
    public bool ProtectSo { get; set; }
    public string ProtectSoMode { get; set; } = "";
    public bool Signed { get; set; }
    public string OutputPath { get; set; } = "";
    public string? SizeReportPath { get; set; }
    public string? SizeSummary { get; set; }
    public List<ReportCategory> Categories { get; set; } = new();
}

public sealed class ReportCategory
{
    public string Title { get; set; } = "";
    public List<ReportCheck> Items { get; set; } = new();
}

public sealed class ReportCheck
{
    public ReportCheck() { }
    public ReportCheck(string name, string status, string detail)
    {
        Name = name;
        Status = status;
        Detail = detail;
    }

    public string Name { get; set; } = "";
    public string Status { get; set; } = "pass"; // pass | warn | fail
    public string Detail { get; set; } = "";
}
