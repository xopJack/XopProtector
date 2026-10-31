using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using IOPath = System.IO.Path;
using Protector.Desktop.Resources;

namespace Protector.Desktop.Pages;

public partial class HardenPage : UserControl
{
    private enum Phase { Idle, Ready, Running, Done, Error }

    private static (string Id, string Label)[] Stages() => new[]
    {
        ("unzip", Strings.Stage_Unzip),
        ("hollow", Strings.Stage_Hollow),
        ("protect_so", Strings.Stage_ProtectSo),
        ("manifest", Strings.Stage_Manifest),
        ("repack", Strings.Stage_Repack),
        ("sign", Strings.Stage_Sign),
        ("done", Strings.Stage_Done),
    };

    private EnginePaths? _paths;
    private EngineRunner? _runner;
    private CancellationTokenSource? _cts;
    private Phase _phase = Phase.Idle;
    private string? _inputApk;
    private string? _lastOutputDir;
    private string? _lastOutputApk;
    private string? _lastPackageName;
    private string? _lastSizeReport;
    private string? _lastProtectLog;
    private ProtectLogWriter? _logWriter;
    private bool _protectSo = true;
    private bool _signCustom;
    private int _percent;
    private bool _userOverridePaymentAutoVmp;
    private bool _userOverrideIndustryAutoVmp;
    private bool _userOverrideSoBudget;
    private bool _applyingAdvancedPreset;
    private readonly Dictionary<string, Border> _stageDots = new();
    private readonly Stopwatch _jobWatch = new();
    private DispatcherTimer? _aliasProbeTimer;
    private int _aliasProbeGen;
    private bool _restoringSign;
    private bool _installBusy;
    private DispatcherTimer? _signSaveTimer;
    private readonly ConcurrentQueue<string> _pendingLogLines = new();
    private DispatcherTimer? _logFlushTimer;
    private const int MaxLogChars = 400_000;

    public HardenPage()
    {
        InitializeComponent();
        BuildStageStrip();
        UpdateChrome();
        StyleSignCard(SignAutoCard, SignAutoDot, true);
        StyleSignCard(SignCustomCard, SignCustomDot, false);
        ThemeService.ThemeChanged += _ => Dispatcher.Invoke(OnThemeChanged);
        Loaded += (_, _) =>
        {
            RestoreSignPrefs();
            ApplyAdvancedPresetsFromProfile();
        };
    }

    private void OnThemeChanged()
    {
        BuildStageStrip();
        ApplySoVisual();
        StyleSignCard(SignAutoCard, SignAutoDot, !_signCustom);
        StyleSignCard(SignCustomCard, SignCustomDot, _signCustom);
        SetPercent(_percent);
    }

    private void ApplySoVisual()
    {
        SoToggle.Background = ThemeService.Brush(_protectSo ? "Accent" : "ToggleOff");
        SoKnob.HorizontalAlignment = _protectSo ? HorizontalAlignment.Right : HorizontalAlignment.Left;
        SoKnob.Fill = _protectSo ? Brushes.White : ThemeService.Brush("ToggleOffKnob");
        SoKnob.Margin = _protectSo ? new Thickness(0, 3, 3, 0) : new Thickness(3, 3, 0, 0);
        SoModePanel.Visibility = _protectSo ? Visibility.Visible : Visibility.Collapsed;
    }

    public void BindEngine(EnginePaths paths)
    {
        _paths = paths;
        if (_signCustom && !string.IsNullOrEmpty(StorePassBox.Password)
            && !string.IsNullOrWhiteSpace(KeystoreBox.Text))
        {
            ScheduleAliasResolve(immediate: true);
        }
    }

    private void RestoreSignPrefs()
    {
        var data = AppSettings.Load();
        if (!data.SignCustom) return;

        _restoringSign = true;
        try
        {
            _signCustom = true;
            SignFields.Visibility = Visibility.Visible;
            StyleSignCard(SignAutoCard, SignAutoDot, false);
            StyleSignCard(SignCustomCard, SignCustomDot, true);

            if (!string.IsNullOrWhiteSpace(data.Keystore))
                KeystoreBox.Text = data.Keystore;
            if (!string.IsNullOrWhiteSpace(data.Alias))
                AliasBox.Text = data.Alias;

            var storePass = AppSettings.UnprotectSecret(data.StorePassProtected);
            if (!string.IsNullOrEmpty(storePass))
                StorePassBox.Password = storePass;

            var keyPass = AppSettings.UnprotectSecret(data.KeyPassProtected);
            if (!string.IsNullOrEmpty(keyPass))
                KeyPassBox.Password = keyPass;

            if (!string.IsNullOrWhiteSpace(data.Alias))
            {
                AliasHint.Text = Strings.Harden_RestoredSign;
                AliasHint.Foreground = ThemeService.Brush("SuccessMeta");
            }
        }
        finally
        {
            _restoringSign = false;
        }

        if (_paths != null && !string.IsNullOrEmpty(StorePassBox.Password)
            && !string.IsNullOrWhiteSpace(KeystoreBox.Text)
            && string.IsNullOrWhiteSpace(AliasBox.Text))
        {
            ScheduleAliasResolve(immediate: true);
        }
    }

    private void PersistSignPrefs()
    {
        if (_restoringSign) return;
        AppSettings.Update(d =>
        {
            d.SignCustom = _signCustom;
            if (_signCustom)
            {
                d.Keystore = KeystoreBox.Text?.Trim() ?? "";
                d.Alias = AliasBox.Text?.Trim() ?? "";
                d.StorePassProtected = AppSettings.ProtectSecret(StorePassBox.Password);
                var keyPass = KeyPassBox.Password;
                d.KeyPassProtected = string.IsNullOrEmpty(keyPass)
                    ? ""
                    : AppSettings.ProtectSecret(keyPass);
            }
        });
    }

    private void SchedulePersistSignPrefs()
    {
        if (_restoringSign) return;
        _signSaveTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(600) };
        _signSaveTimer.Stop();
        _signSaveTimer.Tick -= SignSaveTimer_Tick;
        _signSaveTimer.Tick += SignSaveTimer_Tick;
        _signSaveTimer.Start();
    }

    private void SignSaveTimer_Tick(object? sender, EventArgs e)
    {
        _signSaveTimer?.Stop();
        PersistSignPrefs();
    }

    public void ShowEngineError(string message)
    {
        AppendLog(Strings.Log_ErrorPrefix + message);
        PrimaryBtn.IsEnabled = false;
        PrimaryBtn.Content = Strings.Harden_EngineNotReady;
    }

    private void BuildStageStrip()
    {
        StageStrip.Children.Clear();
        _stageDots.Clear();
        foreach (var (id, label) in Stages())
        {
            var col = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
            var dot = new Border
            {
                Width = 22,
                Height = 22,
                CornerRadius = new CornerRadius(11),
                Background = ThemeService.Brush("StagePendingBg"),
                BorderBrush = ThemeService.Brush("StagePendingBorder"),
                BorderThickness = new Thickness(1.5),
                HorizontalAlignment = HorizontalAlignment.Center,
                Child = new Ellipse { Width = 5, Height = 5, Fill = ThemeService.Brush("StagePendingDot") }
            };
            _stageDots[id] = dot;
            col.Children.Add(dot);
            col.Children.Add(new TextBlock
            {
                Text = label,
                FontSize = 9.5,
                Foreground = ThemeService.Brush("TextDim"),
                Margin = new Thickness(0, 4, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 72
            });
            StageStrip.Children.Add(col);
        }
    }

    private void DropZone_Click(object sender, MouseButtonEventArgs e) => PickInput();

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_DragEnter(object sender, DragEventArgs e)
    {
        DropZone.BorderBrush = ThemeService.Brush("Accent");
        DropHint.Foreground = ThemeService.Brush("Accent");
    }

    private void DropZone_DragLeave(object sender, DragEventArgs e)
    {
        DropZone.BorderBrush = ThemeService.Brush("Border");
        DropHint.Foreground = ThemeService.Brush("TextMuted");
    }

    private void DropZone_Drop(object sender, DragEventArgs e)
    {
        DropZone_DragLeave(sender, e);
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
        {
            var apk = files.FirstOrDefault(f => f.EndsWith(".apk", StringComparison.OrdinalIgnoreCase));
            if (apk != null) SetInput(apk);
        }
    }

    private void PickInput()
    {
        if (_phase == Phase.Running) return;
        var dlg = new OpenFileDialog
        {
            Filter = Strings.Dlg_FilterApk,
            Title = Strings.Dlg_SelectApkTitle
        };
        if (dlg.ShowDialog() == true) SetInput(dlg.FileName);
    }

    private void SetInput(string path)
    {
        _inputApk = path;
        var fi = new System.IO.FileInfo(path);
        FileNameText.Text = fi.Name;
        FileMetaText.Text = $"{fi.Length / 1024.0 / 1024.0:F2} MB";
        DropZone.Visibility = Visibility.Collapsed;
        FileCard.Visibility = Visibility.Visible;
        OptionsPanel.Visibility = Visibility.Visible;
        var dir = fi.DirectoryName ?? "";
        OutputBox.Text = IOPath.Combine(dir, IOPath.GetFileNameWithoutExtension(fi.Name) + "-protected.apk");
        _phase = Phase.Ready;
        EmptyState.Visibility = Visibility.Collapsed;
        WorkPanel.Visibility = Visibility.Visible;
        PhaseTitle.Text = Strings.Harden_PhaseReady;
        PhaseFile.Text = fi.Name;
        DoneCard.Visibility = Visibility.Collapsed;
        SetPercent(0);
        ResetStages();
        LogText.Text = "";
        UpdateChrome();
    }

    private void ClearFile_Click(object sender, RoutedEventArgs e) => Reset();
    private void Reset_Click(object sender, RoutedEventArgs e) => Reset();

    private void Reset()
    {
        if (_phase == Phase.Running) return;
        _inputApk = null;
        _lastOutputDir = null;
        _lastOutputApk = null;
        _lastPackageName = null;
        _phase = Phase.Idle;
        HideDeviceInstallUi();
        DropZone.Visibility = Visibility.Visible;
        FileCard.Visibility = Visibility.Collapsed;
        OptionsPanel.Visibility = Visibility.Collapsed;
        EmptyState.Visibility = Visibility.Visible;
        WorkPanel.Visibility = Visibility.Collapsed;
        DoneCard.Visibility = Visibility.Collapsed;
        LogText.Text = "";
        LogPathHint.Text = "";
        EndJobLogWriter();
        SetPercent(0);
        ResetStages();
        UpdateChrome();
    }

    private void BrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = Strings.Dlg_FilterApk,
            Title = Strings.Dlg_SaveApkTitle,
            FileName = string.IsNullOrWhiteSpace(OutputBox.Text)
                ? "app-protected.apk"
                : IOPath.GetFileName(OutputBox.Text)
        };
        if (dlg.ShowDialog() == true) OutputBox.Text = dlg.FileName;
    }

    private void BrowseKeystore_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = Strings.Dlg_FilterKeystore,
            Title = Strings.Dlg_BrowseKeystoreTitle
        };
        if (dlg.ShowDialog() != true) return;
        KeystoreBox.Text = dlg.FileName;
        ScheduleAliasResolve(immediate: true);
        SchedulePersistSignPrefs();
    }

    private void KeystoreBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ScheduleAliasResolve(immediate: false);
        SchedulePersistSignPrefs();
    }

    private void StorePassBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        ScheduleAliasResolve(immediate: false);
        SchedulePersistSignPrefs();
    }

    private void AliasBox_TextChanged(object sender, TextChangedEventArgs e)
        => SchedulePersistSignPrefs();

    private void KeyPassBox_PasswordChanged(object sender, RoutedEventArgs e)
        => SchedulePersistSignPrefs();

    private void ScheduleAliasResolve(bool immediate)
    {
        _aliasProbeTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(450) };
        _aliasProbeTimer.Stop();
        _aliasProbeTimer.Tick -= AliasProbeTimer_Tick;
        _aliasProbeTimer.Tick += AliasProbeTimer_Tick;
        if (immediate)
            AliasProbeTimer_Tick(_aliasProbeTimer, EventArgs.Empty);
        else
            _aliasProbeTimer.Start();
    }

    private void AliasProbeTimer_Tick(object? sender, EventArgs e)
    {
        _aliasProbeTimer?.Stop();
        _ = ResolveAliasAsync();
    }

    private async Task ResolveAliasAsync()
    {
        var gen = ++_aliasProbeGen;
        var ks = KeystoreBox.Text?.Trim() ?? "";
        var pass = StorePassBox.Password;

        if (_paths == null || string.IsNullOrWhiteSpace(ks) || string.IsNullOrEmpty(pass))
        {
            AliasHint.Text = "";
            return;
        }

        AliasHint.Text = Strings.Harden_Resolving;
        AliasHint.Foreground = ThemeService.Brush("TextFaint");

        var paths = _paths;
        var result = await Task.Run(() => KeystoreProbe.Probe(paths, ks, pass)).ConfigureAwait(true);
        if (gen != _aliasProbeGen) return; // stale

        if (!result.Ok)
        {
            AliasHint.Text = result.Error?.Split('\n')[0] ?? Strings.Harden_ResolveFailed;
            AliasHint.Foreground = ThemeService.Brush("Danger");
            return;
        }

        if (result.Aliases.Count == 0)
        {
            AliasHint.Text = Strings.Harden_NoAlias;
            AliasHint.Foreground = ThemeService.Brush("Danger");
            return;
        }

        // Always refresh to the probed alias(es): single → fill; multi → first + hint.
        AliasBox.Text = result.Aliases[0];
        if (result.Aliases.Count == 1)
        {
            AliasHint.Text = Strings.Harden_AutoDetected;
            AliasHint.Foreground = ThemeService.Brush("SuccessMeta");
        }
        else
        {
            AliasHint.Text = Strings.Harden_MultiAlias + string.Join(", ", result.Aliases);
            AliasHint.Foreground = ThemeService.Brush("AccentSoft");
        }
        PersistSignPrefs();
    }

    private void ToggleSo_Click(object sender, MouseButtonEventArgs e)
    {
        _protectSo = !_protectSo;
        ApplySoVisual();
    }

    private string CurrentProfileName() => ComboTag(ProfileBox, "balanced");

    private static string ComboTag(ComboBox box, string fallback)
    {
        if (box.SelectedItem is ComboBoxItem item)
        {
            var tag = item.Tag?.ToString();
            if (!string.IsNullOrWhiteSpace(tag)) return tag;
            return item.Content?.ToString() ?? fallback;
        }
        return fallback;
    }

    private void ProfileBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyAdvancedPresetsFromProfile();
    }

    private void ApplyAdvancedPresetsFromProfile()
    {
        _applyingAdvancedPreset = true;
        try
        {
            var industry = string.Equals(CurrentProfileName(), "industry", StringComparison.OrdinalIgnoreCase);
            ProfileHint.Visibility = industry ? Visibility.Visible : Visibility.Collapsed;

            if (!_userOverridePaymentAutoVmp)
                PaymentAutoVmpBox.IsChecked = true;
            if (!_userOverrideIndustryAutoVmp)
                IndustryAutoVmpBox.IsChecked = industry;

            SoBudgetHint.Text = industry
                ? Strings.Harden_SoBudgetHintIndustry
                : Strings.Harden_SoBudgetHintDefault;

            if (!_userOverrideSoBudget)
                SoBudgetPresetBox.SelectedIndex = 0;
        }
        finally
        {
            _applyingAdvancedPreset = false;
        }
    }

    private void PaymentAutoVmp_Changed(object sender, RoutedEventArgs e)
    {
        if (_applyingAdvancedPreset) return;
        _userOverridePaymentAutoVmp = true;
    }

    private void IndustryAutoVmp_Changed(object sender, RoutedEventArgs e)
    {
        if (_applyingAdvancedPreset) return;
        _userOverrideIndustryAutoVmp = true;
    }

    private void SoBudgetPreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_applyingAdvancedPreset || !IsLoaded) return;
        if (SoBudgetPresetBox.SelectedIndex > 0)
            _userOverrideSoBudget = true;
    }

    private void ResetAdvanced_Click(object sender, RoutedEventArgs e)
    {
        _userOverridePaymentAutoVmp = false;
        _userOverrideIndustryAutoVmp = false;
        _userOverrideSoBudget = false;
        EncryptAssetsBox.IsChecked = false;
        ResProtectBox.IsChecked = false;
        DetectProxyBox.IsChecked = false;
        PinCertsBox.Text = "";
        ChannelBox.Text = "";
        HollowPrefixBox.Text = "";
        Vmp1PrefixBox.Text = "";
        TrueVmpBox.Text = "";
        ApplyAdvancedPresetsFromProfile();
    }

    private void BrowsePinCerts_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = Strings.Dlg_FilterPinCerts,
            Title = Strings.Harden_BrowsePinCerts
        };
        if (dlg.ShowDialog() == true)
            PinCertsBox.Text = dlg.FileName;
    }

    /// <summary>Tag format: default | budget:maxFile (e.g. 12:8).</summary>
    private (double? BudgetMb, double? MaxFileMb) ResolveSoBudgetPreset()
    {
        var tag = ComboTag(SoBudgetPresetBox, "default");
        if (string.IsNullOrWhiteSpace(tag)
            || string.Equals(tag, "default", StringComparison.OrdinalIgnoreCase))
            return (null, null);

        var parts = tag.Split(':', 2);
        if (parts.Length != 2) return (null, null);
        if (!double.TryParse(parts[0], System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var budget)
            || !double.TryParse(parts[1], System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var maxFile))
            return (null, null);
        if (budget <= 0 || maxFile <= 0) return (null, null);
        return (budget, maxFile);
    }

    private void SignMode_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is not FrameworkElement el || el.Tag is not string tag) return;
        _signCustom = tag == "custom";
        SignFields.Visibility = _signCustom ? Visibility.Visible : Visibility.Collapsed;
        StyleSignCard(SignAutoCard, SignAutoDot, !_signCustom);
        StyleSignCard(SignCustomCard, SignCustomDot, _signCustom);
        PersistSignPrefs();
        if (_signCustom)
        {
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded, () =>
            {
                ConfigScroll.UpdateLayout();
                ConfigScroll.ScrollToEnd();
            });
        }
    }

    private static void StyleSignCard(Border card, Border dot, bool on)
    {
        card.Background = ThemeService.Brush(on ? "AccentBg" : "CardBg");
        card.BorderBrush = ThemeService.Brush(on ? "Accent" : "BorderSoft");
        card.BorderThickness = new Thickness(on ? 1.5 : 1);
        if (on)
        {
            dot.Background = ThemeService.Brush("Accent");
            dot.BorderBrush = ThemeService.Brush("Accent");
            dot.Child = new Ellipse
            {
                Width = 6,
                Height = 6,
                Fill = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
        }
        else
        {
            dot.Background = Brushes.Transparent;
            dot.BorderBrush = ThemeService.Brush("TextFaint");
            dot.Child = null;
        }
    }

    private async void Protect_Click(object sender, RoutedEventArgs e)
    {
        var paths = _paths;
        if (paths == null || string.IsNullOrEmpty(_inputApk) || _phase == Phase.Running)
            return;
        if (_signCustom)
        {
            if (string.IsNullOrWhiteSpace(KeystoreBox.Text) || string.IsNullOrWhiteSpace(AliasBox.Text)
                || string.IsNullOrEmpty(StorePassBox.Password))
            {
                MessageBox.Show(Strings.Harden_NeedSignFields, Strings.ProductName,
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var probe = KeystoreProbe.Probe(
                paths, KeystoreBox.Text.Trim(), StorePassBox.Password, AliasBox.Text.Trim());
            if (!probe.Ok)
            {
                if (probe.Aliases.Count == 1 && string.IsNullOrWhiteSpace(AliasBox.Text))
                    AliasBox.Text = probe.Aliases[0];
                else if (probe.Aliases.Count == 1
                         && !string.Equals(AliasBox.Text.Trim(), probe.Aliases[0], StringComparison.Ordinal))
                {
                    var use = MessageBox.Show(
                        (probe.Error ?? Strings.Harden_AliasMismatch) + "\n\n" +
                        string.Format(Strings.Harden_UseAlias, probe.Aliases[0]),
                        Strings.ProductName, MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (use == MessageBoxResult.Yes)
                    {
                        AliasBox.Text = probe.Aliases[0];
                        probe = KeystoreProbe.Probe(
                            paths, KeystoreBox.Text.Trim(), StorePassBox.Password, AliasBox.Text.Trim());
                    }
                }
                if (!probe.Ok)
                {
                    MessageBox.Show(probe.Error ?? Strings.Harden_KeystoreCheckFailed, Strings.ProductName,
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }
        }

        var output = OutputBox.Text.Trim();
        if (string.IsNullOrEmpty(output))
        {
            MessageBox.Show(Strings.Harden_SetOutput, Strings.ProductName, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var channel = ChannelBox.Text.Trim();
        if (!string.IsNullOrEmpty(channel) && !_signCustom)
        {
            MessageBox.Show(Strings.Harden_ChannelNeedSignWarn, Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var pinCerts = PinCertsBox.Text.Trim();
        if (!string.IsNullOrEmpty(pinCerts) && !System.IO.File.Exists(pinCerts))
        {
            MessageBox.Show(Strings.Harden_PinCertsMissing, Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _phase = Phase.Running;
        _lastPackageName = null;
        HideDeviceInstallUi();
        DoneCard.Visibility = Visibility.Collapsed;
        BeginJobLog(IOPath.GetFileName(_inputApk) ?? "apk");
        ResetStages();
        SetPercent(0);
        PhaseTitle.Text = Strings.Harden_PhaseRunning;
        UpdateChrome();
        AppendLog(Strings.Harden_LogStart + IOPath.GetFileName(_inputApk));

        var soBudget = ResolveSoBudgetPreset();
        var job = new ProtectJobRequest
        {
            InputApk = _inputApk,
            OutputApk = output,
            Profile = ComboTag(ProfileBox, "balanced"),
            ProtectSo = _protectSo,
            ProtectSoMode = ComboTag(SoModeBox, "safe"),
            PaymentAutoVmp = PaymentAutoVmpBox.IsChecked == true,
            IndustryAutoVmp = IndustryAutoVmpBox.IsChecked == true,
            ProtectSoBudgetMb = soBudget.BudgetMb,
            ProtectSoMaxFileMb = soBudget.MaxFileMb,
            // Extra protect forced off (ExtraProtectPanel collapsed). Use packer CLI instead:
            // --encrypt-assets (app must use ProtectorAssets), --enable-res-protect,
            // --detect-proxy, --pin-certs <file>.
            EncryptAssets = false,
            EnableResProtect = false,
            DetectProxy = false,
            PinCertsFile = null,
            Channel = string.IsNullOrWhiteSpace(ChannelBox.Text) ? null : ChannelBox.Text.Trim(),
            HollowPrefixes = HollowPrefixBox.Text,
            VmpPrefixes = Vmp1PrefixBox.Text,
            TrueVmpPrefixes = TrueVmpBox.Text,
        };
        if (_signCustom)
        {
            job.Keystore = KeystoreBox.Text.Trim();
            job.Alias = AliasBox.Text.Trim();
            job.StorePass = StorePassBox.Password;
            job.KeyPass = string.IsNullOrEmpty(KeyPassBox.Password) ? StorePassBox.Password : KeyPassBox.Password;
        }

        _cts = new CancellationTokenSource();
        _runner = new EngineRunner();
        _runner.Progress += OnProgress;
        // Queue only — never Dispatcher.Invoke per line (blocks Java stdout pipe).
        _runner.RawLog += AppendLog;
        _lastSizeReport = null;
        _jobWatch.Restart();
        var startedAt = DateTime.Now;

        try
        {
            var code = await _runner.RunAsync(paths, job, _cts.Token).ConfigureAwait(true);
            _jobWatch.Stop();
            if (code == 0)
            {
                PersistSignPrefs();
                _phase = Phase.Done;
                PhaseTitle.Text = Strings.Harden_PhaseDone;
                SetPercent(100);
                MarkStage("done", done: true);
                _lastOutputDir = IOPath.GetDirectoryName(output);
                _lastOutputApk = output;
                await ShowDoneCardAsync(output).ConfigureAwait(true);
                FinishJobLog(output, _jobWatch.Elapsed);
                SaveHistory(job, startedAt, exitCode: 0, error: null);
            }
            else
            {
                _phase = Phase.Error;
                PhaseTitle.Text = string.Format(Strings.Harden_PhaseFailed, code);
                AppendLog(string.Format(Strings.Harden_LogExit, code));
                FinishJobLog(output);
                SaveHistory(job, startedAt, exitCode: code, error: string.Format(Strings.Meta_ExitCode, code));
            }
        }
        catch (OperationCanceledException)
        {
            _jobWatch.Stop();
            _phase = Phase.Ready;
            PhaseTitle.Text = Strings.Harden_PhaseCancelled;
            AppendLog(Strings.Harden_LogCancelled);
            FinishJobLog(output);
        }
        catch (Exception ex)
        {
            _jobWatch.Stop();
            _phase = Phase.Error;
            PhaseTitle.Text = Strings.Harden_PhaseError;
            AppendLog(Strings.Log_ErrorPrefix + ex.Message);
            FinishJobLog(output);
            SaveHistory(job, startedAt, exitCode: -1, error: ex.Message);
        }
        finally
        {
            if (_runner != null)
            {
                _runner.Progress -= OnProgress;
                await _runner.DisposeAsync();
                _runner = null;
            }
            _cts?.Dispose();
            _cts = null;
            UpdateChrome();
        }
    }

    private void SaveHistory(ProtectJobRequest job, DateTime startedAt, int exitCode, string? error)
    {
        long inBytes = 0, outBytes = 0;
        try { if (System.IO.File.Exists(job.InputApk)) inBytes = new System.IO.FileInfo(job.InputApk).Length; } catch { }
        try { if (System.IO.File.Exists(job.OutputApk)) outBytes = new System.IO.FileInfo(job.OutputApk).Length; } catch { }

        var sizeReport = _lastSizeReport;
        if (string.IsNullOrWhiteSpace(sizeReport) || !System.IO.File.Exists(sizeReport))
        {
            var outDir = IOPath.GetDirectoryName(job.OutputApk) ?? "";
            var baseName = IOPath.GetFileNameWithoutExtension(job.OutputApk) + "-size_report.json";
            var inLog = IOPath.Combine(outDir, "Log", baseName);
            if (System.IO.File.Exists(inLog)) sizeReport = inLog;
            else
            {
                // Legacy: report written beside the APK before Log/ layout.
                var beside = IOPath.Combine(outDir, baseName);
                if (System.IO.File.Exists(beside)) sizeReport = beside;
            }
        }

        var jobId = HistoryStore.NewId();
        sizeReport = SnapshotSizeReport(jobId, sizeReport);

        HistoryStore.Add(new HistoryRecord
        {
            Id = jobId,
            Status = exitCode == 0 ? "done" : "failed",
            InputName = IOPath.GetFileName(job.InputApk),
            InputPath = job.InputApk,
            OutputPath = job.OutputApk,
            Profile = job.Profile,
            ProtectSo = job.ProtectSo,
            ProtectSoMode = job.ProtectSoMode,
            PaymentAutoVmp = job.PaymentAutoVmp,
            IndustryAutoVmp = job.IndustryAutoVmp,
            ProtectSoBudgetMb = job.ProtectSoBudgetMb,
            ProtectSoMaxFileMb = job.ProtectSoMaxFileMb,
            EncryptAssets = job.EncryptAssets,
            EnableResProtect = job.EnableResProtect,
            DetectProxy = job.DetectProxy,
            Channel = job.Channel,
            Signed = !string.IsNullOrEmpty(job.Keystore),
            StartedAt = startedAt.ToString("yyyy-MM-dd HH:mm:ss"),
            FinishedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            DurationMs = _jobWatch.ElapsedMilliseconds,
            InputBytes = inBytes,
            OutputBytes = outBytes,
            SizeReport = sizeReport,
            ProtectLog = _lastProtectLog,
            Error = error,
            ExitCode = exitCode
        });
    }

    /// <summary>
    /// Copy size_report beside the APK into AppData so re-protecting the same
    /// output path does not overwrite older security reports.
    /// </summary>
    private static string? SnapshotSizeReport(string jobId, string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path)) return path;
        try
        {
            var dir = IOPath.Combine(AppDataPaths.Root, "reports");
            System.IO.Directory.CreateDirectory(dir);
            var dest = IOPath.Combine(dir, jobId + "-size_report.json");
            System.IO.File.Copy(path, dest, overwrite: true);
            return dest;
        }
        catch
        {
            return path;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        _runner?.Cancel();
        PhaseTitle.Text = Strings.Harden_Cancelling;
    }

    private void OpenDir_Click(object sender, RoutedEventArgs e)
    {
        var dir = _lastOutputDir;
        if (string.IsNullOrEmpty(dir) || !System.IO.Directory.Exists(dir)) return;
        ShellUtil.RevealInExplorer(dir);
    }

    private void HideDeviceInstallUi()
    {
        DeviceBox.ItemsSource = null;
        DeviceBox.Visibility = Visibility.Collapsed;
        DoneOutput.Visibility = Visibility.Collapsed;
        InstallTestBtn.Visibility = Visibility.Collapsed;
        InstallTestBtn.IsEnabled = true;
        InstallTestBtn.IsHitTestVisible = true;
        InstallTestBtn.Content = Strings.Harden_InstallTest;
        _installBusy = false;
    }

    private async Task ShowDoneCardAsync(string outputApk)
    {
        DoneOutput.Text = IOPath.GetFileName(outputApk);
        HideDeviceInstallUi();
        DoneCard.Visibility = Visibility.Visible;

        IReadOnlyList<AdbService.Device> devices;
        try
        {
            devices = await AdbService.ListDevicesAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AppendLog("[adb] " + ex.Message);
            return;
        }

        if (devices.Count == 0)
            return;

        DoneOutput.Visibility = Visibility.Visible;
        DeviceBox.ItemsSource = devices;
        DeviceBox.DisplayMemberPath = nameof(AdbService.Device.DisplayName);
        DeviceBox.SelectedIndex = 0;
        DeviceBox.Visibility = Visibility.Visible;
        InstallTestBtn.Visibility = Visibility.Visible;
    }

    private async void InstallTest_Click(object sender, RoutedEventArgs e)
    {
        if (_installBusy) return;

        if (DeviceBox.SelectedItem is not AdbService.Device device)
        {
            MessageBox.Show(Strings.Harden_NoDeviceSelected, Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var apk = _lastOutputApk;
        if (string.IsNullOrWhiteSpace(apk) || !System.IO.File.Exists(apk))
        {
            MessageBox.Show(string.Format(Strings.Harden_ApkMissing, apk ?? ""), Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (AdbService.FindAdb() == null)
        {
            MessageBox.Show(Strings.Harden_AdbMissing, Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _installBusy = true;
        InstallTestBtn.Visibility = Visibility.Visible;
        InstallTestBtn.IsEnabled = true;
        InstallTestBtn.IsHitTestVisible = false;
        InstallTestBtn.Content = Strings.Harden_Installing;
        AppendLog($"[adb] install --no-incremental -r -t → {device.DisplayName}");

        try
        {
            var result = await AdbService.InstallAndLaunchAsync(
                device.Serial, apk, _lastPackageName).ConfigureAwait(true);
            if (result.Ok)
            {
                AppendLog("[adb] " + result.Message);
                if (result.Launched)
                {
                    MessageBox.Show(string.Format(Strings.Harden_InstallOk, device.DisplayName), Strings.ProductName,
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show(
                        string.Format(Strings.Harden_InstallOkNoLaunch, device.DisplayName, result.Message),
                        Strings.ProductName, MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            else
            {
                AppendLog("[adb] " + result.Message);
                MessageBox.Show(string.Format(Strings.Harden_InstallFail, result.Message), Strings.ProductName,
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            AppendLog("[adb] " + ex.Message);
            MessageBox.Show(string.Format(Strings.Harden_InstallFail, ex.Message), Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _installBusy = false;
            InstallTestBtn.Visibility = Visibility.Visible;
            InstallTestBtn.IsHitTestVisible = true;
            InstallTestBtn.IsEnabled = true;
            InstallTestBtn.Content = Strings.Harden_InstallTest;
        }
    }

    private void OnProgress(EngineProgressEvent evt)
    {
        Dispatcher.BeginInvoke(() =>
        {
            switch (evt.Type)
            {
                case "phase":
                    if (evt.Percent is int p) SetPercent(p);
                    if (!string.IsNullOrEmpty(evt.Id)) MarkStage(evt.Id, current: true);
                    if (!string.IsNullOrEmpty(evt.Message)) AppendLog("\u2192 " + evt.Message);
                    FlushPendingLogs();
                    break;
                case "log":
                    AppendLog(evt.Message ?? "");
                    FlushPendingLogs();
                    break;
                case "done":
                    SetPercent(100);
                    if (!string.IsNullOrEmpty(evt.Output))
                    {
                        _lastOutputDir = IOPath.GetDirectoryName(evt.Output);
                        _lastOutputApk = evt.Output;
                        DoneOutput.Text = IOPath.GetFileName(evt.Output);
                    }
                    if (!string.IsNullOrEmpty(evt.SizeReport))
                    {
                        _lastSizeReport = evt.SizeReport;
                        AppendLog(string.Format(Strings.Log_SizeReport, evt.SizeReport));
                    }
                    FlushPendingLogs();
                    break;
                case "error":
                    AppendLog(Strings.Log_ErrorPrefix + (evt.Message ?? ""));
                    FlushPendingLogs();
                    break;
            }
        });
    }

    private void MarkStage(string id, bool current = false, bool done = false)
    {
        if (done)
        {
            foreach (var d in _stageDots.Values) ApplyDot(d, DotState.Done);
            return;
        }

        foreach (var (sid, _) in Stages())
        {
            if (!_stageDots.TryGetValue(sid, out var dot)) continue;
            if (sid != id) continue;
            foreach (var (prev, _) in Stages())
            {
                if (prev == sid) break;
                if (_stageDots.TryGetValue(prev, out var pd)) ApplyDot(pd, DotState.Done);
            }
            ApplyDot(dot, current ? DotState.Current : DotState.Done);
            break;
        }
    }

    private enum DotState { Pending, Current, Done }

    private static void ApplyDot(Border dot, DotState state)
    {
        switch (state)
        {
            case DotState.Done:
                dot.Background = ThemeService.Brush("StageDoneBg");
                dot.BorderBrush = ThemeService.Brush("Success");
                dot.Child = new TextBlock
                {
                    Text = "OK",
                    FontSize = 8,
                    Foreground = ThemeService.Brush("Success"),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                break;
            case DotState.Current:
                dot.Background = ThemeService.Brush("StageCurrentBg");
                dot.BorderBrush = ThemeService.Brush("Accent");
                dot.Child = new Ellipse { Width = 8, Height = 8, Fill = ThemeService.Brush("AccentSoft") };
                break;
            default:
                dot.Background = ThemeService.Brush("StagePendingBg");
                dot.BorderBrush = ThemeService.Brush("StagePendingBorder");
                dot.Child = new Ellipse { Width = 5, Height = 5, Fill = ThemeService.Brush("StagePendingDot") };
                break;
        }
    }

    private void ResetStages()
    {
        foreach (var d in _stageDots.Values) ApplyDot(d, DotState.Pending);
    }

    private void SetPercent(int pct)
    {
        _percent = Math.Clamp(pct, 0, 100);
        PctText.Text = $"{_percent}%";
        PctText.Foreground = ThemeService.Brush(_percent >= 100 ? "Success" : "Accent");
        ProgressFill.Background = ThemeService.Brush(_percent >= 100 ? "Success" : "Accent");
        Dispatcher.BeginInvoke(() =>
        {
            if (ProgressFill.Parent is FrameworkElement parent && parent.ActualWidth > 0)
                ProgressFill.Width = parent.ActualWidth * _percent / 100.0;
            else
                ProgressFill.Width = Math.Max(4, _percent * 3);
        });
    }

    private void UpdateChrome()
    {
        PrimaryBtn.Visibility = Visibility.Visible;
        SecondaryBtn.Visibility = Visibility.Collapsed;
        ResetBtn.Visibility = Visibility.Collapsed;
        OpenDirBtn.Visibility = Visibility.Collapsed;
        Grid.SetColumn(PrimaryBtn, 0);
        Grid.SetColumnSpan(PrimaryBtn, 3);

        switch (_phase)
        {
            case Phase.Idle:
                PrimaryBtn.IsEnabled = false;
                PrimaryBtn.Content = Strings.Harden_SelectAppFirst;
                break;
            case Phase.Ready:
            case Phase.Error:
                PrimaryBtn.IsEnabled = _paths != null;
                PrimaryBtn.Content = Strings.Harden_Start;
                break;
            case Phase.Running:
                PrimaryBtn.Visibility = Visibility.Collapsed;
                SecondaryBtn.Visibility = Visibility.Visible;
                SecondaryBtn.Content = Strings.Harden_Cancel;
                Grid.SetColumnSpan(SecondaryBtn, 3);
                break;
            case Phase.Done:
                PrimaryBtn.Visibility = Visibility.Collapsed;
                ResetBtn.Visibility = Visibility.Visible;
                OpenDirBtn.Visibility = Visibility.Visible;
                Grid.SetColumn(ResetBtn, 0);
                Grid.SetColumnSpan(ResetBtn, 1);
                Grid.SetColumn(OpenDirBtn, 2);
                Grid.SetColumnSpan(OpenDirBtn, 1);
                break;
        }
    }

    private void BeginJobLog(string inputName)
    {
        EndJobLogWriter();
        while (_pendingLogLines.TryDequeue(out _)) { }
        LogText.Text = "";
        _lastProtectLog = null;
        try
        {
            _logWriter = new ProtectLogWriter(inputName);
            _lastProtectLog = _logWriter.LogPath;
            LogPathHint.Text = _logWriter.LogPath;
        }
        catch (Exception ex)
        {
            LogPathHint.Text = "";
            LogText.Text = string.Format(Strings.Log_OpenFailed, ex.Message) + "\n";
        }
    }

    private void FinishJobLog(string? outputApk, TimeSpan? elapsedForDone = null)
    {
        FlushPendingLogs();
        if (_logWriter == null)
        {
            if (elapsedForDone is TimeSpan el)
                AppendLog("✓ " + string.Format(Strings.Harden_LogDone, FormatElapsedMinutes(el)));
            FlushPendingLogs();
            return;
        }
        try
        {
            var appDataPath = _logWriter.LogPath;
            AppendLog(string.Format(Strings.Harden_LogSavedAppData, appDataPath));
            FlushPendingLogs();
            string? mirror = null;
            if (!string.IsNullOrWhiteSpace(outputApk))
                mirror = _logWriter.MirrorBesideOutput(outputApk);
            if (!string.IsNullOrEmpty(mirror))
            {
                AppendLog(string.Format(Strings.Harden_LogSavedBeside, mirror));
                FlushPendingLogs();
            }

            // Done line last (after save hints), while writer still open.
            if (elapsedForDone is TimeSpan doneElapsed)
            {
                AppendLog("✓ " + string.Format(Strings.Harden_LogDone, FormatElapsedMinutes(doneElapsed)));
                FlushPendingLogs();
            }

            if (!string.IsNullOrEmpty(mirror) && !string.IsNullOrWhiteSpace(outputApk))
            {
                // Refresh mirror so the Log/ copy includes the final lines.
                mirror = _logWriter.MirrorBesideOutput(outputApk!) ?? mirror;
                _lastProtectLog = mirror;
                LogPathHint.Text = mirror;
            }
            else
            {
                _lastProtectLog = appDataPath;
                LogPathHint.Text = appDataPath;
            }
        }
        finally
        {
            EndJobLogWriter();
        }
    }

    /** Whole minutes if ≥1m and exact; otherwise one decimal (e.g. 7.2). */
    private static string FormatElapsedMinutes(TimeSpan elapsed)
    {
        var mins = elapsed.TotalMinutes;
        if (mins < 0.05) return "0.1";
        if (mins >= 1 && Math.Abs(mins - Math.Round(mins)) < 0.05)
            return ((int)Math.Round(mins)).ToString();
        return mins.ToString("0.#");
    }

    private void EndJobLogWriter()
    {
        try { _logWriter?.Dispose(); } catch { /* ignore */ }
        _logWriter = null;
    }

    private void CopyLog_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrEmpty(LogText.Text))
            {
                Clipboard.Clear();
                return;
            }
            if (LogText.SelectionLength > 0)
                Clipboard.SetText(LogText.SelectedText);
            else
                Clipboard.SetText(LogText.Text);
        }
        catch
        {
            // clipboard busy
        }
    }

    private void SelectAllLog_Click(object sender, RoutedEventArgs e)
    {
        LogText.Focus();
        LogText.SelectAll();
    }

    private void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        var path = _lastProtectLog;
        if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
            path = _logWriter?.LogPath;
        if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
        {
            var dir = ProtectLogWriter.LogsDirectory;
            if (System.IO.Directory.Exists(dir))
                ShellUtil.RevealInExplorer(dir);
            else
                MessageBox.Show(Strings.Harden_NoLogYet, Strings.ProductName,
                    MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch
        {
            ShellUtil.RevealInExplorer(IOPath.GetDirectoryName(path)!);
        }
    }

    private void AppendLog(string line)
    {
        if (string.IsNullOrEmpty(line)) return;

        // Packer prints: "Package: com.example.app"
        var pkg = AdbService.TryParsePackageFromEngineLog(line);
        if (!string.IsNullOrWhiteSpace(pkg))
            _lastPackageName = pkg;

        var stamp = DateTime.Now.ToString("HH:mm:ss");
        var stamped = $"[{stamp}]  {line}";
        _pendingLogLines.Enqueue(stamped);
        _logWriter?.Append(stamped);
        EnsureLogFlushTimer();
        if (Dispatcher.CheckAccess())
            FlushPendingLogs();
    }

    private void EnsureLogFlushTimer()
    {
        if (_logFlushTimer != null) return;
        _logFlushTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _logFlushTimer.Tick += (_, _) => FlushPendingLogs();
        _logFlushTimer.Start();
    }

    private void FlushPendingLogs()
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(FlushPendingLogs);
            return;
        }
        if (_pendingLogLines.IsEmpty) return;
        var sb = new StringBuilder();
        while (_pendingLogLines.TryDequeue(out var stamped))
        {
            if (sb.Length > 0) sb.Append('\n');
            sb.Append(stamped);
        }
        if (sb.Length == 0) return;
        if (LogText.Text.Length > 0)
            LogText.AppendText("\n");
        LogText.AppendText(sb.ToString());
        if (LogText.Text.Length > MaxLogChars)
        {
            var t = LogText.Text;
            var keep = MaxLogChars / 2;
            LogText.Text = "…(log truncated)…\n" + t.Substring(t.Length - keep);
        }
        LogText.CaretIndex = LogText.Text.Length;
        LogText.ScrollToEnd();
    }
}
