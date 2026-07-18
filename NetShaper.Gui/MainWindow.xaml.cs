using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using NetShaper.Core.Api;
using NetShaper.Core.Dns;
using NetShaper.Core.Firewall;
using NetShaper.Core.Logging;
using NetShaper.Core.Policy;
using NetShaper.Core.Security;
using NetShaper.Core.Shaping;
using NetShaper.Core.Stats;
using NetShaper.Core.Traffic;
using NetShaper.Core.Wfp;
using Forms = System.Windows.Forms;

namespace NetShaper.Gui;

[SupportedOSPlatform("windows")]
public partial class MainWindow : Window
{
    private const string ServiceName = "NetShaper";
    private readonly ProfileStore _profiles = new();
    private readonly PolicyStore _legacyStore = new();
    private readonly WindowsTrafficSampler _sampler = new();
    private readonly TrafficSampleEngine _sampleEngine;
    private readonly LimitEnforcer _limitEnforcer = new();
    private readonly PolicyEnforcer _enforcer = new();
    private readonly ActivityLog _log = new();
    private readonly RateHistory _rateHistory = new(120);
    private readonly ProcessRateHistory _procHistory = new(48);
    private readonly AskFirewallMonitor _askMonitor = new();
    private readonly AskFirewallController _askController = new();
    private readonly Queue<AskRequest> _askQueue = new();
    private readonly StatsStore _stats = new();
    private readonly DnsCache _dns = new();
    private ApiSettings _apiSettings = ApiSettings.Load();
    private LocalApiServer? _api;
    private RemoteApiServer? _remoteApi;
    private readonly AccessControlStore _aclStore = new();
    private AccessControlDocument _acl = new();
    private AccessRight _myRights = AccessRight.All;
    private readonly DispatcherTimer _timer;
    private List<SystemSamplePoint> _historyPoints = new();
    private GuiSettings _gui = GuiSettings.Load();
    private PolicyDocument _doc = PolicyDocument.CreateDefaults();
    private string _activeProfile = "default";
    private List<ConnectionInfo> _allConnections = new();
    private List<ConnectionInfo> _visibleConnections = new();
    private List<ProcessTraffic> _lastProcesses = new();
    private Forms.NotifyIcon? _tray;
    private bool _reallyClosing;
    private bool _profileComboSilent;
    private bool _loadingUi;
    private bool _askDialogOpen;
    private readonly HashSet<Guid> _toastedQuotas = new();
    private DateTime _sessionStart = DateTime.UtcNow;
    private double _sessionBytesIn;
    private double _sessionBytesOut;
    private DateTime _lastAlertUtc = DateTime.MinValue;
    private int _sampleBusy; // 0=idle, 1=running (Interlocked)
    private TrafficSnapshot? _lastSnap;
    private DispatcherTimer? _filterDebounce;
    private DateTime _lastGridBindUtc = DateTime.MinValue;
    private DateTime _lastChartUtc = DateTime.MinValue;
    private DateTime _lastTitleUtc = DateTime.MinValue;
    private int _shaperBusy;
    private int _selectedPid = -1;
    private static readonly SolidColorBrush ChartInBrush = FreezeBrush(0x3F, 0xB9, 0x50);
    private static readonly SolidColorBrush ChartOutBrush = FreezeBrush(0x58, 0xA6, 0xFF);

    private static SolidColorBrush FreezeBrush(byte r, byte g, byte b)
    {
        var br = new SolidColorBrush(Color.FromRgb(r, g, b));
        if (br.CanFreeze) br.Freeze();
        return br;
    }

    /// <summary>0=Dashboard, 1=Live, … — avoid rebinding invisible grids.</summary>
    private int ActiveTabIndex => Tabs?.SelectedIndex ?? 0;

    public MainWindow()
    {
        // Prefer GPU composition (smoother scrolling / less CPU paint)
        try
        {
            RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.Default;
            Timeline.DesiredFrameRateProperty.OverrideMetadata(
                typeof(Timeline),
                new FrameworkPropertyMetadata { DefaultValue = 30 });
        }
        catch { /* already set */ }

        InitializeComponent();
        _sampleEngine = new TrafficSampleEngine(_sampler)
        {
            PreferEStats = true,
            IncludeConnections = true,
            IntervalSeconds = Math.Clamp(_gui.RefreshSeconds, 1.0, 5),
        };
        _sampleEngine.SnapshotReady += OnEngineSnapshot;
        _loadingUi = true;
        ThemeService.Apply(_gui.Theme);
        _activeProfile = _profiles.GetActiveName();
        _doc = _profiles.LoadActive();
        PolicyPathRun.Text = _profiles.ProfilePath(_activeProfile);
        AdminHint.IsChecked = IsElevated();
        LoadGuiPrefsUi();
        LoadSettingsUi();
        ReloadProfilesCombo();
        LoadTemplates();
        ReloadPinnedList();
        ReloadAllGrids();
        RefreshServiceStatus();
        RefreshStatusPanels(quiet: true);
        InitTray();
        RefreshActivityGrid();
        ApplyStatsSettingsFromGui();
        StatsDbPathText.Text = "DB: " + _stats.DbPath;
        RefreshHistoryView();
        FilterMatcher.SharedDns = _dns;
        _enforcer.Dns = _dns;
        if (_doc.DnsEnabled)
        {
            _dns.StartBackground();
            _dns.RefreshFromSystemDnsCache();
        }
        RefreshDnsGrid();
        LoadApiUi();
        if (_apiSettings.Enabled)
            TryStartApi(quiet: true);
        ReloadAclUi();
        ApplyRightsToUi();
        _loadingUi = false;

        // Never block UI on activity log refresh
        _log.EntryAdded += e => Dispatcher.BeginInvoke(() =>
        {
            if (ActiveTabIndex == 9) // Activity tab only when visible
                RefreshActivityGrid();
            if (ChkToasts.IsChecked == true && e.Level is ActivityLevel.Warn or ActivityLevel.Error or ActivityLevel.Success)
                ToastWindow.ShowToast(this, e.Level.ToString(), e.Message, warn: e.Level != ActivityLevel.Success);
        }, DispatcherPriority.Background);

        // UI timer: quotas / ask only. Shaper runs off UI thread.
        var interval = Math.Clamp(_gui.RefreshSeconds, 1.0, 5);
        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(Math.Max(1.0, interval)),
        };
        _timer.Tick += (_, _) => OnTick();
        _timer.Start();
        _sampleEngine.IntervalSeconds = interval;
        _sampleEngine.PreferEStats = true;
        _sampleEngine.Start(); // dedicated LongRunning sampler

        if (App.StartMinimized || _gui.StartMinimized)
        {
            WindowState = WindowState.Minimized;
            if (_gui.TrayEnabled) Hide();
        }

        LogInfo("Ready — NetShaper free open-source build.");
        // First-run tips after the window is shown (don't block InitializeComponent)
        Loaded += (_, _) =>
        {
            if (_gui.WelcomeSeen) return;
            try
            {
                ShowWelcomeTips();
                _gui.WelcomeSeen = true;
                _gui.Save();
            }
            catch { /* non-fatal */ }
        };
    }

    private void ShowWelcomeTips()
    {
        var elevated = IsElevated();
        MessageBox.Show(
            "Welcome to NetShaper — free open-source bandwidth limiter\n\n" +
            "Quick start:\n" +
            "1. Live traffic — watch per-app rates (warm-up 1–2 sec)\n" +
            "2. Limits / Rules — limit or block an app, then Apply all\n" +
            "3. Shaper modes: Soft (default), QoS, Aggressive, Packet (WinDivert)\n\n" +
            (elevated
                ? "You are elevated — Apply all / WFP / QoS can enforce system-wide.\n"
                : "Not elevated — you can store rules; Apply all needs Administrator.\n") +
            "\nOptional: Setup.cmd option [3] installs WinDivert for smooth Packet mode.\n" +
            "Help: https://github.com/ksanjeev284/NetShaper",
            "NetShaper — getting started",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void LogInfo(string m, string? d = null) { _log.Info(m, d); SetStatus(m); }
    private void LogOk(string m, string? d = null) { _log.Success(m, d); SetStatus(m); }
    private void LogWarn(string m, string? d = null) { _log.Warn(m, d); SetStatus(m); }

    private void OnTick()
    {
        // Sync engine prefs from UI (cheap). Stats checkbox only controls DB recording
        // in OnEngineSnapshot — never gate quota / Ask / bandwidth shaper here.
        try
        {
            _sampleEngine.PreferEStats = ChkEStats.IsChecked != false;
            _sampleEngine.IntervalSeconds = Math.Clamp(_gui.RefreshSeconds, 1.0, 5);
        }
        catch { /* */ }

        // Quota: use last engine snapshot — never re-sample on UI thread
        if (ChkQuota.IsChecked == true && _lastSnap is { } snap)
        {
            try
            {
                var exceeded = _enforcer.TickQuota(_doc, snap, ChkQuotaAutoBlock.IsChecked == true);
                if (exceeded.Count > 0)
                {
                    SavePolicy(null, tryAuto: false);
                    foreach (var id in exceeded.Where(id => _toastedQuotas.Add(id)))
                        LogWarn("Quota exceeded — block rule added", id.ToString("N")[..8]);
                    if (ChkApplyOnSave.IsChecked == true && IsElevated())
                        TryAutoApplyAll();
                }
                else if (ActiveTabIndex == 5) // Quotas tab
                    ReloadQuotasGrid();
            }
            catch { /* non-fatal */ }
        }

        TickAskFirewall();
        // Shaper off UI thread so clicks stay responsive
        TickBandwidthShaperAsync();
    }

    private void ApplyStatsSettingsFromGui()
    {
        _stats.RetentionDays = Math.Clamp(_gui.StatsRetentionDays, 1, 3650);
        StatsRetentionBox.Text = _stats.RetentionDays.ToString();
        ChkStatsProcesses.IsChecked = _gui.StatsRecordProcesses;
    }

    private void StatsRetention_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        if (int.TryParse(StatsRetentionBox.Text, out var d) && d >= 1)
        {
            _gui.StatsRetentionDays = d;
            _stats.RetentionDays = d;
            _gui.Save();
            LogInfo($"Stats retention → {d} days");
        }
    }

    private (DateTimeOffset from, DateTimeOffset to) GetHistoryRange()
    {
        var to = DateTimeOffset.UtcNow;
        return HistoryRangeCombo.SelectedIndex switch
        {
            1 => (to.AddHours(-6), to),
            2 => (to.AddHours(-24), to),
            3 => (to.AddDays(-7), to),
            4 => (to.AddDays(-30), to),
            _ => (to.AddHours(-1), to),
        };
    }

    private void HistoryRange_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded) RefreshHistoryView();
    }

    private void HistoryRefresh_Click(object sender, RoutedEventArgs e) => RefreshHistoryView();

    private void RefreshHistoryView()
    {
        try
        {
            var (from, to) = GetHistoryRange();
            HistoryRangeLabel.Text = $"{from.ToLocalTime():g} → {to.ToLocalTime():g}";
            _historyPoints = _stats.QuerySystem(from, to).ToList();
            DrawHistoryChart();

            var apps = _stats.QueryTopApps(from, to, 40);
            var total = apps.Sum(a => a.BytesIn + a.BytesOut);
            if (total <= 0) total = 1;
            HistoryAppsGrid.ItemsSource = apps.Select(a => new HistoryAppRow
            {
                Name = a.Name,
                InDisplay = FormatBytes(a.BytesIn),
                OutDisplay = FormatBytes(a.BytesOut),
                TotalDisplay = FormatBytes(a.BytesIn + a.BytesOut),
                ShareDisplay = $"{100.0 * (a.BytesIn + a.BytesOut) / total:0.0}%",
            }).ToList();

            var info = _stats.GetInfo();
            HistoryInfoText.Text =
                $"Stats · {info.SampleCount:N0} samples · {info.ProcessSampleCount:N0} proc rows · " +
                $"{FormatBytes(info.FileBytes)} · keep {_stats.RetentionDays}d";
            StatsDbPathText.Text = "DB: " + info.Path;
        }
        catch (Exception ex)
        {
            HistoryInfoText.Text = "History error: " + ex.Message;
        }
    }

    private void DrawHistoryChart()
    {
        HistoryCanvas.Children.Clear();
        var samples = _historyPoints;
        if (samples.Count < 2) return;
        double w = HistoryCanvas.ActualWidth;
        double h = HistoryCanvas.ActualHeight;
        if (w < 10 || h < 10) return;
        double max = samples.Max(s => Math.Max(s.BitsIn, s.BitsOut));
        if (max < 1) max = 1;

        void AddLine(Func<SystemSamplePoint, long> sel, Color color)
        {
            var poly = new Polyline
            {
                Stroke = new SolidColorBrush(color),
                StrokeThickness = 1.6,
                StrokeLineJoin = PenLineJoin.Round,
            };
            for (int i = 0; i < samples.Count; i++)
            {
                double x = i * (w - 4) / (samples.Count - 1) + 2;
                double y = h - 4 - (sel(samples[i]) / max) * (h - 14);
                poly.Points.Add(new Point(x, Math.Clamp(y, 2, h - 2)));
            }
            HistoryCanvas.Children.Add(poly);
        }
        AddLine(s => s.BitsIn, Color.FromRgb(0x3D, 0xDC, 0x97));
        AddLine(s => s.BitsOut, Color.FromRgb(0x3D, 0x8B, 0xFF));
    }

    private void HistoryCanvas_SizeChanged(object sender, SizeChangedEventArgs e) => DrawHistoryChart();

    private void HistoryExportSystem_Click(object sender, RoutedEventArgs e)
    {
        var (from, to) = GetHistoryRange();
        var dlg = new SaveFileDialog
        {
            Filter = "CSV (*.csv)|*.csv",
            FileName = $"netshaper-system-{DateTime.Now:yyyyMMdd-HHmm}.csv",
        };
        if (dlg.ShowDialog() != true) return;
        File.WriteAllText(dlg.FileName, _stats.ExportSystemCsv(from, to));
        LogOk("Exported system history", dlg.FileName);
    }

    private void HistoryExportApps_Click(object sender, RoutedEventArgs e)
    {
        var (from, to) = GetHistoryRange();
        var dlg = new SaveFileDialog
        {
            Filter = "CSV (*.csv)|*.csv",
            FileName = $"netshaper-apps-{DateTime.Now:yyyyMMdd-HHmm}.csv",
        };
        if (dlg.ShowDialog() != true) return;
        File.WriteAllText(dlg.FileName, _stats.ExportTopAppsCsv(from, to));
        LogOk("Exported app history", dlg.FileName);
    }

    private void HistoryPurge_Click(object sender, RoutedEventArgs e)
    {
        _stats.PurgeOlderThan(_stats.RetentionDays);
        RefreshHistoryView();
        LogInfo($"Purged stats older than {_stats.RetentionDays} days");
    }

    private void HistoryClear_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Delete ALL stats history?", "NetShaper",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _stats.ClearAll();
        RefreshHistoryView();
        LogWarn("All stats history cleared");
    }

    private void HistoryApps_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (HistoryAppsGrid.SelectedItem is not HistoryAppRow row) return;
        ProcessFilter.Text = row.Name;
        Tabs.SelectedIndex = 1; // Live
        LogInfo("Filtered live view: " + row.Name);
    }

    /// <summary>
    /// Runs shaper on a worker thread using the latest engine snapshot.
    /// Never calls Sample() on the UI thread (was the main click-lag source).
    /// </summary>
    private void TickBandwidthShaperAsync()
    {
        if (!_doc.LimiterEnabled || _doc.ShaperMode == BandwidthShaperMode.Off)
            return;
        if (Interlocked.CompareExchange(ref _shaperBusy, 1, 0) != 0)
            return;

        var snap = _lastSnap ?? _sampleEngine.TryGetLatest();
        if (snap is null)
        {
            Interlocked.Exchange(ref _shaperBusy, 0);
            return;
        }

        var doc = _doc;
        var elevated = IsElevated();
        _ = Task.Run(() =>
        {
            try
            {
                _enforcer.Shaper.QosResyncInterval = TimeSpan.FromSeconds(45);
                var result = _enforcer.Shaper.Tick(doc, snap, elevated, snap.Connections);
                Dispatcher.BeginInvoke(() =>
                {
                    try
                    {
                        if (ActiveTabIndex == 4) // Limits tab only
                            UpdateLimitsLiveGrid(result);
                        else
                        {
                            // Light status line only
                            var pkt = _enforcer.Shaper.Packet;
                            ShaperStatusText.Text = $"Bandwidth shaper · {doc.ShaperMode}" +
                                (result.QosSynced ? " · QoS synced" : "") +
                                (elevated ? " · elevated" : " · not elevated") +
                                (doc.ShaperMode == BandwidthShaperMode.Packet
                                    ? $" · divert={pkt.Status}"
                                    : "");
                        }
                        if (result.SoftActions > 0 || result.KilledConnections > 0)
                            SetStatus(result.Summary);
                    }
                    finally
                    {
                        Interlocked.Exchange(ref _shaperBusy, 0);
                    }
                }, DispatcherPriority.Background);
            }
            catch (Exception ex)
            {
                Dispatcher.BeginInvoke(() =>
                {
                    LimitsGapText.Text = "Shaper error: " + ex.Message;
                    Interlocked.Exchange(ref _shaperBusy, 0);
                }, DispatcherPriority.Background);
            }
        });
    }

    private void TickBandwidthShaper() => TickBandwidthShaperAsync();

    private void UpdateLimitsLiveGrid(BandwidthShaper.TickResult result)
    {
        var policyLimits = _limitEnforcer.GetActiveLimits(_doc)
            .ToDictionary(l => l.RuleId);
        var rows = new List<LimitRow>();
        foreach (var s in result.Statuses)
        {
            policyLimits.TryGetValue(s.RuleId, out var pl);
            rows.Add(new LimitRow
            {
                FilterName = s.FilterName,
                LimitDisplay = $"{PolicyEditor.BytesPerSecToKbps(s.LimitBytesPerSec)} kbps",
                MeasuredDisplay = ProcessTraffic.FormatRate(s.MeasuredBitsPerSec),
                OverLimit = s.OverLimit,
                Action = s.Action,
                ProcessSummary = s.ProcessSummary,
                MatchedProcesses = s.MatchedProcesses,
                Matchers = pl is null ? "" : string.Join("; ", pl.MatcherSummary),
                Kbps = PolicyEditor.BytesPerSecToKbps(s.LimitBytesPerSec),
                Direction = pl?.Direction.ToString() ?? "",
                ScheduleActive = s.ScheduleActive,
            });
        }
        // include limits with no live match yet
        foreach (var pl in _limitEnforcer.GetActiveLimits(_doc))
        {
            if (rows.Any(r => r.FilterName == pl.FilterName && r.Kbps == PolicyEditor.BytesPerSecToKbps(pl.BytesPerSec)))
                continue;
            if (result.Statuses.Any(s => s.RuleId == pl.RuleId)) continue;
            rows.Add(new LimitRow
            {
                FilterName = pl.FilterName,
                LimitDisplay = $"{PolicyEditor.BytesPerSecToKbps(pl.BytesPerSec)} kbps",
                MeasuredDisplay = "—",
                OverLimit = false,
                Action = pl.ScheduleActive ? "idle" : "sched-off",
                ProcessSummary = "",
                MatchedProcesses = 0,
                Matchers = string.Join("; ", pl.MatcherSummary),
                Kbps = PolicyEditor.BytesPerSecToKbps(pl.BytesPerSec),
                Direction = pl.Direction.ToString(),
                ScheduleActive = pl.ScheduleActive,
            });
        }
        LimitsGrid.ItemsSource = rows;
        LimitsGapText.Text = _limitEnforcer.ExplainGap(_doc);
        var pkt = _enforcer.Shaper.Packet;
        ShaperStatusText.Text = $"Bandwidth shaper · {_doc.ShaperMode}" +
            (result.QosSynced ? " · QoS synced" : "") +
            (IsElevated() ? " · elevated" : " · not elevated (QoS/pulse/packet need admin)") +
            (_doc.ShaperMode == BandwidthShaperMode.Packet
                ? $" · divert={pkt.Status} pkts={pkt.PacketsHandled} delayed={pkt.PacketsDelayed}"
                : "");
    }

    private void ProbeWinDivert_Click(object sender, RoutedEventArgs e)
    {
        var msg = _enforcer.Shaper.PacketProbe;
        MessageBox.Show(
            msg + "\n\nInstall (admin):\n  scripts\\install-windivert.ps1\n\n" +
            "Then set Limits mode to Packet and run elevated.",
            "WinDivert probe");
        LogInfo(msg);
    }

    private void ShaperMode_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        _doc.ShaperMode = ShaperModeCombo.SelectedIndex switch
        {
            0 => BandwidthShaperMode.Off,
            1 => BandwidthShaperMode.Qos,
            3 => BandwidthShaperMode.Aggressive,
            4 => BandwidthShaperMode.Packet,
            _ => BandwidthShaperMode.Soft,
        };
        if (_doc.ShaperMode != BandwidthShaperMode.Off)
            _doc.LimiterEnabled = true;
        SavePolicy($"Shaper mode → {_doc.ShaperMode}", tryAuto: _doc.ShaperMode >= BandwidthShaperMode.Qos);
        LimitsGapText.Text = _limitEnforcer.ExplainGap(_doc);
    }

    private void TickAskFirewall()
    {
        if (!_doc.AskModeEnabled) return;
        try
        {
            _askMonitor.PruneDeadProcesses();
            // Never Sample() on UI thread — reuse engine snapshot (same as quota/shaper)
            var snap = _lastSnap ?? _sampleEngine.TryGetLatest();
            if (snap is null) return;
            var news = _askMonitor.FindNewAsks(_doc, snap);
            foreach (var r in news)
            {
                _askMonitor.MarkPending(r.Key);
                _askQueue.Enqueue(r);
                LogWarn($"Ask: {r.ProcessName} (PID {r.ProcessId})", r.ExecutablePath);
                if (ChkToasts.IsChecked == true)
                    ToastWindow.ShowToast(this, "Firewall Ask", r.ProcessName + " is using the network", warn: true);
            }
            UpdateAskBadge();
            PumpAskQueue();
        }
        catch (Exception ex)
        {
            LogWarn("Ask monitor error: " + ex.Message);
        }
    }

    private void UpdateAskBadge()
    {
        var n = _askQueue.Count;
        AskQueueBadge.Text = n > 0 ? $"({n})" : "";
    }

    private void PumpAskQueue()
    {
        if (_askDialogOpen || _askQueue.Count == 0) return;
        var req = _askQueue.Peek();
        _askDialogOpen = true;
        try
        {
            // Restore window if in tray so user can answer
            if (!IsVisible)
            {
                Show();
                WindowState = WindowState.Normal;
                Activate();
            }

            var dlg = new AskDialog(req, IsElevated()) { Owner = IsVisible ? this : null };
            var ok = dlg.ShowDialog() == true && dlg.Result is AskDecisionKind kind;
            _askQueue.Dequeue();
            _askMonitor.ClearPending(req.Key);

            if (!ok || dlg.Result is null)
            {
                // closed without choice → treat as skip for session to avoid loop
                _askMonitor.Remember(new AskDecision
                {
                    Key = req.Key,
                    Kind = AskDecisionKind.Skip,
                    ProcessId = req.ProcessId,
                });
                UpdateAskBadge();
                return;
            }

            _askController.PreferPersistentPolicyWfp = ChkPersistWfp.IsChecked == true;
            var result = _askController.ApplyDecision(_doc, req, dlg.Result.Value, IsElevated(), _askMonitor);
            if (result.PolicyChanged)
            {
                _profiles.SaveProfile(_activeProfile, _doc);
                ReloadAllGrids();
                if (IsElevated())
                {
                    // Full re-apply so Always rules + lockdown stay consistent
                    try
                    {
                        var r = _enforcer.ApplyAll(_doc, ChkPersistWfp.IsChecked == true, applyWfp: true, applyQos: false);
                        LogOk(result.Message + " · " + r.Summary);
                    }
                    catch (Exception ex)
                    {
                        LogWarn(result.Message + " · WFP re-apply: " + ex.Message);
                    }
                }
                else
                {
                    LogOk(result.Message + " · saved (Apply WFP as admin to enforce)");
                }
            }
            else
            {
                LogOk(result.Message + (result.WfpApplied ? " · temp WFP ok" : (IsElevated() ? "" : " · no WFP (not elevated)")));
            }
        }
        finally
        {
            _askDialogOpen = false;
            UpdateAskBadge();
            // chain next on dispatcher so UI can breathe
            if (_askQueue.Count > 0)
                Dispatcher.BeginInvoke(new Action(PumpAskQueue), DispatcherPriority.Background);
        }
    }

    private void AskMode_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        var on = (sender == ChkAskMode ? ChkAskMode.IsChecked : ChkAskModeSettings.IsChecked) == true;
        _loadingUi = true;
        ChkAskMode.IsChecked = on;
        ChkAskModeSettings.IsChecked = on;
        _loadingUi = false;
        _doc.AskModeEnabled = on;
        if (on)
        {
            _doc.FirewallEnabled = true;
            _loadingUi = true;
            ChkFirewall.IsChecked = true;
            _loadingUi = false;
        }
        SavePolicy(on ? "Ask firewall enabled — new network apps will prompt" : "Ask firewall disabled",
            tryAuto: false);
    }

    private void AskOptions_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        _doc.AskIgnoreSystemProcesses = ChkAskIgnoreSystem.IsChecked != false;
        _doc.AskIncludeListeners = ChkAskListeners.IsChecked == true;
        SavePolicy("Ask options saved", tryAuto: false);
    }

    private void ClearAskSession_Click(object sender, RoutedEventArgs e)
    {
        _askMonitor.ClearSession();
        _askQueue.Clear();
        UpdateAskBadge();
        LogInfo("Ask session decisions cleared");
    }

    private void ShowAskQueue_Click(object sender, RoutedEventArgs e)
    {
        if (_askQueue.Count == 0)
        {
            MessageBox.Show("No pending Ask prompts.", "NetShaper Ask");
            return;
        }
        var list = string.Join("\n", _askQueue.Select(r => $"• {r.ProcessName} PID {r.ProcessId} → {r.SampleRemote}"));
        MessageBox.Show($"{_askQueue.Count} pending:\n\n{list}", "NetShaper Ask queue");
        PumpAskQueue();
    }

    private static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void SetStatus(string msg) => StatusBar.Text = msg;

    private void InitTray()
    {
        System.Drawing.Icon? trayIcon = null;
        try
        {
            var icoPath = Path.Combine(AppContext.BaseDirectory, "Assets", "NetShaper.ico");
            if (!File.Exists(icoPath))
                icoPath = Path.Combine(AppContext.BaseDirectory, "NetShaper.ico");
            if (File.Exists(icoPath))
                trayIcon = new System.Drawing.Icon(icoPath);
        }
        catch { /* fall back */ }

        _tray = new Forms.NotifyIcon
        {
            Text = "NetShaper",
            Visible = true,
            Icon = trayIcon ?? System.Drawing.SystemIcons.Application,
        };
        _tray.DoubleClick += (_, _) => RestoreFromTray();
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Apply all", null, (_, _) => Dispatcher.Invoke(() => ApplyAll_Click(this, new RoutedEventArgs())));
        menu.Items.Add("Exit", null, (_, _) => { _reallyClosing = true; Close(); });
        _tray.ContextMenuStrip = menu;
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (ChkTray.IsChecked == true && WindowState == WindowState.Minimized)
        {
            Hide();
            _tray?.ShowBalloonTip(700, "NetShaper", "Running in tray", Forms.ToolTipIcon.Info);
        }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_reallyClosing && ChkTray.IsChecked == true)
        {
            e.Cancel = true;
            WindowState = WindowState.Minimized;
            return;
        }
        _timer.Stop();
        try { _sampleEngine.Dispose(); } catch { /* ignore */ }
        try { _sampler.Dispose(); } catch { /* ignore */ }
        _askController.Dispose();
        try { _enforcer.Shaper.Dispose(); } catch { /* ignore */ }
        try { _stats.Dispose(); } catch { /* ignore */ }
        try { _dns.StopBackground(); } catch { /* ignore */ }
        try { _api?.Dispose(); } catch { /* ignore */ }
        try { _remoteApi?.Dispose(); } catch { /* ignore */ }
        if (_tray != null) { _tray.Visible = false; _tray.Dispose(); _tray = null; }
    }

    private void LoadApiUi()
    {
        _apiSettings = ApiSettings.Load();
        _apiSettings.EnsureKey();
        ChkApiEnabled.IsChecked = _apiSettings.Enabled;
        ApiPortBox.Text = _apiSettings.Port.ToString();
        ChkRemoteApi.IsChecked = _apiSettings.RemoteEnabled;
        RemotePortBox.Text = _apiSettings.RemotePort.ToString();
        RemoteHostBox.Text = _apiSettings.RemoteHostName;
        ChkRemoteNonLocal.IsChecked = _apiSettings.AllowNonLocal;
        UpdateApiStatusText();
        UpdateRemoteApiStatusText();
        DriverStatusText.Text = _enforcer.Shaper.Driver.StatusText();
    }

    private void UpdateApiStatusText()
    {
        var run = _api?.IsRunning == true;
        ApiStatusText.Text =
            $"URL: {_apiSettings.BaseUrl}/api/v1  ·  running={run}\n" +
            $"Key file: {ApiSettings.FilePath}\n" +
            (string.IsNullOrEmpty(_api?.LastError) ? "" : "Error: " + _api!.LastError);
    }

    private void UpdateRemoteApiStatusText()
    {
        var run = _remoteApi?.IsRunning == true;
        RemoteApiStatusText.Text =
            $"mTLS: {_apiSettings.RemoteBaseUrl}/api/v1  ·  running={run}  ·  clients={_remoteApi?.ActiveClients ?? 0}\n" +
            $"Certs: {CertificateManager.CertsDir}  ·  PKI ready={CertificateManager.HasPki}  ·  pwd={CertificateManager.PasswordSource}\n" +
            (string.IsNullOrEmpty(_remoteApi?.LastError) ? "" : "Error: " + _remoteApi!.LastError);
    }

    private void TryStartApi(bool quiet)
    {
        try
        {
            _api?.Dispose();
            if (int.TryParse(ApiPortBox.Text, out var port) && port is > 0 and < 65536)
                _apiSettings.Port = port;
            _apiSettings.Host = "127.0.0.1";
            _apiSettings.EnsureKey();
            _api = new LocalApiServer(new ApiServices
            {
                PolicyStore = _legacyStore,
                Sampler = _sampler,
                Enforcer = _enforcer,
                Stats = _stats,
                Dns = _dns,
            }, _apiSettings);
            _api.Start();
            _apiSettings.Enabled = true;
            _apiSettings.Save();
            if (!quiet) LogOk($"API listening {_apiSettings.BaseUrl}");
        }
        catch (Exception ex)
        {
            LogWarn("API start failed: " + ex.Message);
            if (!quiet)
                MessageBox.Show(ex.Message + "\n\nIf port is in use, change port. URL ACL rarely needed for 127.0.0.1.",
                    "API");
        }
        UpdateApiStatusText();
    }

    private void ApiEnabled_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        if (ChkApiEnabled.IsChecked == true)
            TryStartApi(quiet: false);
        else
        {
            _api?.Stop();
            _apiSettings.Enabled = false;
            _apiSettings.Save();
            LogInfo("Local API stopped");
            UpdateApiStatusText();
        }
    }

    private void ApiSettings_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        if (int.TryParse(ApiPortBox.Text, out var port) && port is > 0 and < 65536)
        {
            _apiSettings.Port = port;
            _apiSettings.Save();
            if (_api?.IsRunning == true)
                TryStartApi(quiet: true);
            UpdateApiStatusText();
        }
    }

    private void ApiCopyUrl_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_apiSettings.BaseUrl + "/api/v1");
            SetStatus("API URL copied");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void ApiCopyKey_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_apiSettings.ApiKey);
            SetStatus("API key copied");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void ApiRegenKey_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Regenerate API key? Existing clients will break.", "NetShaper",
                MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
        _apiSettings.ApiKey = ApiSettings.GenerateKey();
        _apiSettings.Save();
        if (_api?.IsRunning == true)
            TryStartApi(quiet: true);
        LogWarn("API key regenerated");
        UpdateApiStatusText();
    }

    private void RemoteApi_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        if (ChkRemoteApi.IsChecked == true)
            TryStartRemoteApi();
        else
        {
            _remoteApi?.Stop();
            _apiSettings.RemoteEnabled = false;
            _apiSettings.Save();
            LogInfo("Remote mTLS API stopped");
            UpdateRemoteApiStatusText();
        }
    }

    private void RemoteApiSettings_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        if (int.TryParse(RemotePortBox.Text, out var p) && p is > 0 and < 65536)
            _apiSettings.RemotePort = p;
        _apiSettings.RemoteHostName = string.IsNullOrWhiteSpace(RemoteHostBox.Text)
            ? Environment.MachineName : RemoteHostBox.Text.Trim();
        _apiSettings.AllowNonLocal = ChkRemoteNonLocal.IsChecked == true;
        _apiSettings.Save();
        if (_remoteApi?.IsRunning == true)
            TryStartRemoteApi();
        UpdateRemoteApiStatusText();
    }

    private void TryStartRemoteApi()
    {
        try
        {
            if (!EnsureControl("start remote API")) return;
            _remoteApi?.Dispose();
            if (int.TryParse(RemotePortBox.Text, out var p) && p is > 0 and < 65536)
                _apiSettings.RemotePort = p;
            _apiSettings.RemoteHostName = string.IsNullOrWhiteSpace(RemoteHostBox.Text)
                ? Environment.MachineName : RemoteHostBox.Text.Trim();
            _apiSettings.AllowNonLocal = ChkRemoteNonLocal.IsChecked == true;
            CertificateManager.EnsurePki(_apiSettings.RemoteHostName);
            _remoteApi = new RemoteApiServer(new ApiServices
            {
                PolicyStore = _legacyStore,
                Sampler = _sampler,
                Enforcer = _enforcer,
                Stats = _stats,
                Dns = _dns,
            }, _apiSettings);
            _remoteApi.Start();
            _apiSettings.RemoteEnabled = true;
            _apiSettings.Save();
            LogOk($"Remote mTLS API on port {_apiSettings.RemotePort}");
        }
        catch (Exception ex)
        {
            LogWarn("Remote API failed: " + ex.Message);
            MessageBox.Show(ex.Message, "Remote API");
        }
        UpdateRemoteApiStatusText();
    }

    private void CertsEnsure_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            CertificateManager.EnsurePki(RemoteHostBox.Text?.Trim());
            LogOk("CA + server certificates ready");
            UpdateRemoteApiStatusText();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void CertsIssue_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new InputDialog("Client certificate", "Client name:", "admin-client") { Owner = this };
        if (dlg.ShowDialog() != true) return;
        try
        {
            CertificateManager.EnsurePki(_apiSettings.RemoteHostName);
            var (_, path) = CertificateManager.IssueClientCertificate(dlg.Value);
            var pwdNote = CertificateManager.IsUsingLegacyDevPassword
                ? "LEGACY password — run CLI: certs rotate <newPassword>"
                : CertificateManager.PfxPassword;
            LogOk("Issued client cert: " + path);
            MessageBox.Show(
                $"Client PFX:\n{path}\n\nPassword:\n{pwdNote}\n\n" +
                $"Source: {CertificateManager.PasswordSource}\n" +
                "Copy PFX to the remote client machine.",
                "Client certificate");
            UpdateRemoteApiStatusText();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void CertsFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(CertificateManager.CertsDir);
        Process.Start(new ProcessStartInfo("explorer.exe", CertificateManager.CertsDir) { UseShellExecute = true });
    }

    private void DriverStatus_Click(object sender, RoutedEventArgs e)
    {
        DriverStatusText.Text = _enforcer.Shaper.Driver.StatusText() + "\n" + _enforcer.Shaper.PacketProbe;
        LogInfo(DriverStatusText.Text);
    }

    private void DriverPush_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("push driver limits")) return;
        if (!_enforcer.Shaper.Driver.PushLimitsFromPolicy(_doc))
        {
            MessageBox.Show(_enforcer.Shaper.Driver.LastError ?? "Push failed", "Driver");
            return;
        }
        DriverStatusText.Text = _enforcer.Shaper.Driver.StatusText();
        LogOk("Limits pushed to kernel driver");
    }

    private void DriverDocs_Click(object sender, RoutedEventArgs e)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var readme = Path.Combine(dir.FullName, "driver", "README.md");
            if (File.Exists(readme))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{readme}\"") { UseShellExecute = true });
                return;
            }
            dir = dir.Parent;
        }
        MessageBox.Show("driver\\README.md not found next to sources.", "Driver");
    }

    private void DnsEnabled_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        _doc.DnsEnabled = ChkDns.IsChecked != false;
        if (_doc.DnsEnabled)
        {
            _dns.StartBackground();
            _dns.RefreshFromSystemDnsCache();
        }
        else
        {
            _dns.StopBackground();
        }
        SavePolicy(_doc.DnsEnabled ? "DNS enrichment on" : "DNS enrichment off", tryAuto: false);
        RefreshDnsGrid();
    }

    private void DnsRefresh_Click(object sender, RoutedEventArgs e)
    {
        _dns.RefreshFromSystemDnsCache();
        RefreshDnsGrid();
        LogInfo($"DNS cache refreshed · hosts={_dns.CountHosts} ips={_dns.CountIps}");
    }

    private void DnsClear_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Clear in-memory DNS map?", "NetShaper", MessageBoxButton.YesNo) != MessageBoxResult.Yes)
            return;
        _dns.Clear();
        RefreshDnsGrid();
        LogInfo("DNS map cleared");
    }

    private void RefreshDnsGrid()
    {
        DnsGrid.ItemsSource = _dns.Snapshot(400);
        DnsStatusText.Text = $"DNS map · {_dns.CountHosts} hosts · {_dns.CountIps} IPs" +
            (_doc.DnsEnabled ? "" : " (disabled)");
    }

    private async void DnsResolve_Click(object sender, RoutedEventArgs e)
    {
        var d = (DnsDomainBox.Text ?? "").Trim().TrimEnd('.');
        if (d.Length == 0)
        {
            MessageBox.Show("Enter a domain.");
            return;
        }
        await _dns.ResolveHostAsync(d);
        RefreshDnsGrid();
        var ips = _dns.GetIpsForHost(d);
        LogOk($"Resolved {d} → {(ips.Count == 0 ? "(none)" : string.Join(", ", ips.Take(8)))}");
    }

    private void DnsBlockDomain_Click(object sender, RoutedEventArgs e)
    {
        var d = (DnsDomainBox.Text ?? "").Trim().TrimEnd('.');
        if (d.Length == 0) { MessageBox.Show("Enter a domain."); return; }
        _ = _dns.ResolveHostAsync(d);
        PolicyEditor.AddDomainBlock(_doc, d, TrafficDirection.Both);
        SavePolicy($"Block domain {d} — Apply WFP to enforce IPs");
        if (IsElevated())
            ApplyWfp_Click(sender, e);
        RefreshDnsGrid();
    }

    private void DnsAllowDomain_Click(object sender, RoutedEventArgs e)
    {
        var d = (DnsDomainBox.Text ?? "").Trim().TrimEnd('.');
        if (d.Length == 0) { MessageBox.Show("Enter a domain."); return; }
        _ = _dns.ResolveHostAsync(d);
        PolicyEditor.AddDomainAllow(_doc, d, TrafficDirection.Both);
        SavePolicy($"Allow domain {d} — Apply WFP to enforce IPs");
        if (IsElevated())
            ApplyWfp_Click(sender, e);
        RefreshDnsGrid();
    }

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.F5) { Refresh_Click(this, new RoutedEventArgs()); e.Handled = true; }
        if (e.Key == Key.A && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            ApplyAll_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
    }

    private void Topmost_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        Topmost = ChkTopmost.IsChecked == true;
        _gui.Topmost = Topmost;
        _gui.Save();
    }

    private void RefreshSlider_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (!IsLoaded || _timer is null || _loadingUi) return;
        var s = Math.Round(RefreshSlider.Value, 1);
        s = Math.Clamp(s, 1.0, 5.0);
        RefreshLabel.Text = $"{s:0.0} s";
        _timer.Interval = TimeSpan.FromSeconds(s);
        _sampleEngine.IntervalSeconds = s;
        _gui.RefreshSeconds = s;
        _gui.Save();
    }

    private void LoadGuiPrefsUi()
    {
        ThemeCombo.SelectedIndex = string.Equals(_gui.Theme, "Light", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        ChkTray.IsChecked = _gui.TrayEnabled;
        ChkToasts.IsChecked = _gui.ToastsEnabled;
        ChkStatsProcesses.IsChecked = _gui.StatsRecordProcesses;
        StatsRetentionBox.Text = Math.Clamp(_gui.StatsRetentionDays, 1, 3650).ToString();
        ChkTopmost.IsChecked = _gui.Topmost;
        Topmost = _gui.Topmost;
        ChkEStats.IsChecked = _gui.EStats;
        ChkApplyOnSave.IsChecked = _gui.AutoApply;
        ChkPersistWfp.IsChecked = _gui.PersistWfp;
        ChkQuotaAutoBlock.IsChecked = _gui.QuotaAutoBlock;
        ChkStartup.IsChecked = StartupHelper.IsEnabled() || _gui.StartWithWindows;
        ChkStartMin.IsChecked = _gui.StartMinimized;
        ChkCompact.IsChecked = _gui.CompactMode;
        RefreshSlider.Value = Math.Clamp(_gui.RefreshSeconds, 0.5, 5);
        RefreshLabel.Text = $"{_gui.RefreshSeconds:0.0} s";
        AlertMbpsBox.Text = _gui.AlertBitsPerSec <= 0
            ? "0"
            : (_gui.AlertBitsPerSec / 1_000_000.0).ToString("0.##");
        ApplyCompactMode(_gui.CompactMode);
    }

    private void PersistGuiPrefs()
    {
        if (_loadingUi || !IsLoaded) return;
        _gui.Theme = ThemeCombo.SelectedIndex == 1 ? "Light" : "Dark";
        _gui.TrayEnabled = ChkTray.IsChecked == true;
        _gui.ToastsEnabled = ChkToasts.IsChecked == true;
        _gui.Topmost = ChkTopmost.IsChecked == true;
        _gui.EStats = ChkEStats.IsChecked != false;
        _gui.AutoApply = ChkApplyOnSave.IsChecked == true;
        _gui.PersistWfp = ChkPersistWfp.IsChecked == true;
        _gui.QuotaAutoBlock = ChkQuotaAutoBlock.IsChecked == true;
        _gui.StartWithWindows = ChkStartup.IsChecked == true;
        _gui.StartMinimized = ChkStartMin.IsChecked == true;
        _gui.CompactMode = ChkCompact.IsChecked == true;
        _gui.StatsRecordProcesses = ChkStatsProcesses.IsChecked != false;
        if (int.TryParse(StatsRetentionBox.Text, out var rd) && rd >= 1)
            _gui.StatsRetentionDays = rd;
        _stats.RetentionDays = _gui.StatsRetentionDays;
        _gui.RefreshSeconds = Math.Round(RefreshSlider.Value, 1);
        _gui.LastProfile = _activeProfile;
        if (double.TryParse(AlertMbpsBox.Text, out var mbd) && mbd >= 0)
            _gui.AlertBitsPerSec = (long)(mbd * 1_000_000);
        _gui.Save();
    }

    private void GuiPref_Changed(object sender, RoutedEventArgs e) => PersistGuiPrefs();

    private void Theme_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        var theme = ThemeCombo.SelectedIndex == 1 ? "Light" : "Dark";
        ThemeService.Apply(theme);
        _gui.Theme = theme;
        _gui.Save();
        DrawRateChart();
        DrawProcessSpark();
    }

    private void Startup_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        try
        {
            StartupHelper.SetEnabled(ChkStartup.IsChecked == true);
            _gui.StartWithWindows = ChkStartup.IsChecked == true;
            _gui.Save();
            LogInfo(ChkStartup.IsChecked == true ? "Start with Windows enabled" : "Start with Windows disabled");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Startup");
        }
    }

    private void Compact_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        ApplyCompactMode(ChkCompact.IsChecked == true);
        PersistGuiPrefs();
    }

    private void ApplyCompactMode(bool compact)
    {
        FontSize = compact ? 12 : 13;
    }

    private void AlertThreshold_Changed(object sender, RoutedEventArgs e) => PersistGuiPrefs();

    private void Lockdown_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        var on = (sender == ChkLockdown ? ChkLockdown.IsChecked : ChkLockdownSettings.IsChecked) == true;
        // keep both checkboxes in sync
        _loadingUi = true;
        ChkLockdown.IsChecked = on;
        ChkLockdownSettings.IsChecked = on;
        _loadingUi = false;
        _doc.LockdownEnabled = on;
        if (on) _doc.FirewallEnabled = true;
        SavePolicy(on ? "LOCKDOWN enabled — Apply WFP to enforce (Allow rules only)" : "Lockdown disabled",
            tryAuto: true);
    }

    private void SavePolicy(string? status = null, bool tryAuto = true)
    {
        if (!EnsureControl("change policy")) return;
        _profiles.SaveProfile(_activeProfile, _doc);
        ReloadAllGrids();
        UpdateDashboardMeta();
        if (status != null) LogInfo(status);
        if (tryAuto && ChkApplyOnSave.IsChecked == true)
            TryAutoApplyAll();
    }

    private bool EnsureControl(string action)
    {
        RefreshMyRights();
        if ((_myRights & AccessRight.Control) == AccessRight.Control)
            return true;
        MessageBox.Show(
            $"Access denied: '{action}' requires Control right.\n\n{AccessChecker.DescribeCurrent(_acl)}",
            "NetShaper ACL", MessageBoxButton.OK, MessageBoxImage.Warning);
        LogWarn($"Denied Control: {action}");
        return false;
    }

    private void RefreshMyRights()
    {
        _acl = _aclStore.Load();
        _myRights = AccessChecker.GetRights(_acl);
    }

    private void ReloadAclUi()
    {
        _loadingUi = true;
        _acl = _aclStore.Load();
        _myRights = AccessChecker.GetRights(_acl);
        ChkAclEnabled.IsChecked = _acl.Enabled;
        ChkAclAdmins.IsChecked = _acl.AdministratorsFullAccess;
        AclGrid.ItemsSource = _acl.Entries.ToList();
        AccessCurrentText.Text = AccessChecker.DescribeCurrent(_acl);
        _loadingUi = false;
    }

    private void ApplyRightsToUi()
    {
        RefreshMyRights();
        var canControl = (_myRights & AccessRight.Control) == AccessRight.Control;
        var canMonitor = (_myRights & AccessRight.Monitor) == AccessRight.Monitor || canControl;
        // Header actions
        foreach (var btn in FindLogicalChildren<System.Windows.Controls.Button>(this))
        {
            var c = btn.Content?.ToString() ?? "";
            if (c is "Apply all" or "WFP" or "QoS" or "Clear WFP" or "Clear QoS" or "Apply QoS now")
                btn.IsEnabled = canControl;
        }
        ChkLockdown.IsEnabled = canControl;
        ChkAskMode.IsEnabled = canControl;
        if (!canMonitor)
            LogWarn("Monitor right missing — limited view");
        AccessCurrentText.Text = AccessChecker.DescribeCurrent(_acl) + (canControl ? "" : "  [READ-ONLY UI]");
    }

    private static IEnumerable<T> FindLogicalChildren<T>(DependencyObject? parent) where T : DependencyObject
    {
        if (parent is null) yield break;
        foreach (var child in LogicalTreeHelper.GetChildren(parent))
        {
            if (child is T t) yield return t;
            if (child is DependencyObject d)
            {
                foreach (var c in FindLogicalChildren<T>(d))
                    yield return c;
            }
        }
    }

    private void AclEnabled_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        if (ChkAclEnabled.IsChecked == true)
        {
            if (!EnsureControl("enable ACL") && _acl.Enabled == false && _acl.Entries.Count > 0)
            {
                _loadingUi = true;
                ChkAclEnabled.IsChecked = false;
                _loadingUi = false;
                return;
            }
            // First enable: ensure self has All
            if (_acl.Entries.Count == 0 || !AccessChecker.Has(AccessRight.Control, _acl))
            {
                using var id = WindowsIdentity.GetCurrent();
                _acl.Entries.RemoveAll(x =>
                    x.Principal.Equals(id.Name, StringComparison.OrdinalIgnoreCase));
                _acl.Entries.Add(new AccessEntry
                {
                    Principal = id.Name ?? Environment.UserName,
                    Sid = id.User?.Value,
                    Allowed = AccessRight.All,
                    Note = "self on enable",
                });
            }
            _acl.Enabled = true;
        }
        else
        {
            if (!_acl.Enabled) return;
            if (!EnsureControl("disable ACL") && !AccessChecker.IsLocalAdmin(WindowsIdentity.GetCurrent()))
            {
                _loadingUi = true;
                ChkAclEnabled.IsChecked = true;
                _loadingUi = false;
                return;
            }
            _acl.Enabled = false;
        }
        _aclStore.Save(_acl);
        ReloadAclUi();
        ApplyRightsToUi();
        LogOk(_acl.Enabled ? "ACL enforcement ON" : "ACL enforcement OFF");
    }

    private void AclAdmins_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        if (!EnsureControl("edit ACL")) { ReloadAclUi(); return; }
        _acl.AdministratorsFullAccess = ChkAclAdmins.IsChecked != false;
        _aclStore.Save(_acl);
        ReloadAclUi();
        ApplyRightsToUi();
    }

    private void AclAdd_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("edit ACL")) return;
        var p = (AclPrincipalBox.Text ?? "").Trim();
        if (p.Length == 0)
        {
            MessageBox.Show("Enter principal (DOMAIN\\user).");
            return;
        }
        var rights = (AclRightsBox.SelectedItem as ComboBoxItem)?.Content?.ToString() switch
        {
            "Monitor" => AccessRight.Monitor,
            "Control" => AccessRight.Control,
            "RemoteApi" => AccessRight.RemoteApi,
            "Monitor,RemoteApi" => AccessRight.Monitor | AccessRight.RemoteApi,
            _ => AccessRight.All,
        };
        var sid = AccessChecker.TryResolveSid(p);
        _acl.Entries.RemoveAll(x =>
            x.Principal.Equals(p, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrEmpty(sid) && x.Sid == sid));
        _acl.Entries.Add(new AccessEntry { Principal = p, Sid = sid, Allowed = rights });
        _aclStore.Save(_acl);
        ReloadAclUi();
        ApplyRightsToUi();
        LogOk($"ACL entry {p} → {rights}");
    }

    private void AclRemove_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("edit ACL")) return;
        if (AclGrid.SelectedItem is not AccessEntry row)
        {
            MessageBox.Show("Select an entry.");
            return;
        }
        _acl.Entries.RemoveAll(x =>
            x.Principal.Equals(row.Principal, StringComparison.OrdinalIgnoreCase));
        _aclStore.Save(_acl);
        ReloadAclUi();
        ApplyRightsToUi();
        LogInfo("ACL entry removed");
    }

    private void TryAutoApplyAll()
    {
        if (!IsElevated())
        {
            LogWarn("Auto-apply skipped (not elevated)");
            return;
        }
        var r = _enforcer.ApplyAll(_doc, ChkPersistWfp.IsChecked == true);
        LogOk("Auto-apply: " + r.Summary);
        RefreshStatusPanels(quiet: true);
    }

    #region Profiles

    private void ReloadProfilesCombo()
    {
        _profileComboSilent = true;
        var names = _profiles.ListProfiles();
        ProfileCombo.ItemsSource = names;
        ProfileCombo.SelectedItem = names.FirstOrDefault(n =>
            n.Equals(_activeProfile, StringComparison.OrdinalIgnoreCase)) ?? names.FirstOrDefault();
        _profileComboSilent = false;
    }

    private void ProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_profileComboSilent || !IsLoaded) return;
        if (ProfileCombo.SelectedItem is not string name) return;
        if (name.Equals(_activeProfile, StringComparison.OrdinalIgnoreCase)) return;
        // save current first
        _profiles.SaveProfile(_activeProfile, _doc);
        _profiles.SetActive(name);
        _activeProfile = name;
        _doc = _profiles.LoadActive();
        PolicyPathRun.Text = _profiles.ProfilePath(_activeProfile);
        LoadSettingsUi();
        ReloadAllGrids();
        LogOk($"Switched profile → {name}");
    }

    private void ProfileNew_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new InputDialog("New profile", "Profile name:", "work") { Owner = this };
        if (dlg.ShowDialog() != true) return;
        try
        {
            _profiles.CreateProfile(dlg.Value, cloneActive: false);
            _profiles.SetActive(dlg.Value);
            _activeProfile = dlg.Value;
            _doc = _profiles.LoadActive();
            ReloadProfilesCombo();
            LoadSettingsUi();
            ReloadAllGrids();
            LogOk("Created profile " + dlg.Value);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "NetShaper"); }
    }

    private void ProfileClone_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new InputDialog("Clone profile", "Name for clone of current:", _activeProfile + "-copy") { Owner = this };
        if (dlg.ShowDialog() != true) return;
        try
        {
            _profiles.SaveProfile(_activeProfile, _doc);
            _profiles.CreateProfile(dlg.Value, cloneActive: true);
            ReloadProfilesCombo();
            LogOk("Cloned profile → " + dlg.Value);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "NetShaper"); }
    }

    private void ProfileDelete_Click(object sender, RoutedEventArgs e)
    {
        if (_activeProfile.Equals("default", StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show("Cannot delete the default profile.", "NetShaper");
            return;
        }
        if (MessageBox.Show($"Delete profile '{_activeProfile}'?", "NetShaper",
                MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
        try
        {
            _profiles.DeleteProfile(_activeProfile);
            _activeProfile = _profiles.GetActiveName();
            _doc = _profiles.LoadActive();
            ReloadProfilesCombo();
            LoadSettingsUi();
            ReloadAllGrids();
            LogWarn("Deleted profile");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "NetShaper"); }
    }

    #endregion

    #region Templates / Dashboard

    private void LoadTemplates()
    {
        TemplatesList.ItemsSource = RuleTemplates.All.ToList();
        if (TemplatesList.Items.Count > 0)
            TemplatesList.SelectedIndex = 0;
    }

    private void ApplyTemplate_Click(object sender, RoutedEventArgs e)
    {
        if (TemplatesList.SelectedItem is not RuleTemplates.Template t)
        {
            MessageBox.Show("Select a template.", "NetShaper");
            return;
        }
        if (MessageBox.Show($"Apply template:\n\n{t.Name}\n{t.Description}", "NetShaper",
                MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
        t.Apply(_doc);
        SavePolicy($"Template applied: {t.Name}");
        LogOk("Template: " + t.Name, t.Description);
    }

    private void UpdateDashboardMeta()
    {
        var active = _doc.Rules.Count(r => r.IsActiveNow());
        DashRules.Text = $"{active} / {_doc.Rules.Count}";
    }

    private void DrawRateChart()
    {
        RateCanvas.Children.Clear();
        var samples = _rateHistory.Samples;
        if (samples.Count < 2) return;
        double w = RateCanvas.ActualWidth;
        double h = RateCanvas.ActualHeight;
        if (w < 10 || h < 10) return;

        var (maxIn, maxOut) = _rateHistory.MaxBits();
        double max = Math.Max(maxIn, maxOut);
        if (max < 1) max = 1;

        Point CollectionToPoint(int i, long bits)
        {
            double x = i * (w - 4) / (samples.Count - 1) + 2;
            double y = h - 4 - (bits / max) * (h - 12);
            return new Point(x, Math.Clamp(y, 2, h - 2));
        }

        void AddLine(Func<RateHistory.Sample, long> sel, SolidColorBrush stroke)
        {
            var poly = new Polyline
            {
                Stroke = stroke,
                StrokeThickness = 1.8,
                StrokeLineJoin = PenLineJoin.Round,
            };
            for (int i = 0; i < samples.Count; i++)
                poly.Points.Add(CollectionToPoint(i, sel(samples[i])));
            RateCanvas.Children.Add(poly);
        }

        AddLine(s => s.BitsIn, ChartInBrush);
        AddLine(s => s.BitsOut, ChartOutBrush);
    }

    private void RateCanvas_SizeChanged(object sender, SizeChangedEventArgs e) => DrawRateChart();

    #endregion

    /// <summary>Called from sampler worker thread — prep off UI, paint on dispatcher.</summary>
    private void OnEngineSnapshot(TrafficSnapshot snap)
    {
        // Drop frame if previous UI apply still running (keeps clicks snappy)
        if (Interlocked.CompareExchange(ref _sampleBusy, 1, 0) != 0)
            return;

        try
        {
            var statsOn = _doc.StatsEnabled;
            var statsProc = _gui.StatsRecordProcesses;
            var dnsOn = _doc.DnsEnabled;

            // SQLite write + DNS resolve stay on worker
            if (statsOn)
            {
                try { _stats.Record(snap, includeProcesses: statsProc); }
                catch { /* background */ }
            }

            // Only resolve hostnames for visible connection window (top 80 by rate)
            if (dnsOn)
            {
                foreach (var c in snap.Connections.Take(80))
                {
                    _dns.ObserveRemoteEndPoint(c.RemoteEndPoint);
                    c.RemoteHost = _dns.ResolveHostHint(c.RemoteEndPoint);
                }
            }

            var pinned = _gui.PinnedProcessNames.ToList();
            var dt = Math.Max(0.5, _sampleEngine.IntervalSeconds);

            // Capture filter on UI thread inside invoke; pre-filter without filter first
            var processesAll = snap.Processes;

            Dispatcher.BeginInvoke(() =>
            {
                try
                {
                    var filter = "";
                    try { filter = (ProcessFilter.Text ?? "").Trim(); } catch { /* */ }
                    var processes = FilterProcesses(processesAll, filter, pinned);
                    ApplySnapshotUi(snap, processes, dt);
                }
                finally
                {
                    Interlocked.Exchange(ref _sampleBusy, 0);
                }
            }, DispatcherPriority.Background);
        }
        catch
        {
            Interlocked.Exchange(ref _sampleBusy, 0);
        }
    }

    private static List<ProcessTraffic> FilterProcesses(
        IReadOnlyList<ProcessTraffic> src, string filter, List<string> pinned)
    {
        IEnumerable<ProcessTraffic> q = src;
        if (!string.IsNullOrEmpty(filter))
        {
            q = q.Where(p =>
                p.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                p.DisplayName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                (p.ServiceNames?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.ExecutablePath?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false));
        }
        var list = q.ToList();
        if (pinned.Count > 0)
        {
            list = list
                .OrderByDescending(p => pinned.Any(n =>
                    p.ProcessName.Contains(n, StringComparison.OrdinalIgnoreCase) ||
                    (p.ServiceNames?.Contains(n, StringComparison.OrdinalIgnoreCase) ?? false)))
                .ThenByDescending(p => p.BitsPerSecIn + p.BitsPerSecOut)
                .ToList();
        }
        return list;
    }

    private Task RequestSampleAsync(bool force)
    {
        if (force) _sampleEngine.Kick();
        return Task.CompletedTask;
    }

    private void ApplySnapshotUi(TrafficSnapshot snap, List<ProcessTraffic> processes, double dt)
    {
        try
        {
            _lastSnap = snap;
            _rateHistory.Add(snap.TotalBitsPerSecIn, snap.TotalBitsPerSecOut);
            _procHistory.Record(snap.Processes);

            _sessionBytesIn += snap.TotalBitsPerSecIn * dt / 8.0;
            _sessionBytesOut += snap.TotalBitsPerSecOut * dt / 8.0;

            // Preserve selection by PID across rebinds
            var prevPid = _selectedPid;
            if (ProcessGrid.SelectedItem is ProcessTraffic sel)
                prevPid = sel.ProcessId;

            _lastProcesses = processes;
            _allConnections = snap.Connections as List<ConnectionInfo> ?? snap.Connections.ToList();

            var now = DateTime.UtcNow;
            var tab = ActiveTabIndex;
            // Throttle heavy grid rebinds (DataGrid rebuild is expensive and freezes clicks)
            var rebindGrids = (now - _lastGridBindUtc).TotalSeconds >= 1.2 || _lastGridBindUtc == DateTime.MinValue;

            if (rebindGrids)
            {
                _lastGridBindUtc = now;
                // Do NOT null ItemsSource first — that doubles visual tree thrash
                if (tab is 0 or 1) // Dashboard or Live
                {
                    ProcessGrid.ItemsSource = _lastProcesses;
                    if (tab == 0)
                    {
                        TopTalkersGrid.ItemsSource = _lastProcesses
                            .OrderByDescending(p => p.BitsPerSecIn + p.BitsPerSecOut)
                            .ThenByDescending(p => p.DataBytesIn + p.DataBytesOut)
                            .Take(15)
                            .ToList();
                    }
                }
                if (tab == 1) // Live connections only when visible
                {
                    FilterConnectionsBySelection();
                    if (prevPid > 0)
                    {
                        var match = _lastProcesses.FirstOrDefault(p => p.ProcessId == prevPid);
                        if (match is not null)
                            ProcessGrid.SelectedItem = match;
                    }
                    DrawProcessSpark();
                }
            }

            // Lightweight dashboard numbers — every sample, no grid rebuild
            var mbIn = snap.TotalBitsPerSecIn / 1_000_000.0;
            var mbOut = snap.TotalBitsPerSecOut / 1_000_000.0;
            var elev = snap.IsElevated ? "Admin" : "not admin";
            var mode = string.IsNullOrEmpty(snap.RateMode)
                ? (snap.EStatsWorking ? "EStats" : "NIC-share")
                : snap.RateMode;
            StatusTotals.Text =
                $"↓ {mbIn:0.00} Mb/s  ↑ {mbOut:0.00} Mb/s  ·  {snap.Processes.Count} apps · {snap.Connections.Count} conns  ·  {elev} · {mode}"
                + (_doc.LockdownEnabled ? "  ·  LOCKDOWN" : "");
            DashDown.Text = ProcessTraffic.FormatRate(snap.TotalBitsPerSecIn);
            DashUp.Text = ProcessTraffic.FormatRate(snap.TotalBitsPerSecOut);
            DashApps.Text = $"{snap.Processes.Count} / {snap.Connections.Count}";
            DashSessIn.Text = FormatBytes((long)_sessionBytesIn);
            DashSessOut.Text = FormatBytes((long)_sessionBytesOut);
            UpdateDashboardMeta();

            // Chart / title / session summary throttled
            if (tab == 0 && (now - _lastChartUtc).TotalSeconds >= 1.0)
            {
                _lastChartUtc = now;
                DrawRateChart();
            }
            if ((now - _lastTitleUtc).TotalSeconds >= 2.0)
            {
                _lastTitleUtc = now;
                Title = $"NetShaper — ↓{ProcessTraffic.FormatRate(snap.TotalBitsPerSecIn)} ↑{ProcessTraffic.FormatRate(snap.TotalBitsPerSecOut)}";
                UpdateSessionSummary();
            }

            MaybeRateAlert(snap.TotalBitsPerSecIn + snap.TotalBitsPerSecOut);
        }
        catch (Exception ex)
        {
            LogWarn("UI update: " + ex.Message);
        }
    }

    /// <summary>Legacy sync entry used by a few buttons — kicks engine.</summary>
    private void SampleTraffic() => _sampleEngine.Kick();

    private void MaybeRateAlert(long totalBits)
    {
        if (_gui.AlertBitsPerSec <= 0) return;
        if (totalBits < _gui.AlertBitsPerSec) return;
        if ((DateTime.UtcNow - _lastAlertUtc).TotalSeconds < 30) return;
        _lastAlertUtc = DateTime.UtcNow;
        LogWarn($"Rate alert: {ProcessTraffic.FormatRate(totalBits)} exceeds threshold");
    }

    private void DrawProcessSpark()
    {
        ProcessSparkCanvas.Children.Clear();
        if (ProcessGrid.SelectedItem is not ProcessTraffic pt) return;
        var samples = _procHistory.Get(pt.ProcessId);
        if (samples.Count < 2) return;
        double w = ProcessSparkCanvas.ActualWidth;
        double h = ProcessSparkCanvas.ActualHeight;
        if (w < 8 || h < 8)
        {
            w = 160; h = 40;
        }
        double max = samples.Max(s => Math.Max(s.inn, s.outt));
        if (max < 1) max = 1;

        void Add(Func<(double inn, double outt), double> sel, SolidColorBrush stroke)
        {
            var poly = new Polyline
            {
                Stroke = stroke,
                StrokeThickness = 1.4,
            };
            for (int i = 0; i < samples.Count; i++)
            {
                double x = i * (w - 2) / (samples.Count - 1);
                double y = h - 2 - (sel(samples[i]) / max) * (h - 4);
                poly.Points.Add(new Point(x, Math.Clamp(y, 1, h - 1)));
            }
            ProcessSparkCanvas.Children.Add(poly);
        }
        Add(s => s.inn, ChartInBrush);
        Add(s => s.outt, ChartOutBrush);
    }

    private void UpdateSessionSummary()
    {
        var uptime = DateTime.UtcNow - _sessionStart;
        SessionSummaryText.Text =
            $"Started: {_sessionStart.ToLocalTime():HH:mm:ss}  uptime {uptime:hh\\:mm\\:ss}\n" +
            $"Session download ≈ {FormatBytes((long)_sessionBytesIn)}\n" +
            $"Session upload   ≈ {FormatBytes((long)_sessionBytesOut)}\n" +
            $"Profile: {_activeProfile}  lockdown={_doc.LockdownEnabled}  rules={_doc.Rules.Count}";
    }

    private void FilterConnectionsBySelection()
    {
        IEnumerable<ConnectionInfo> src = ProcessGrid.SelectedItem is ProcessTraffic pt
            ? _allConnections.Where(c => c.ProcessId == pt.ProcessId)
            : _allConnections;

        var cf = (ConnFilter?.Text ?? "").Trim();
        if (cf.Length > 0)
        {
            src = src.Where(c =>
                c.ProcessName.Contains(cf, StringComparison.OrdinalIgnoreCase) ||
                c.LocalEndPoint.Contains(cf, StringComparison.OrdinalIgnoreCase) ||
                c.RemoteEndPoint.Contains(cf, StringComparison.OrdinalIgnoreCase) ||
                c.State.Contains(cf, StringComparison.OrdinalIgnoreCase));
        }

        if (ConnProtoFilter?.SelectedIndex > 0 && ConnProtoFilter.SelectedItem is ComboBoxItem cbi)
        {
            var proto = cbi.Content?.ToString() ?? "";
            src = src.Where(c => c.Protocol.Equals(proto, StringComparison.OrdinalIgnoreCase));
        }

        if (ChkEstablishedOnly?.IsChecked == true)
            src = src.Where(c => c.State is "Established");

        _visibleConnections = src.Take(400).ToList();
        ConnectionGrid.ItemsSource = _visibleConnections;

        if (ProcessGrid.SelectedItem is ProcessTraffic p2)
            SelectedProcessLabel.Text =
                $"{p2.DisplayName} (PID {p2.ProcessId})  ↓{p2.RateInDisplay} ↑{p2.RateOutDisplay}  " +
                $"data ↓{p2.DataInDisplay} ↑{p2.DataOutDisplay}  conns={p2.ConnectionCount}";
        else
            SelectedProcessLabel.Text = "Select a process to filter connections";
    }

    private void ProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is ProcessTraffic pt)
            _selectedPid = pt.ProcessId;
        FilterConnectionsBySelection();
        DrawProcessSpark();
    }

    private void PinProcess_Click(object sender, RoutedEventArgs e)
    {
        var pt = RequireProcess();
        if (pt is null) return;
        var name = pt.ProcessName;
        if (!_gui.PinnedProcessNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            _gui.PinnedProcessNames.Add(name);
            _gui.Save();
            ReloadPinnedList();
            LogOk("Pinned " + name);
        }
    }

    private void ReloadPinnedList()
    {
        PinnedList.ItemsSource = _gui.PinnedProcessNames.ToList();
    }

    private void UnpinSelected_Click(object sender, RoutedEventArgs e)
    {
        if (PinnedList.SelectedItem is not string name) return;
        _gui.PinnedProcessNames.RemoveAll(n => n.Equals(name, StringComparison.OrdinalIgnoreCase));
        _gui.Save();
        ReloadPinnedList();
    }

    private void PinnedFilter_Click(object sender, RoutedEventArgs e)
    {
        if (PinnedList.SelectedItem is string name)
            ProcessFilter.Text = name;
        else if (_gui.PinnedProcessNames.Count > 0)
            ProcessFilter.Text = _gui.PinnedProcessNames[0];
        Tabs.SelectedIndex = 1; // Live
    }

    private void CrossSearch_Click(object sender, RoutedEventArgs e)
    {
        var hits = ProfileSearch.Search(_profiles, CrossSearchBox.Text ?? "");
        CrossSearchGrid.ItemsSource = hits.ToList();
        LogInfo($"Cross-profile search: {hits.Count} hit(s)");
    }

    private void QuickFirewallOn_Click(object sender, RoutedEventArgs e)
    {
        _doc.FirewallEnabled = true;
        LoadSettingsUi();
        SavePolicy("Firewall enabled");
        if (IsElevated()) ApplyWfp_Click(sender, e);
    }

    private void QuickLockdownOff_Click(object sender, RoutedEventArgs e)
    {
        _doc.LockdownEnabled = false;
        LoadSettingsUi();
        SavePolicy("Lockdown off");
    }

    private void ClearAllRules_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Remove ALL rules (keep zone filters)?", "NetShaper",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _doc.Rules.Clear();
        _doc.Filters.RemoveAll(f => !f.IsZone && f.Name != "Any");
        // re-add Any if missing
        if (_doc.Filters.All(f => f.Name != "Any"))
            _doc.Filters.Insert(0, new Filter { Name = "Any" });
        SavePolicy("All rules cleared");
    }

    private void CopySessionSummary_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(SessionSummaryText.Text ?? "");
            SetStatus("Session summary copied.");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }
    private void ProcessFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        // Debounce filter so typing doesn't thrash full samples
        _filterDebounce ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(350) };
        _filterDebounce.Stop();
        _filterDebounce.Tick -= FilterDebounce_Tick;
        _filterDebounce.Tick += FilterDebounce_Tick;
        _filterDebounce.Start();
    }

    private void FilterDebounce_Tick(object? sender, EventArgs e)
    {
        _filterDebounce?.Stop();
        if (_lastSnap is { } snap)
        {
            var filter = (ProcessFilter.Text ?? "").Trim();
            var processes = snap.Processes
                .Where(p => string.IsNullOrEmpty(filter) ||
                            p.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                            p.DisplayName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                            (p.ServiceNames?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false) ||
                            (p.ExecutablePath?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false))
                .ToList();
            _lastProcesses = processes;
            ProcessGrid.ItemsSource = processes;
            FilterConnectionsBySelection();
        }
        else
            _ = RequestSampleAsync(force: true);
    }
    private void ConnFilter_TextChanged(object sender, TextChangedEventArgs e) => FilterConnectionsBySelection();
    private void ConnFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (IsLoaded) FilterConnectionsBySelection();
    }

    private void EStats_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        _sampler.PreferEStats = ChkEStats.IsChecked != false;
        PersistGuiPrefs();
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        _doc = _profiles.LoadActive();
        LoadSettingsUi();
        ReloadAllGrids();
        SampleTraffic();
        RefreshServiceStatus();
        RefreshStatusPanels(quiet: true);
        AdminHint.IsChecked = IsElevated();
        LogInfo("Refreshed");
    }

    private void LoadSettingsUi()
    {
        var prev = _loadingUi;
        _loadingUi = true;
        ChkFirewall.IsChecked = _doc.FirewallEnabled;
        ChkLimiter.IsChecked = _doc.LimiterEnabled;
        ChkPriority.IsChecked = _doc.PriorityEnabled;
        ChkQuota.IsChecked = _doc.QuotaEnabled;
        ChkSchedule.IsChecked = _doc.ScheduleEnabled;
        ChkStats.IsChecked = _doc.StatsEnabled;
        ChkLockdown.IsChecked = _doc.LockdownEnabled;
        ChkLockdownSettings.IsChecked = _doc.LockdownEnabled;
        ChkAskMode.IsChecked = _doc.AskModeEnabled;
        ChkAskModeSettings.IsChecked = _doc.AskModeEnabled;
        ChkAskIgnoreSystem.IsChecked = _doc.AskIgnoreSystemProcesses;
        ChkAskListeners.IsChecked = _doc.AskIncludeListeners;
        ChkDns.IsChecked = _doc.DnsEnabled;
        ShaperModeCombo.SelectedIndex = _doc.ShaperMode switch
        {
            BandwidthShaperMode.Off => 0,
            BandwidthShaperMode.Qos => 1,
            BandwidthShaperMode.Aggressive => 3,
            BandwidthShaperMode.Packet => 4,
            _ => 2,
        };
        _loadingUi = prev;
    }

    private void Settings_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        _doc.FirewallEnabled = ChkFirewall.IsChecked == true;
        _doc.LimiterEnabled = ChkLimiter.IsChecked == true;
        _doc.PriorityEnabled = ChkPriority.IsChecked == true;
        _doc.QuotaEnabled = ChkQuota.IsChecked == true;
        _doc.ScheduleEnabled = ChkSchedule.IsChecked == true;
        _doc.StatsEnabled = ChkStats.IsChecked == true;
        SavePolicy("Settings saved", tryAuto: false);
    }

    private void ReloadAllGrids()
    {
        ReloadRulesGrid();
        ReloadLimitsGrid();
        ReloadQuotasGrid();
        ReloadFiltersGrid();
        UpdateDashboardMeta();
    }

    private void ReloadRulesGrid()
    {
        var q = (RulesFilter?.Text ?? "").Trim();
        var kind = (RulesKindFilter?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All kinds";
        var rows = new List<RuleRow>();
        foreach (var r in _doc.Rules.OrderByDescending(r => r.UpdatedUtc))
        {
            if (kind != "All kinds" && !r.Kind.ToString().Equals(kind, StringComparison.OrdinalIgnoreCase))
                continue;
            var f = _doc.Filters.FirstOrDefault(x => x.Id == r.FilterId);
            var filterName = f?.Name ?? "?";
            var matchers = f is null ? "" : string.Join("; ", f.Matchers.Select(DescribeMatcher));
            if (q.Length > 0 &&
                !filterName.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !r.Kind.ToString().Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !matchers.Contains(q, StringComparison.OrdinalIgnoreCase))
                continue;

            rows.Add(new RuleRow
            {
                RuleId = r.Id,
                Kind = r.Kind.ToString(),
                FilterName = filterName,
                Direction = r.Direction.ToString(),
                Detail = FormatRuleDetail(r),
                Enabled = r.Enabled,
                ScheduleDisplay = FormatSchedule(r),
                ActiveNow = r.IsActiveNow(),
                Matchers = matchers,
            });
        }
        RulesGrid.ItemsSource = rows;
    }

    private void RulesFilter_TextChanged(object sender, RoutedEventArgs e)
    {
        if (IsLoaded) ReloadRulesGrid();
    }

    private static string FormatSchedule(Rule r)
    {
        if (r.Schedule is not { Enabled: true } s) return "—";
        return $"{s.StartLocal ?? "00:00"}–{s.EndLocal ?? "24:00"}";
    }

    private static string FormatRuleDetail(Rule r) => r.Kind switch
    {
        RuleKind.Limit when r.LimitBytesPerSec is long bps =>
            $"{PolicyEditor.BytesPerSecToKbps(bps)} kbps",
        RuleKind.Priority => r.Priority?.ToString() ?? "—",
        RuleKind.Quota when r.QuotaBytes is long q => $"{q / (1024.0 * 1024.0):0.#} MB",
        _ => "—",
    };

    private static string DescribeMatcher(Matcher m) => m.Kind switch
    {
        MatcherKind.AppPathEquals => $"path=={m.StringValue}",
        MatcherKind.AppPathContains => $"path*={m.StringValue}",
        MatcherKind.ProcessIdEquals => $"pid={m.UIntValue}",
        MatcherKind.RemotePortInRange => $"rport={m.PortFrom}-{m.PortTo}",
        MatcherKind.LocalPortInRange => $"lport={m.PortFrom}-{m.PortTo}",
        MatcherKind.DomainEquals => $"domain={m.StringValue}",
        MatcherKind.RemoteAddressInRange => $"rcidr={m.Cidr ?? m.StringValue}",
        MatcherKind.IsInternet => "zone:internet",
        MatcherKind.IsLocalNetwork => "zone:local",
        _ => $"{m.Kind}:{m.StringValue ?? m.UIntValue?.ToString() ?? ""}",
    };

    private void ReloadLimitsGrid()
    {
        var limits = _limitEnforcer.GetActiveLimits(_doc);
        LimitsGrid.ItemsSource = limits.Select(l => new LimitRow
        {
            FilterName = l.FilterName,
            Kbps = PolicyEditor.BytesPerSecToKbps(l.BytesPerSec),
            LimitDisplay = $"{PolicyEditor.BytesPerSecToKbps(l.BytesPerSec)} kbps",
            MeasuredDisplay = "—",
            OverLimit = false,
            Action = l.ScheduleActive ? "idle" : "sched-off",
            ProcessSummary = "",
            MatchedProcesses = 0,
            Direction = l.Direction.ToString(),
            ScheduleActive = l.ScheduleActive,
            Matchers = string.Join("; ", l.MatcherSummary),
        }).ToList();
        LimitsGapText.Text = _limitEnforcer.ExplainGap(_doc);
        ShaperStatusText.Text = $"Bandwidth shaper · {_doc.ShaperMode}";
    }

    private void ReloadQuotasGrid()
    {
        QuotasGrid.ItemsSource = _enforcer.Quota.GetStatuses(_doc).Select(s => new QuotaRow
        {
            RuleId = s.RuleId,
            FilterName = s.FilterName,
            UsedDisplay = FormatBytes(s.UsedBytes),
            CeilingDisplay = FormatBytes(s.CeilingBytes),
            PercentDisplay = $"{s.Percent:0.0}%",
            Exceeded = s.Exceeded,
            ActiveNow = s.ActiveNow,
        }).ToList();
    }

    private static string FormatBytes(long b)
    {
        double v = b;
        string[] u = ["B", "KB", "MB", "GB"];
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.##} {u[i]}";
    }

    private void ReloadFiltersGrid()
    {
        FiltersGrid.ItemsSource = _doc.Filters.Select(f => new FilterRow
        {
            Name = f.Name,
            IsZone = f.IsZone,
            Weight = f.Weight,
            Matchers = string.Join("; ", f.Matchers.Select(DescribeMatcher)),
            IdShort = f.Id.ToString("N")[..8],
        }).ToList();
    }

    private void RefreshActivityGrid()
    {
        ActivityGrid.ItemsSource = _log.Snapshot().Select(e => new ActivityRow
        {
            TimeDisplay = e.Time.ToString("HH:mm:ss"),
            Level = e.Level.ToString(),
            Message = e.Message,
            Detail = e.Detail ?? "",
        }).ToList();
    }

    private void CopyActivity_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_log.ExportText());
            SetStatus("Activity log copied.");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void ClearActivity_Click(object sender, RoutedEventArgs e)
    {
        _log.ClearMemory();
        RefreshActivityGrid();
    }

    private void ReloadPolicy_Click(object sender, RoutedEventArgs e)
    {
        _doc = _profiles.LoadActive();
        LoadSettingsUi();
        ReloadAllGrids();
        LogInfo("Policy reloaded");
    }

    private void ResetQuotaSelected_Click(object sender, RoutedEventArgs e)
    {
        if (QuotasGrid.SelectedItem is not QuotaRow row)
        {
            MessageBox.Show("Select a quota row.");
            return;
        }
        _enforcer.Quota.Reset(row.RuleId);
        _toastedQuotas.Remove(row.RuleId);
        ReloadQuotasGrid();
        LogInfo("Quota usage reset");
    }

    private void ResetQuotaAll_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Reset all quota counters?", "NetShaper", MessageBoxButton.YesNo) != MessageBoxResult.Yes)
            return;
        _enforcer.Quota.ResetAll();
        _toastedQuotas.Clear();
        ReloadQuotasGrid();
        LogInfo("All quotas reset");
    }

    private TrafficDirection SelectedDir() => QuickDir.SelectedIndex switch
    {
        0 => TrafficDirection.In,
        1 => TrafficDirection.Out,
        _ => TrafficDirection.Both,
    };

    private string? RequireQuickPath()
    {
        var path = (QuickPath.Text ?? "").Trim();
        if (path.Length == 0)
        {
            MessageBox.Show("Enter a path or path substring.");
            return null;
        }
        return path;
    }

    private void QuickBlock_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireQuickPath();
        if (path is null) return;
        PolicyEditor.AddBlock(_doc, path, SelectedDir());
        SavePolicy($"Block: {path}");
    }

    private void QuickAllow_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireQuickPath();
        if (path is null) return;
        PolicyEditor.AddAllow(_doc, path, SelectedDir());
        SavePolicy($"Allow: {path}");
    }

    private void QuickLimit_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireQuickPath();
        if (path is null) return;
        if (!long.TryParse(QuickKbps.Text, out var kbps) || kbps <= 0)
        {
            MessageBox.Show("Enter positive kbps.");
            return;
        }
        PolicyEditor.AddLimit(_doc, path, kbps, SelectedDir());
        SavePolicy($"Limit {kbps} kbps: {path}");
    }

    private void QuickPriority_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireQuickPath();
        if (path is null) return;
        PolicyEditor.AddPriority(_doc, path, PriorityBand.High, SelectedDir());
        SavePolicy($"Priority High: {path}");
    }

    private void QuickQuota_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireQuickPath();
        if (path is null) return;
        if (!long.TryParse(QuickQuotaMb.Text, out var mb) || mb <= 0)
        {
            MessageBox.Show("Enter positive quota MB.");
            return;
        }
        PolicyEditor.AddQuota(_doc, path, mb * 1024 * 1024, SelectedDir());
        SavePolicy($"Quota {mb} MB: {path}");
    }

    private void QuickIgnoreLimits_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireQuickPath();
        if (path is null) return;
        PolicyEditor.AddIgnoreLimits(_doc, path, SelectedDir());
        SavePolicy($"Ignore limits: {path}");
    }

    private string ProcessKey(ProcessTraffic pt) =>
        !string.IsNullOrWhiteSpace(pt.ExecutablePath) ? pt.ExecutablePath! : pt.ProcessName;

    private string ProcessPathContains(ProcessTraffic pt) =>
        Path.GetFileNameWithoutExtension(
            !string.IsNullOrWhiteSpace(pt.ExecutablePath) ? pt.ExecutablePath! : pt.ProcessName);

    private ProcessTraffic? RequireProcess()
    {
        if (ProcessGrid.SelectedItem is ProcessTraffic pt) return pt;
        MessageBox.Show("Select a process first.");
        return null;
    }

    private void BlockSelected_Click(object sender, RoutedEventArgs e)
    {
        var pt = RequireProcess();
        if (pt is null) return;
        PolicyEditor.AddBlock(_doc, ProcessKey(pt), TrafficDirection.Both);
        SavePolicy($"Block {pt.ProcessName}");
    }

    private void AllowSelected_Click(object sender, RoutedEventArgs e)
    {
        var pt = RequireProcess();
        if (pt is null) return;
        PolicyEditor.AddAllow(_doc, ProcessKey(pt), TrafficDirection.Both);
        SavePolicy($"Allow {pt.ProcessName}");
    }

    private void LimitSelected_Click(object sender, RoutedEventArgs e)
    {
        var pt = RequireProcess();
        if (pt is null) return;
        var dlg = new LimitDialog(pt.ProcessName) { Owner = this };
        if (dlg.ShowDialog() != true) return;
        PolicyEditor.AddLimit(_doc, ProcessPathContains(pt), dlg.Kbps, TrafficDirection.Both);
        SavePolicy($"Limit {dlg.Kbps} kbps {pt.ProcessName}");
    }

    private void PrioritySelected_Click(object sender, RoutedEventArgs e)
    {
        var pt = RequireProcess();
        if (pt is null) return;
        PolicyEditor.AddPriority(_doc, ProcessPathContains(pt), PriorityBand.High, TrafficDirection.Both);
        SavePolicy($"Priority High {pt.ProcessName}");
    }

    private void QuotaSelected_Click(object sender, RoutedEventArgs e)
    {
        var pt = RequireProcess();
        if (pt is null) return;
        var dlg = new InputDialog("Quota", "Quota size in MB:", "1024") { Owner = this };
        if (dlg.ShowDialog() != true) return;
        if (!long.TryParse(dlg.Value, out var mb) || mb <= 0)
        {
            MessageBox.Show("Invalid MB.");
            return;
        }
        PolicyEditor.AddQuota(_doc, ProcessPathContains(pt), mb * 1024 * 1024, TrafficDirection.Both);
        SavePolicy($"Quota {mb} MB {pt.ProcessName}");
    }

    private void KillConnection_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("kill connection")) return;
        if (ConnectionGrid.SelectedItem is not ConnectionInfo c)
        {
            MessageBox.Show("Select a connection.");
            return;
        }
        if (!ConnectionKiller.TryKill(c, out var err))
        {
            MessageBox.Show(err, "Kill connection");
            return;
        }
        LogOk($"Killed {c.LocalEndPoint} → {c.RemoteEndPoint}");
        SampleTraffic();
    }

    private void KillProcessConns_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("kill process connections")) return;
        var pt = RequireProcess();
        if (pt is null) return;
        var n = ConnectionKiller.KillMatching(_allConnections, c => c.ProcessId == pt.ProcessId && c.IsIpv4Tcp);
        LogOk($"Killed {n} connection(s) for {pt.ProcessName}");
        SampleTraffic();
    }

    private RuleRow? SelectedRuleRow()
    {
        if (RulesGrid.SelectedItem is RuleRow row) return row;
        MessageBox.Show("Select a rule.");
        return null;
    }

    private void RemoveRule_Click(object sender, RoutedEventArgs e)
    {
        var row = SelectedRuleRow();
        if (row is null) return;
        PolicyEditor.RemoveRuleById(_doc, row.RuleId);
        SavePolicy("Rule removed");
    }

    private void DuplicateRule_Click(object sender, RoutedEventArgs e)
    {
        var row = SelectedRuleRow();
        if (row is null) return;
        var rule = _doc.Rules.FirstOrDefault(r => r.Id == row.RuleId);
        var filter = rule is null ? null : _doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
        if (rule is null || filter is null)
        {
            MessageBox.Show("Could not duplicate.");
            return;
        }
        var nf = new Filter
        {
            Name = filter.Name + " (copy)",
            Weight = filter.Weight,
            Matchers = filter.Matchers.Select(m => new Matcher
            {
                Kind = m.Kind,
                Match = m.Match,
                StringValue = m.StringValue,
                UIntValue = m.UIntValue,
                PortFrom = m.PortFrom,
                PortTo = m.PortTo,
                Cidr = m.Cidr,
            }).ToList(),
        };
        var nr = new Rule
        {
            FilterId = nf.Id,
            Kind = rule.Kind,
            Direction = rule.Direction,
            Enabled = rule.Enabled,
            Weight = rule.Weight,
            LimitBytesPerSec = rule.LimitBytesPerSec,
            Priority = rule.Priority,
            QuotaBytes = rule.QuotaBytes,
            Schedule = rule.Schedule is null ? null : new RuleSchedule
            {
                Enabled = rule.Schedule.Enabled,
                StartLocal = rule.Schedule.StartLocal,
                EndLocal = rule.Schedule.EndLocal,
                DaysOfWeek = rule.Schedule.DaysOfWeek?.ToList(),
            },
            Notes = rule.Notes,
        };
        _doc.Filters.Add(nf);
        _doc.Rules.Add(nr);
        SavePolicy("Rule duplicated");
    }

    private void EnableRule_Click(object sender, RoutedEventArgs e)
    {
        var row = SelectedRuleRow();
        if (row is null) return;
        PolicyEditor.SetRuleEnabled(_doc, row.RuleId, true);
        SavePolicy("Enabled " + row.FilterName);
    }

    private void DisableRule_Click(object sender, RoutedEventArgs e)
    {
        var row = SelectedRuleRow();
        if (row is null) return;
        PolicyEditor.SetRuleEnabled(_doc, row.RuleId, false);
        SavePolicy("Disabled " + row.FilterName);
    }

    private void EditRule_Click(object sender, RoutedEventArgs e) => EditSelectedRule();
    private void RulesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => EditSelectedRule();

    private void EditSelectedRule()
    {
        if (RulesGrid.SelectedItem is not RuleRow row) return;
        var rule = _doc.Rules.FirstOrDefault(r => r.Id == row.RuleId);
        if (rule is null) return;
        var dlg = new EditRuleDialog(rule, row.FilterName) { Owner = this };
        if (dlg.ShowDialog() != true) return;
        PolicyEditor.UpdateDirection(_doc, rule.Id, dlg.Direction);
        PolicyEditor.SetRuleEnabled(_doc, rule.Id, dlg.Enabled);
        PolicyEditor.SetSchedule(_doc, rule.Id, dlg.Schedule);
        PolicyEditor.SetNotes(_doc, rule.Id, dlg.Notes);
        if (dlg.LimitKbps is long kbps) PolicyEditor.UpdateLimitKbps(_doc, rule.Id, kbps);
        if (dlg.Priority is PriorityBand band) PolicyEditor.UpdatePriority(_doc, rule.Id, band);
        if (dlg.QuotaBytes is long qb) PolicyEditor.UpdateQuotaBytes(_doc, rule.Id, qb);
        SavePolicy("Updated " + row.FilterName);
    }

    private void UnblockMatching_Click(object sender, RoutedEventArgs e)
    {
        var q = (UnblockQuery.Text ?? "").Trim();
        if (q.Length == 0) { MessageBox.Show("Enter substring."); return; }
        var n = PolicyEditor.Unblock(_doc, q);
        SavePolicy($"Unblocked {n} rule(s)");
    }

    private void RemoveMatching_Click(object sender, RoutedEventArgs e)
    {
        var q = (UnblockQuery.Text ?? "").Trim();
        if (q.Length == 0) { MessageBox.Show("Enter substring."); return; }
        var n = PolicyEditor.RemoveRulesMatching(_doc, q);
        SavePolicy($"Removed {n} rule(s)");
    }

    private void RemoveMatchingLimits_Click(object sender, RoutedEventArgs e)
    {
        var q = (UnblockQuery.Text ?? "").Trim();
        if (q.Length == 0) { MessageBox.Show("Enter substring."); return; }
        var n = PolicyEditor.RemoveRulesMatching(_doc, q, RuleKind.Limit);
        SavePolicy($"Removed {n} limit(s)");
    }

    private void AddMatcher_Click(object sender, RoutedEventArgs e)
    {
        var row = SelectedRuleRow();
        if (row is null) return;
        var kindIdx = ExtraMatcherKind.SelectedIndex;
        var raw = (ExtraPortFrom.Text ?? "").Trim();
        var rawTo = (ExtraPortTo.Text ?? "").Trim();
        try
        {
            Matcher matcher = kindIdx switch
            {
                0 => PortMatcher(MatcherKind.RemotePortInRange, raw, rawTo),
                1 => PortMatcher(MatcherKind.LocalPortInRange, raw, rawTo),
                2 => new Matcher { Kind = MatcherKind.DomainEquals, StringValue = raw },
                3 => new Matcher { Kind = MatcherKind.RemoteAddressInRange, Cidr = raw, StringValue = raw },
                4 => new Matcher { Kind = MatcherKind.ProcessIdEquals, UIntValue = ulong.Parse(raw) },
                _ => throw new InvalidOperationException("Unknown matcher"),
            };
            if (!PolicyEditor.AddMatcherToRule(_doc, row.RuleId, matcher))
            {
                MessageBox.Show("Could not add matcher.");
                return;
            }
            SavePolicy("Matcher added", tryAuto: false);
        }
        catch (Exception ex)
        {
            MessageBox.Show("Invalid matcher: " + ex.Message);
        }
    }

    private static Matcher PortMatcher(MatcherKind kind, string from, string to)
    {
        if (!ushort.TryParse(from, out var a)) throw new FormatException("port from");
        if (!ushort.TryParse(string.IsNullOrWhiteSpace(to) ? from : to, out var b))
            throw new FormatException("port to");
        if (b < a) (a, b) = (b, a);
        return new Matcher { Kind = kind, PortFrom = a, PortTo = b };
    }

    private void CopyConnections_Click(object sender, RoutedEventArgs e)
    {
        if (_visibleConnections.Count == 0) { MessageBox.Show("No connections."); return; }
        var sb = new StringBuilder();
        sb.AppendLine("PID\tProcess\tProto\tDown\tUp\tLocal\tRemote\tState");
        foreach (var c in _visibleConnections)
            sb.AppendLine($"{c.ProcessId}\t{c.ProcessName}\t{c.Protocol}\t{c.RateInDisplay}\t{c.RateOutDisplay}\t{c.LocalEndPoint}\t{c.RemoteEndPoint}\t{c.State}");
        try
        {
            Clipboard.SetText(sb.ToString());
            LogInfo($"Copied {_visibleConnections.Count} connection(s)");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void ExportConnectionsCsv_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = "CSV (*.csv)|*.csv",
            FileName = $"netshaper-conns-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };
        if (dlg.ShowDialog() != true) return;
        var sb = new StringBuilder();
        sb.AppendLine("PID,Process,Proto,Down,Up,Local,Remote,State");
        foreach (var c in _visibleConnections)
        {
            static string Esc(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
            sb.AppendLine(string.Join(',',
                c.ProcessId,
                Esc(c.ProcessName),
                Esc(c.Protocol),
                Esc(c.RateInDisplay),
                Esc(c.RateOutDisplay),
                Esc(c.LocalEndPoint),
                Esc(c.RemoteEndPoint),
                Esc(c.State)));
        }
        File.WriteAllText(dlg.FileName, sb.ToString());
        LogOk("Exported CSV", dlg.FileName);
    }

    private void RequireAdminOrWarn(string action)
    {
        if (IsElevated()) return;
        var detail = action.ToLowerInvariant() switch
        {
            var a when a.Contains("wfp") =>
                "Windows Filtering Platform rules (block/allow/lockdown) need admin to install into the system filter engine.",
            var a when a.Contains("qos") =>
                "Policy-based QoS / NetQos throttling needs admin to create system QoS policies.",
            var a when a.Contains("apply all") =>
                "Apply all installs WFP firewall rules and QoS limits into Windows. That requires Administrator.",
            var a when a.Contains("packet") || a.Contains("divert") =>
                "Packet mode (WinDivert) needs admin to open the capture/inject handle.",
            _ => "This action modifies system network policy and requires Administrator."
        };
        MessageBox.Show(
            $"{action} requires Administrator.\n\n{detail}\n\n" +
            "Still works without admin:\n" +
            "• Store rules / limits / quotas in policy\n" +
            "• Live traffic (NIC-share rates; EStats is more precise when elevated)\n" +
            "• Local API, stats, CLI list/sample\n\n" +
            "Tip: close NetShaper and restart via UAC, or use Setup.cmd / Run as administrator.",
            "NetShaper — elevation needed",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
        LogWarn($"{action}: not elevated");
    }

    private void ApplyAll_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("Apply all")) return;
        if (!IsElevated()) { RequireAdminOrWarn("Apply all"); return; }
        _doc = _profiles.LoadActive();
        var r = _enforcer.ApplyAll(_doc, ChkPersistWfp.IsChecked == true);
        LogOk(r.Summary);
        if (r.Errors.Count > 0)
            MessageBox.Show(string.Join("\n", r.Errors.Take(12)), "Apply all — warnings");
        RefreshStatusPanels(quiet: true);
    }

    private void ApplyWfp_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("Apply WFP")) return;
        if (!IsElevated()) { RequireAdminOrWarn("Apply WFP"); return; }
        _doc = _profiles.LoadActive();
        var r = _enforcer.ApplyAll(_doc, ChkPersistWfp.IsChecked == true, applyWfp: true, applyQos: false);
        LogOk("WFP: " + r.Summary);
        RefreshStatusPanels(quiet: true);
    }

    private void ApplyQos_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("Apply QoS")) return;
        if (!IsElevated()) { RequireAdminOrWarn("Apply QoS"); return; }
        _doc = _profiles.LoadActive();
        var r = _enforcer.ApplyAll(_doc, ChkPersistWfp.IsChecked == true, applyWfp: false, applyQos: true);
        LogOk("QoS: " + r.Summary);
        if (r.Errors.Count > 0)
            MessageBox.Show(string.Join("\n", r.Errors.Take(12)), "QoS warnings");
        RefreshStatusPanels(quiet: true);
    }

    private void ClearWfp_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("Clear WFP")) return;
        if (!IsElevated()) { RequireAdminOrWarn("Clear WFP"); return; }
        try
        {
            var mode = ChkPersistWfp.IsChecked == true ? WfpSessionMode.Persistent : WfpSessionMode.Dynamic;
            using var eng = new WfpFilterEngine(mode);
            eng.Open();
            var n = eng.ClearOurFilters();
            LogOk($"WFP cleared ≈{n}");
            RefreshStatusPanels(quiet: true);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void ClearQos_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureControl("Clear QoS")) return;
        if (!IsElevated()) { RequireAdminOrWarn("Clear QoS"); return; }
        var errors = new List<string>();
        var n = _enforcer.Qos.ClearOurPolicies(errors);
        LogOk($"QoS cleared ≈{n}");
        if (errors.Count > 0)
            MessageBox.Show(string.Join("\n", errors.Take(8)));
        RefreshStatusPanels(quiet: true);
    }

    private void RefreshWfpStatus_Click(object sender, RoutedEventArgs e) => RefreshStatusPanels(quiet: false);

    private void RefreshStatusPanels(bool quiet)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Elevated: {IsElevated()}  Profile: {_activeProfile}");
        sb.AppendLine($"WFP mode: {(ChkPersistWfp.IsChecked == true ? "Persistent" : "Dynamic")}");
        sb.AppendLine($"Provider: {WfpFilterEngine.ProviderKey}");
        var statePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "NetShaper", "wfp-filters.json");
        if (File.Exists(statePath))
        {
            try
            {
                var keys = System.Text.Json.JsonSerializer.Deserialize<List<Guid>>(File.ReadAllText(statePath));
                sb.AppendLine($"WFP tracked keys: {keys?.Count ?? 0}");
            }
            catch { sb.AppendLine("WFP tracked keys: (unreadable)"); }
        }
        else sb.AppendLine("WFP tracked keys: 0");

        if (IsElevated())
        {
            try
            {
                var mode = ChkPersistWfp.IsChecked == true ? WfpSessionMode.Persistent : WfpSessionMode.Dynamic;
                using var eng = new WfpFilterEngine(mode);
                var s = eng.GetStatus();
                sb.AppendLine($"Engine tracked: {s.TrackedFilterKeys}");
            }
            catch (Exception ex) { sb.AppendLine("Engine: " + ex.Message); }
        }
        WfpStatusText.Text = sb.ToString().TrimEnd();
        QosStatusText.Text = _enforcer.Qos.StatusText();
        if (!quiet) LogInfo("Status refreshed");
    }

    private void RefreshService_Click(object sender, RoutedEventArgs e) => RefreshServiceStatus();

    private void RefreshServiceStatus()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            ServiceStatusText.Text =
                $"Name: {ServiceName}\nDisplay: {sc.DisplayName}\nStatus: {sc.Status}\nStart: {sc.StartType}";
        }
        catch (InvalidOperationException)
        {
            ServiceStatusText.Text = $"Service '{ServiceName}' not installed.\nAdmin: .\\scripts\\install-service.ps1";
        }
        catch (Exception ex)
        {
            ServiceStatusText.Text = "Service check failed: " + ex.Message;
        }
    }

    private void OpenScriptsFolder_Click(object sender, RoutedEventArgs e)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string? scripts = null;
        while (dir != null)
        {
            var c = Path.Combine(dir.FullName, "scripts");
            if (Directory.Exists(c)) { scripts = c; break; }
            dir = dir.Parent;
        }
        if (scripts is null) { MessageBox.Show("Scripts folder not found."); return; }
        Process.Start(new ProcessStartInfo("explorer.exe", scripts) { UseShellExecute = true });
    }

    private void OpenPolicyFolder_Click(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo("explorer.exe", _profiles.RootDir) { UseShellExecute = true });
    }

    private void ViewPolicyJson_Click(object sender, RoutedEventArgs e)
    {
        var path = _profiles.ProfilePath(_activeProfile);
        var json = File.Exists(path) ? File.ReadAllText(path) : PolicyEditor.ToJson(_doc);
        new TextViewerDialog($"Policy — {_activeProfile}", json) { Owner = this }.ShowDialog();
    }

    private void ExportPolicy_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = "JSON (*.json)|*.json",
            FileName = $"netshaper-{_activeProfile}.json",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            _profiles.SaveProfile(_activeProfile, _doc);
            File.Copy(_profiles.ProfilePath(_activeProfile), dlg.FileName, overwrite: true);
            LogOk("Exported", dlg.FileName);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void ImportPolicy_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "JSON (*.json)|*.json" };
        if (dlg.ShowDialog() != true) return;
        try
        {
            _doc = _legacyStore.ImportFrom(dlg.FileName, replace: false);
            _profiles.SaveProfile(_activeProfile, _doc);
            // also sync via save
            LoadSettingsUi();
            ReloadAllGrids();
            LogOk("Imported into profile " + _activeProfile, dlg.FileName);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void CopyPolicyPath_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_profiles.ProfilePath(_activeProfile));
            SetStatus("Path copied.");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void ResetPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Reset current profile to defaults?", "NetShaper",
                MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
        _doc = PolicyDocument.CreateDefaults();
        SavePolicy("Profile reset to defaults");
        LoadSettingsUi();
    }

    private sealed class RuleRow
    {
        public Guid RuleId { get; set; }
        public string Kind { get; set; } = "";
        public string FilterName { get; set; } = "";
        public string Direction { get; set; } = "";
        public string Detail { get; set; } = "";
        public bool Enabled { get; set; }
        public string ScheduleDisplay { get; set; } = "";
        public bool ActiveNow { get; set; }
        public string Matchers { get; set; } = "";
    }

    private sealed class LimitRow
    {
        public string FilterName { get; set; } = "";
        public long Kbps { get; set; }
        public string LimitDisplay { get; set; } = "";
        public string MeasuredDisplay { get; set; } = "";
        public bool OverLimit { get; set; }
        public string Action { get; set; } = "";
        public string ProcessSummary { get; set; } = "";
        public int MatchedProcesses { get; set; }
        public string Direction { get; set; } = "";
        public bool ScheduleActive { get; set; }
        public string Matchers { get; set; } = "";
    }

    private sealed class QuotaRow
    {
        public Guid RuleId { get; set; }
        public string FilterName { get; set; } = "";
        public string UsedDisplay { get; set; } = "";
        public string CeilingDisplay { get; set; } = "";
        public string PercentDisplay { get; set; } = "";
        public bool Exceeded { get; set; }
        public bool ActiveNow { get; set; }
    }

    private sealed class FilterRow
    {
        public string Name { get; set; } = "";
        public bool IsZone { get; set; }
        public int Weight { get; set; }
        public string Matchers { get; set; } = "";
        public string IdShort { get; set; } = "";
    }

    private sealed class ActivityRow
    {
        public string TimeDisplay { get; set; } = "";
        public string Level { get; set; } = "";
        public string Message { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    private sealed class HistoryAppRow
    {
        public string Name { get; set; } = "";
        public string InDisplay { get; set; } = "";
        public string OutDisplay { get; set; } = "";
        public string TotalDisplay { get; set; } = "";
        public string ShareDisplay { get; set; } = "";
    }
}
