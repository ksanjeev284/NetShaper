using System.Windows;
using NetShaper.Core.Policy;

namespace NetShaper.Gui;

public partial class EditRuleDialog : Window
{
    public TrafficDirection Direction { get; private set; }
    public bool Enabled { get; private set; }
    public long? LimitKbps { get; private set; }
    public PriorityBand? Priority { get; private set; }
    public long? QuotaBytes { get; private set; }
    public RuleSchedule? Schedule { get; private set; }
    public string? Notes { get; private set; }

    private readonly RuleKind _kind;

    public EditRuleDialog(Rule rule, string filterName)
    {
        InitializeComponent();
        _kind = rule.Kind;
        TitleText.Text = $"Edit {rule.Kind}: {filterName}";
        EnabledBox.IsChecked = rule.Enabled;
        NotesBox.Text = rule.Notes ?? "";
        DirBox.SelectedIndex = rule.Direction switch
        {
            TrafficDirection.In => 0,
            TrafficDirection.Out => 1,
            _ => 2,
        };

        if (rule.Kind == RuleKind.Limit)
        {
            LimitPanel.Visibility = Visibility.Visible;
            KbpsBox.Text = rule.LimitBytesPerSec is long b
                ? PolicyEditor.BytesPerSecToKbps(b).ToString()
                : "1000";
        }
        else if (rule.Kind == RuleKind.Priority)
        {
            PriorityPanel.Visibility = Visibility.Visible;
            PriorityBox.SelectedIndex = (int)(rule.Priority ?? PriorityBand.Normal);
        }
        else if (rule.Kind == RuleKind.Quota)
        {
            QuotaPanel.Visibility = Visibility.Visible;
            QuotaMbBox.Text = rule.QuotaBytes is long q
                ? Math.Max(1, q / (1024 * 1024)).ToString()
                : "1024";
        }

        if (rule.Schedule is { } s)
        {
            SchedEnabled.IsChecked = s.Enabled;
            SchedStart.Text = s.StartLocal ?? "09:00";
            SchedEnd.Text = s.EndLocal ?? "17:00";
            SchedDays.Text = s.DaysOfWeek is { Count: > 0 } d
                ? string.Join(",", d)
                : "";
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        Direction = DirBox.SelectedIndex switch
        {
            0 => TrafficDirection.In,
            1 => TrafficDirection.Out,
            _ => TrafficDirection.Both,
        };
        Enabled = EnabledBox.IsChecked == true;
        Notes = string.IsNullOrWhiteSpace(NotesBox.Text) ? null : NotesBox.Text.Trim();

        if (_kind == RuleKind.Limit)
        {
            if (!long.TryParse(KbpsBox.Text, out var k) || k <= 0)
            {
                MessageBox.Show("Enter a positive kbps value.", "NetShaper");
                return;
            }
            LimitKbps = k;
        }
        else if (_kind == RuleKind.Priority)
        {
            Priority = (PriorityBand)Math.Clamp(PriorityBox.SelectedIndex, 0, 4);
        }
        else if (_kind == RuleKind.Quota)
        {
            if (!long.TryParse(QuotaMbBox.Text, out var mb) || mb <= 0)
            {
                MessageBox.Show("Enter a positive quota in MB.", "NetShaper");
                return;
            }
            QuotaBytes = mb * 1024 * 1024;
        }

        if (SchedEnabled.IsChecked == true)
        {
            List<int>? days = null;
            var raw = (SchedDays.Text ?? "").Trim();
            if (raw.Length > 0)
            {
                days = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(s => int.Parse(s))
                    .Where(i => i is >= 0 and <= 6)
                    .ToList();
            }
            Schedule = new RuleSchedule
            {
                Enabled = true,
                StartLocal = (SchedStart.Text ?? "").Trim(),
                EndLocal = (SchedEnd.Text ?? "").Trim(),
                DaysOfWeek = days,
            };
        }
        else
        {
            Schedule = new RuleSchedule { Enabled = false };
        }

        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
