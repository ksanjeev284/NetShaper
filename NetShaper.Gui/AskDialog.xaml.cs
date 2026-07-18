using System.Windows;
using NetShaper.Core.Firewall;

namespace NetShaper.Gui;

public partial class AskDialog : Window
{
    public AskDecisionKind? Result { get; private set; }
    public AskRequest Request { get; }

    public AskDialog(AskRequest request, bool elevated)
    {
        InitializeComponent();
        Request = request;
        TitleText.Text = request.ProcessName + " wants network access";
        PathText.Text = request.ExecutablePath ?? "(path unavailable)";
        PidText.Text = request.ProcessId.ToString();
        ProtoText.Text = request.Protocol;
        LocalText.Text = request.SampleLocal;
        RemoteText.Text = request.SampleRemote;
        ConnsText.Text = request.ConnectionCount.ToString();
        ElevHint.Text = elevated ? "Elevated — WFP can apply now" : "Not elevated — policy only until Apply WFP";
    }

    private void Finish(AskDecisionKind kind)
    {
        Result = kind;
        DialogResult = true;
        Close();
    }

    private void AllowAlways_Click(object sender, RoutedEventArgs e) => Finish(AskDecisionKind.AllowAlways);
    private void BlockAlways_Click(object sender, RoutedEventArgs e) => Finish(AskDecisionKind.BlockAlways);
    private void AllowOnce_Click(object sender, RoutedEventArgs e) => Finish(AskDecisionKind.AllowOnce);
    private void BlockOnce_Click(object sender, RoutedEventArgs e) => Finish(AskDecisionKind.BlockOnce);
    private void Skip_Click(object sender, RoutedEventArgs e) => Finish(AskDecisionKind.Skip);
}
