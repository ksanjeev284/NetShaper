using System.Windows;

namespace NetShaper.Gui;

public partial class LimitDialog : Window
{
    public long Kbps { get; private set; }

    public LimitDialog(string processName)
    {
        InitializeComponent();
        TitleText.Text = $"Limit bandwidth for {processName}";
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (!long.TryParse(KbpsBox.Text, out var k) || k <= 0)
        {
            MessageBox.Show("Enter a positive kbps value.", "NetShaper");
            return;
        }
        Kbps = k;
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
