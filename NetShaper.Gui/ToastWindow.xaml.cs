using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace NetShaper.Gui;

public partial class ToastWindow : Window
{
    private readonly DispatcherTimer _timer;

    public ToastWindow(string title, string body, bool warn = false)
    {
        InitializeComponent();
        TitleText.Text = title;
        BodyText.Text = body;
        if (warn)
            Root.BorderBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0xC8, 0x57));

        var work = SystemParameters.WorkArea;
        Left = work.Right - 380;
        Top = work.Bottom - 120;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4.5) };
        _timer.Tick += (_, _) => Close();
        _timer.Start();
    }

    private void Root_Click(object sender, System.Windows.Input.MouseButtonEventArgs e) => Close();

    public static void ShowToast(Window? owner, string title, string body, bool warn = false)
    {
        var w = new ToastWindow(title, body, warn);
        if (owner != null)
            w.Owner = owner;
        w.Show();
    }
}
