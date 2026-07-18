using NetShaper.Core.Policy;

namespace NetShaper.Gui;

public partial class App : System.Windows.Application
{
    public static bool StartMinimized { get; private set; }

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        StartMinimized = e.Args.Any(a =>
            a.Equals("--minimized", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("-min", StringComparison.OrdinalIgnoreCase));

        // Prefer hardware rendering; keep UI thread free for input
        try
        {
            System.Windows.Media.RenderOptions.ProcessRenderMode =
                System.Windows.Interop.RenderMode.Default;
        }
        catch { /* ignore */ }

        // Apply saved theme before any window is created (dictionary swap + SystemColors)
        try
        {
            var theme = GuiSettings.Load().Theme;
            ThemeService.Apply(string.IsNullOrWhiteSpace(theme) ? "Dark" : theme);
        }
        catch
        {
            ThemeService.Apply("Dark");
        }

        base.OnStartup(e);
    }
}
