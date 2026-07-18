using System.Windows;

namespace NetShaper.Gui;

/// <summary>
/// Standard WPF theming: swap a color ResourceDictionary (Dark/Light) that also
/// overrides SystemColors so DataGrid/ComboBox/etc. use readable foregrounds.
/// </summary>
public static class ThemeService
{
    private const string DarkUri = "pack://application:,,,/Themes/Dark.xaml";
    private const string LightUri = "pack://application:,,,/Themes/Light.xaml";
    private const string ControlsUri = "pack://application:,,,/Themes/Controls.xaml";

    public static string Current { get; private set; } = "Dark";

    public static void Apply(string theme)
    {
        var dark = !string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase);
        Current = dark ? "Dark" : "Light";

        var app = Application.Current;
        if (app?.Resources is null) return;

        var merged = app.Resources.MergedDictionaries;

        // Remove previous theme color dictionaries (keep Controls.xaml)
        for (int i = merged.Count - 1; i >= 0; i--)
        {
            var src = merged[i].Source?.ToString() ?? "";
            if (src.Contains("Themes/Dark.xaml", StringComparison.OrdinalIgnoreCase) ||
                src.Contains("Themes/Light.xaml", StringComparison.OrdinalIgnoreCase) ||
                src.Contains("Themes/Controls.xaml", StringComparison.OrdinalIgnoreCase))
            {
                merged.RemoveAt(i);
            }
        }

        // Order: colors first, then control styles that reference them
        merged.Insert(0, new ResourceDictionary { Source = new Uri(dark ? DarkUri : LightUri) });
        merged.Insert(1, new ResourceDictionary { Source = new Uri(ControlsUri) });

        // Mirror tokens onto Application.Resources root so any lingering
        // DynamicResource lookups without merged scope still resolve.
        CopyToken(app.Resources, merged[0], "BgBrush");
        CopyToken(app.Resources, merged[0], "PanelBrush");
        CopyToken(app.Resources, merged[0], "Panel2Brush");
        CopyToken(app.Resources, merged[0], "PanelHoverBrush");
        CopyToken(app.Resources, merged[0], "BorderBrush");
        CopyToken(app.Resources, merged[0], "TextBrush");
        CopyToken(app.Resources, merged[0], "MutedBrush");
        CopyToken(app.Resources, merged[0], "AccentBrush");
        CopyToken(app.Resources, merged[0], "AccentTextBrush");
        CopyToken(app.Resources, merged[0], "DangerBrush");
        CopyToken(app.Resources, merged[0], "OkBrush");
        CopyToken(app.Resources, merged[0], "WarnBrush");
        CopyToken(app.Resources, merged[0], "SelectedBrush");
        CopyToken(app.Resources, merged[0], "SelectedTextBrush");
        CopyToken(app.Resources, merged[0], "InputBgBrush");
        CopyToken(app.Resources, merged[0], "HeaderBgBrush");
    }

    private static void CopyToken(ResourceDictionary target, ResourceDictionary source, string key)
    {
        if (source.Contains(key))
            target[key] = source[key];
    }
}
