using Microsoft.Win32;

namespace NetShaper.Gui;

public static class StartupHelper
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "NetShaper";

    public static bool IsEnabled()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(RunKey, false);
            return k?.GetValue(ValueName) is string;
        }
        catch { return false; }
    }

    public static void SetEnabled(bool enabled, string? exePath = null)
    {
        using var k = Registry.CurrentUser.OpenSubKey(RunKey, true)
                      ?? Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled)
        {
            var path = exePath ?? Environment.ProcessPath
                       ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                       ?? "";
            if (path.Length == 0) return;
            k.SetValue(ValueName, "\"" + path + "\" --minimized");
        }
        else
        {
            try { k.DeleteValue(ValueName, false); } catch { /* ignore */ }
        }
    }
}
