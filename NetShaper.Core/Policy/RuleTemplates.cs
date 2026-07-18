namespace NetShaper.Core.Policy;

/// <summary>Built-in rule packs the GUI can apply in one click.</summary>
public static class RuleTemplates
{
    public sealed record Template(
        string Id,
        string Name,
        string Description,
        Action<PolicyDocument> Apply);

    public static IReadOnlyList<Template> All { get; } = new List<Template>
    {
        new("throttle-browser", "Throttle browsers 2 Mbps",
            "Limit chrome/msedge/firefox to ~2000 kbps both ways.",
            doc =>
            {
                foreach (var app in new[] { "chrome", "msedge", "firefox", "brave" })
                    PolicyEditor.AddLimit(doc, app, 2000, TrafficDirection.Both);
            }),

        new("block-torrents-ports", "Block common P2P ports",
            "Block apps matching torrent/qbittorrent/utorrent (path contains).",
            doc =>
            {
                foreach (var app in new[] { "qbittorrent", "utorrent", "bittorrent", "transmission", "deluge" })
                    PolicyEditor.AddBlock(doc, app, TrafficDirection.Both);
            }),

        new("work-focus", "Work focus (block social)",
            "Block discord, telegram, steam, epic (path contains).",
            doc =>
            {
                foreach (var app in new[] { "discord", "telegram", "steam", "epicgameslauncher", "spotify" })
                    PolicyEditor.AddBlock(doc, app, TrafficDirection.Both);
            }),

        new("game-priority", "Gaming priority pack",
            "High priority for steam/gamebar; limit chrome to 1 Mbps.",
            doc =>
            {
                PolicyEditor.AddPriority(doc, "steam", PriorityBand.High, TrafficDirection.Both);
                PolicyEditor.AddPriority(doc, "GameBar", PriorityBand.High, TrafficDirection.Both);
                PolicyEditor.AddLimit(doc, "chrome", 1000, TrafficDirection.Both);
                PolicyEditor.AddLimit(doc, "msedge", 1000, TrafficDirection.Both);
            }),

        new("cap-updates", "Cap Windows/update agents 500 kbps",
            "Throttle common update-related processes.",
            doc =>
            {
                foreach (var app in new[] { "TiWorker", "UsoClient", "wuauclt", "WindowsUpdate", "DoSvc" })
                    PolicyEditor.AddLimit(doc, app, 500, TrafficDirection.Both);
            }),

        new("night-quota-10gb", "Night quota 10 GB (22:00–07:00)",
            "Quota rule on Any-like path chrome with overnight schedule — edit path after apply.",
            doc =>
            {
                var r = PolicyEditor.AddQuota(doc, "chrome", 10L * 1024 * 1024 * 1024, TrafficDirection.Both);
                PolicyEditor.SetSchedule(doc, r.Id, new RuleSchedule
                {
                    Enabled = true,
                    StartLocal = "22:00",
                    EndLocal = "07:00",
                });
            }),

        new("allow-local-tools", "Allow local dev tools",
            "Allow code/cursor/devenv/docker paths.",
            doc =>
            {
                foreach (var app in new[] { "Code", "Cursor", "devenv", "docker", "WindowsTerminal" })
                    PolicyEditor.AddAllow(doc, app, TrafficDirection.Both);
            }),

        new("lockdown-essentials", "Lockdown allowlist essentials",
            "Enable lockdown + allow system/browser/shell essentials (edit after apply).",
            doc =>
            {
                doc.LockdownEnabled = true;
                doc.FirewallEnabled = true;
                foreach (var app in new[]
                         {
                             "svchost", "System", "explorer", "SearchHost", "RuntimeBroker",
                             "msedge", "chrome", "firefox", "OneDrive", "SecurityHealthService",
                         })
                    PolicyEditor.AddAllow(doc, app, TrafficDirection.Both);
            }),

        new("stream-cap", "Cap streaming apps 4 Mbps",
            "Limit spotify/netflix/youtube/vlc-style apps.",
            doc =>
            {
                foreach (var app in new[] { "Spotify", "vlc", "mpv", "Video.UI", "ApplicationFrameHost" })
                    PolicyEditor.AddLimit(doc, app, 4000, TrafficDirection.Both);
            }),

        new("remote-work", "Remote work pack",
            "Allow Teams/Zoom/Slack; throttle chrome; block steam/discord.",
            doc =>
            {
                foreach (var a in new[] { "Teams", "ms-teams", "Zoom", "Slack" })
                    PolicyEditor.AddAllow(doc, a, TrafficDirection.Both);
                PolicyEditor.AddLimit(doc, "chrome", 3000, TrafficDirection.Both);
                PolicyEditor.AddBlock(doc, "steam", TrafficDirection.Both);
                PolicyEditor.AddBlock(doc, "discord", TrafficDirection.Both);
            }),

        new("download-managers", "Throttle download managers 1 Mbps",
            "Limit common download clients.",
            doc =>
            {
                foreach (var a in new[] { "IDMan", "FreeDownloadManager", "Motrix", "aria2c", "wget" })
                    PolicyEditor.AddLimit(doc, a, 1000, TrafficDirection.Both);
            }),
    };

    public static Template? Find(string id) =>
        All.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
}
