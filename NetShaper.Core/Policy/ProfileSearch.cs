namespace NetShaper.Core.Policy;

public sealed record ProfileSearchHit(
    string Profile,
    Guid RuleId,
    string Kind,
    string FilterName,
    string Matchers,
    bool Enabled,
    bool ActiveNow);

/// <summary>Search rules across all profiles on disk.</summary>
public static class ProfileSearch
{
    public static IReadOnlyList<ProfileSearchHit> Search(ProfileStore store, string query)
    {
        var q = (query ?? "").Trim();
        if (q.Length == 0) return Array.Empty<ProfileSearchHit>();

        var hits = new List<ProfileSearchHit>();
        foreach (var name in store.ListProfiles())
        {
            PolicyDocument doc;
            try { doc = store.LoadProfile(name); }
            catch { continue; }

            foreach (var r in doc.Rules)
            {
                var f = doc.Filters.FirstOrDefault(x => x.Id == r.FilterId);
                var filterName = f?.Name ?? "";
                var matchers = f is null
                    ? ""
                    : string.Join("; ", f.Matchers.Select(m =>
                        $"{m.Kind}:{m.StringValue ?? m.UIntValue?.ToString() ?? m.Cidr ?? $"{m.PortFrom}-{m.PortTo}"}"));

                var blob = $"{r.Kind} {filterName} {matchers} {r.Notes}";
                if (!blob.Contains(q, StringComparison.OrdinalIgnoreCase))
                    continue;

                hits.Add(new ProfileSearchHit(
                    name,
                    r.Id,
                    r.Kind.ToString(),
                    filterName,
                    matchers,
                    r.Enabled,
                    r.IsActiveNow()));
            }
        }
        return hits;
    }
}
