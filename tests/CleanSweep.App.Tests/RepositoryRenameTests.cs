using CleanSweep.App.Services;
using CleanSweep.Core.Integrity;

namespace CleanSweep.App.Tests;

public sealed class RepositoryRenameTests
{
    [Theory]
    [InlineData("boooooommmmmm/Cleaner", "boooooommmmmm/FatalCleaner")]
    [InlineData(" boooooommmmmm/cleaner ", "boooooommmmmm/FatalCleaner")]
    [InlineData("someone/Cleaner", "someone/Cleaner")]
    [InlineData("https://example.com/Cleaner", "https://example.com/Cleaner")]
    public void Settings_migrate_old_official_source_and_preserve_custom_sources(string saved, string expected)
    {
        var settings = new AppSettings { UpdateSource = saved };
        settings.Normalize();
        Assert.Equal(expected, settings.UpdateSource);
        Assert.NotNull(UpdateSources.Resolve(settings.UpdateSource));
    }
}
