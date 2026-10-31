using System.IO;
using Microsoft.Win32;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Localization;

namespace SentinelAI.Desktop.Services;

/// <summary>The last installation language this Windows user saw (HKCU), for starts while Core does not answer.</summary>
public sealed class WindowsLanguageCache : ILanguageCache
{
    private const string KeyPath = @"Software\SentinelAI\Desktop";
    private const string ValueName = "Language";

    public UiLanguage? Read()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
            return key?.GetValue(ValueName) is string code && UiLanguages.TryParse(code, out var language) ? language : null;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return null;
        }
    }

    public void Save(UiLanguage language)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath, writable: true);
            key.SetValue(ValueName, UiLanguages.Code(language), RegistryValueKind.String);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // Only a convenience for the next start.
        }
    }
}
