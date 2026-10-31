using System.Windows.Markup;
using SentinelAI.Localization;

namespace SentinelAI.Desktop.Localization;

/// <summary>
/// A fixed text in Desktop's language: <c>{loc:T 'Refresh'}</c>. Desktop chooses its language once at start, so the
/// text is resolved when the view is created.
/// </summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class TExtension : MarkupExtension
{
    public TExtension() { }

    public TExtension(string text) => Text = text;

    [ConstructorArgument("text")]
    public string Text { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider) => Localizer.T(Text);
}
