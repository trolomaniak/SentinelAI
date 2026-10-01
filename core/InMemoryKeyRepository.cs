using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace SentinelAI.Core;

// ASP.NET Core starts its key manager even when bearer tokens use the ephemeral
// provider. Keep that unused key ring in memory as well, so no key is written
// unencrypted to a user-profile directory.
internal sealed class InMemoryKeyRepository : IXmlRepository
{
    private readonly List<XElement> _keys = [];
    private readonly object _sync = new();

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        lock (_sync)
        {
            return _keys.Select(key => new XElement(key)).ToArray();
        }
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        lock (_sync)
        {
            _keys.Add(new XElement(element));
        }
    }
}
