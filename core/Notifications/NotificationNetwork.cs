using System.Net;
using System.Net.Mail;
using System.Net.Sockets;

namespace SentinelAI.Core.Notifications;

internal sealed class NotificationDestinationRejectedException : Exception;

internal static class NotificationNetwork
{
    internal static bool IsValidWebhookUri(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Port == 443 && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && uri.OriginalString.Length <= 2048 &&
        !uri.OriginalString.Any(char.IsControl) && IsValidHost(uri.IdnHost);

    internal static bool IsValidHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253 || host.Any(c => c > 127 || char.IsControl(c)) ||
            host != host.Trim() || host.EndsWith('.')) return false;
        if (IPAddress.TryParse(host, out var address)) return IsPublicAddress(address);
        return Uri.CheckHostName(host) == UriHostNameType.Dns && host.Contains('.') &&
            !new[] { ".localhost", ".local", ".internal", ".home.arpa", ".test", ".invalid" }
                .Any(suffix => host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
    }

    internal static bool IsValidMailbox(string? value) => value is { Length: > 0 and <= 254 } &&
        !value.Any(c => c > 127 || char.IsControl(c)) && value == value.Trim() &&
        MailAddress.TryCreate(value, out var address) && address.DisplayName.Length == 0 && address.Address == value;

    internal static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
            return b[0] is not (0 or 10 or 127) && b[0] < 224 &&
                !(b[0] == 100 && b[1] is >= 64 and <= 127) &&
                !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && b[1] is >= 16 and <= 31) &&
                !(b[0] == 192 && (b[1] == 168 || b[1] == 0 && b[2] is 0 or 2 || b[1] == 88 && b[2] == 99)) &&
                !(b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)) &&
                !(b[0] == 203 && b[1] == 0 && b[2] == 113);
        // Accept global unicast only, excluding special-use, documentation and transition ranges.
        return address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId == 0 && (b[0] & 0xe0) == 0x20 &&
            !(b[0] == 0x20 && b[1] == 0x01 && (b[2] < 2 || b[2] == 0x0d && b[3] == 0xb8)) &&
            !(b[0] == 0x20 && b[1] == 0x02) && !(b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0);
    }

    internal static async Task<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken)
    {
        if (!IsValidHost(host) || port is not (443 or 587)) throw new NotificationDestinationRejectedException();
        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        return await ConnectResolvedAsync(addresses, port, static async (address, destinationPort, token) =>
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, destinationPort), token);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch { socket.Dispose(); throw; }
        }, cancellationToken);
    }

    internal static async Task<Stream> ConnectResolvedAsync(IPAddress[] addresses, int port,
        Func<IPAddress, int, CancellationToken, Task<Stream>> connect, CancellationToken cancellationToken)
    {
        // Reject mixed answers too. The socket uses the checked IP, never a second DNS lookup.
        if (addresses.Length is < 1 or > 16 || addresses.Any(address => !IsPublicAddress(address)) || port is not (443 or 587))
            throw new NotificationDestinationRejectedException();
        foreach (var address in addresses.Distinct())
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { return await connect(address, port, cancellationToken); }
            catch (SocketException) { }
        }
        throw new IOException("Notification connection failed.");
    }
}
