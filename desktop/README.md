# Native desktop

`SentinelAI.Desktop` is a native WPF application for Windows x64 on .NET 10. It opens its own Windows window with standard window controls. Devices now lists enrolled endpoints and opens native endpoint details. Overview, Alerts, Risk, Reports and Settings remain placeholders.

## Build and run

From the repository root with the .NET 10 SDK and Bash (for example Git Bash on Windows):

```sh
./scripts/build.sh
./scripts/publish-desktop-windows.sh
```

The publish command produces a self-contained, untrimmed application directory at `artifacts/desktop/win-x64`. On Windows, run `SentinelAI.Desktop.exe` from that directory. Keep the accompanying files together; a separate .NET installation is unnecessary. This is a development artifact, not an installer or an Authenticode-signed release.

Linux can restore and cross-compile the Windows projects through `EnableWindowsTargeting`. It can run the portable desktop tests, but cannot execute WPF or establish native Windows acceptance.

## Boundaries and lifecycle

- `SentinelAI.Desktop` contains WPF views, Windows installation/connected-peer trust adapters, semantic theme resources and the DPI manifest.
- `SentinelAI.Desktop.Foundation` contains navigation, observable shell/authentication state and bounded Core clients behind service interfaces. It has no WPF or third-party dependency.
- First-run setup uses the trusted installed Core's local one-shot command and existing operator filesystem authority. Normal sign-in uses Core's existing authoritative API; the connected TCP peer must belong to the trusted Core process before credentials can be transmitted. See [setup and authentication](../docs/DESKTOP-AUTH.md).
- The window opens immediately and checks Core asynchronously. Navigation remains disabled until authenticated. Bearers stay in memory for at most 15 minutes; sign-out, expiry, restart and connection loss clear the local session. Reconnection requires explicit sign-in. Closing the window cancels pending work, clears credentials and leaves Core running.
- A separate setup-only window can request UAC approval for initial creation; the normal desktop runs without elevation. Desktop does not install or control Core's service, migrate dashboard screens or perform updates.

The light palette uses semantic `DynamicResource` brush keys, and common controls have shared styles. A later dark/light feature can replace the palette without changing view models or page layouts. WPF logical units, flexible grid sizing, wrapped text, scrolling and layout rounding provide the scaling foundation. The process requests PerMonitorV2 awareness and runs without elevation.

## Validation

The repository's `./scripts/test.sh` includes executable portable assertions for desktop navigation, connection handling and shutdown. On Windows, also run:

```powershell
dotnet run --project tests/SentinelAI.Desktop.Windows.Tests/SentinelAI.Desktop.Windows.Tests.csproj --configuration Release --runtime win-x64
bash ./scripts/publish-desktop-windows.sh
pwsh -NoLogo -NoProfile -NonInteractive -File tests/desktop/Windows.Acceptance.ps1 -ExecutablePath artifacts/desktop/win-x64/SentinelAI.Desktop.exe
```

The Windows test runner checks actual WPF authentication, password clearing, gated navigation, native Devices filtering/paging/virtualization/details, keyboard focus, layout, DPI and disposal. The standalone acceptance script launches the published executable, verifies its native signed-out window and requests a graceful close. The dedicated Windows CI job runs both before uploading the application directory. The Core-service Windows CI job additionally runs `tests/desktop/Authentication.Acceptance.ps1` against the signed installed Core and published desktop, covering real bootstrap, sign-in/out, listener rejection, restart/reconnect and Devices against synthetic enrolled endpoints. See [device operation and limits](../docs/DESKTOP-DEVICES.md).

Physical scaling remains a practical manual check on a Windows desktop:

1. At 100%, 125%, 150% and 200% Windows display scaling, open the executable and resize between its minimum and a maximized window.
2. Check setup/sign-in controls, then sign in and visit each navigation item using the mouse and keyboard. Verify headings, descriptions, focus indicators and the connection strip remain readable; page content should scroll when space is limited.
3. If monitors use different scaling, move the window between them and repeat navigation and resizing. Text should remain sharp and controls should follow the destination monitor's scale.
4. Close the application during a connection check and verify that it exits promptly.

Logical window-size tests and DPI-context checks do not simulate every physical monitor configuration. Record the actual Windows test results before marking native launch acceptance complete.
