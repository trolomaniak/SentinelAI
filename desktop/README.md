# Native desktop foundation

`SentinelAI.Desktop` is a native WPF application for Windows x64 on .NET 10. It opens its own Windows window with standard window controls. Its Overview, Devices, Alerts, Risk, Reports and Settings pages are placeholders; they do not yet expose the browser dashboard's workflows.

## Build and run

From the repository root with the .NET 10 SDK and Bash (for example Git Bash on Windows):

```sh
./scripts/build.sh
./scripts/publish-desktop-windows.sh
```

The publish command produces a self-contained, untrimmed application directory at `artifacts/desktop/win-x64`. On Windows, run `SentinelAI.Desktop.exe` from that directory. Keep the accompanying files together; a separate .NET installation is unnecessary. This is a development artifact, not an installer or an Authenticode-signed release.

Linux can restore and cross-compile the Windows projects through `EnableWindowsTargeting`. It can run the portable desktop tests, but cannot execute WPF or establish native Windows acceptance.

## Boundaries and lifecycle

- `SentinelAI.Desktop` contains the composition root, WPF views, semantic theme resources and Windows DPI manifest.
- `SentinelAI.Desktop.Foundation` contains navigation, observable shell state, the refresh command and the `ICoreClient` service boundary. It has no WPF or third-party dependency.
- The only implemented Core operation is a bounded, unauthenticated health check against the fixed `http://127.0.0.1:5000/api/health` endpoint. The UI accepts no destination. Redirects and proxy routing are disabled for this loopback check; failures appear as an unavailable connection without preventing navigation.
- The window opens immediately and checks Core asynchronously. **Check connection** refreshes the same endpoint. Closing the window cancels pending work and disposes the client; the application writes no desktop configuration, passwords or credentials.
- The title is SentinelAI, and the visible version comes from the application's build metadata. No Core service installation, authentication, credential persistence, screen migration or updater behavior is implemented by this foundation.

The light palette uses semantic `DynamicResource` brush keys, and common controls have shared styles. A later dark/light feature can replace the palette without changing view models or page layouts. WPF logical units, flexible grid sizing, wrapped text, scrolling and layout rounding provide the scaling foundation. The process requests PerMonitorV2 awareness and runs without elevation.

## Validation

The repository's `./scripts/test.sh` includes executable portable assertions for desktop navigation, connection handling and shutdown. On Windows, also run:

```powershell
dotnet run --project tests/SentinelAI.Desktop.Windows.Tests/SentinelAI.Desktop.Windows.Tests.csproj --configuration Release --runtime win-x64
bash ./scripts/publish-desktop-windows.sh
pwsh -NoLogo -NoProfile -NonInteractive -File tests/desktop/Windows.Acceptance.ps1 -ExecutablePath artifacts/desktop/win-x64/SentinelAI.Desktop.exe
```

The Windows test runner opens the actual WPF views and checks bindings, placeholder navigation, keyboard focus, representative window sizes, DPI awareness and disposal. The acceptance script launches the published executable, verifies its native window and navigation, and requests a graceful close. The dedicated Windows CI job runs both before uploading the application directory.

Physical scaling remains a practical manual check on a Windows desktop:

1. At 100%, 125%, 150% and 200% Windows display scaling, open the executable and resize between its minimum and a maximized window.
2. Visit each navigation item using the mouse and keyboard. Verify headings, descriptions, focus indicators and the connection strip remain readable; page content should scroll when space is limited.
3. If monitors use different scaling, move the window between them and repeat navigation and resizing. Text should remain sharp and controls should follow the destination monitor's scale.
4. Close the application during a connection check and verify that it exits promptly.

Logical window-size tests and DPI-context checks do not simulate every physical monitor configuration. Record the actual Windows test results before marking native launch acceptance complete.
