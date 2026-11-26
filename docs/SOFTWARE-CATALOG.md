# Software catalog

Open **Software catalog** in Desktop to search by application name or publisher. Search is case-insensitive and treats punctuation literally. Select a product to see its recorded versions and architectures on individual endpoints. The change view can show the selected product or the whole fleet, including products that have disappeared from the current catalog.

The catalog uses the latest accepted software observation from each enrolled endpoint. The Windows Agent reads machine-wide entries from the 32-bit and 64-bit uninstall registry views. The source covers visible application entries with a name. Per-user and Store apps, hidden components, patch entries and software without a corresponding registry entry are outside this scope. Core stores name, publisher, version and architecture from this source. See [Endpoint telemetry](ENDPOINT-TELEMETRY.md).

Core groups a product by its case-folded name and publisher. It regards an unknown publisher as a separate group. Versions are kept as reported by the vendor, and multiple versions or architectures can appear on a device. A product's variant count is the number of distinct version and architecture pairs seen across the fleet.

Coverage shows how many active endpoints reported a complete or partial software scan and how many have unavailable or missing software data. Collected software data becomes stale after three hours. Partial and stale reports can still contribute observed applications. A new unavailable report leaves the endpoint without current rows. Use the coverage counters when interpreting zero search results.

## Changes

Core compares consecutive observations only when both software sections were collected with no truncation or reported skips. The first usable observation establishes a baseline. An incomplete or unavailable observation breaks the comparison. A subsequent complete observation establishes a new baseline. Older Agents could silently stop at their registry entry limit, so historical events describe the contents of the reports.

A change is **observed**, **no longer observed** or **variants changed**. View the collection time of each observation and the previous and new version and architecture pairs. The registry provides observations of entries. Confirmation of an installation, uninstall or upgrade requires separate evidence.

Change history retains up to 90 days from Core receipt time and up to 25,000 changes. Each event stores the first 12 distinct variants from each observation and the full variant counts. Removing an endpoint removes it from the current catalog. Retained observations expire normally. An upgrade or restore of older data populates the current catalog in the background from stored reports. History begins with subsequent accepted comparisons. A new backup includes the catalog and its retained history.

## Local API

The following routes require a local administrator session and return `Cache-Control: no-store`. The Agent network listener denies them. Each page accepts `offset` and `limit`. The default page size is 25 and the maximum is 50.

- `GET /api/admin/software-catalog?q=...` searches the catalog. Omit `q` to list all products.
- `GET /api/admin/software-catalog/{productId}/installations` lists variants and endpoints for one product.
- `GET /api/admin/software-catalog/changes?productId=...` filters changes by product. Omit `productId` for the fleet history.
