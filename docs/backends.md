# Backend development

Backends are in-process adapters compiled into the single `xrayctl` binary.
There is deliberately no Rust DLL/SO plugin ABI.

## Dependency rule

`xray-manager-core` owns domain types, use cases and ports. A backend belongs in
`xray-manager-platform`, depends on core, and must not introduce a reverse
dependency. `xrayctl` is the composition root.

## Adding a backend

1. Implement only the smallest applicable port, such as `ServiceManager`,
   `FirewallManager`, or `DesktopProxyManager`. Do not implement a monolithic
   platform object.
2. Keep command construction and OS APIs inside the adapter. Core use cases
   operate on semantic requests.
3. Add a `BackendFactory` descriptor with a stable ID, contract version,
   capabilities, platform, requirements, a non-mutating availability probe,
   and a `create` implementation returning the requested typed
   `BackendComponent`.
4. Register the factory only under the applicable target `cfg`.
5. The composition root asks the registry to instantiate the resolved
   components; it does not match concrete backend IDs. Test/fake factories must
   never be registered by the production root.
6. Run the registry contract suite and add template/plan tests that require no
   elevated privileges.

## Compatibility rules

- A requested but uncompiled backend is an error.
- An unavailable explicit backend does not silently fall back.
- Normal operations may use only a backend whose probe succeeded. During
  install/repair, an automatically selected compiled backend with missing
  bootstrap dependencies remains instantiable only to produce a dry-run plan
  and an exact package-install hint; mutation is blocked until its probe
  succeeds.
- Install stores the selected backend IDs. Repair and removal reuse them.
- A missing capability returns `PlatformUnsupported` with a remediation.
- Target-specific crates belong under target-specific Cargo dependencies.

Potential future modules include Debian/APT, OpenRC, firewalld, GNOME proxy,
Windows Service, WinTUN/WFP and Windows system proxy adapters.
