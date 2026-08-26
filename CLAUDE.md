# Maze Security — build & conventions

Root-free Android pentest toolkit. Kotlin + Jetpack Compose, manual DI (no Hilt).

## Build
- App: `./gradlew :app:assembleDebug` (JDK 17+, ANDROID_HOME set).
- Native tools: `native-tools/build.sh` (needs `ANDROID_NDK_HOME`). Outputs to
  `app/src/main/jniLibs/<abi>/lib<tool>.so`; re-run the app build afterwards.
- Toolchain: AGP 8.7.3, Gradle 8.9, Kotlin 2.0.21, Compose BOM 2024.10.01,
  compileSdk 35, minSdk 26.

## Structure
- `AppContainer` (held by `MazeApp`) wires repositories + scanner engines.
- `SessionViewModel` is activity-scoped: holds target, selected tool, config,
  and live scan state; scans survive navigation.
- Add a tool: new `ScannerEngine` in `domain/scanner`, register in
  `AppContainer.engines`, add a `ToolType` entry (drives dashboard + config).
- Binary tools resolve their executable via `NativeBinaries.binary("<name>")`
  → `nativeLibraryDir/lib<name>.so`, and stream output through `ProcessRunner`.

## Conventions
- Kotlin scanners must stay root-free (sockets only). Binary tools must only
  pass unprivileged flags (nmap `-sT`, never `-sS`).
- All scan output flows as `ScanEvent`; structured hits become `Finding`s via
  each scanner's `parseLine`.
