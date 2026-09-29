from pathlib import Path
from shutil import copy2

Import("env")

project_dir = Path(env.subst("$PROJECT_DIR"))
src_dir = Path(env.subst("$PROJECT_SRC_DIR"))
src_dir.mkdir(parents=True, exist_ok=True)

source = project_dir / "Homeserver_Autosetup_Modem_V1_USBHost.ino"
target = src_dir / source.name

if not source.is_file():
    raise RuntimeError(f"Missing Arduino sketch: {source}")

# Keep the Arduino sketch in the project root as the single source of truth.
# Copy it before PlatformIO runs ConvertInoToCpp so the normal Arduino prototype
# generation is preserved in the ESP-IDF/Arduino-component build as well.
if (not target.exists()
        or target.stat().st_size != source.stat().st_size
        or target.stat().st_mtime_ns != source.stat().st_mtime_ns):
    copy2(source, target)
