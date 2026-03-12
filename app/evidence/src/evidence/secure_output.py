from pathlib import Path

import pyzipper

from logger import get_logger

log = get_logger("evidence.secure_output")


def create_secure_package(
    source_dir: Path,
    output_path: Path | None = None,
    password: str = "",
) -> Path:
    source_dir = Path(source_dir)
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    if output_path is None:
        output_path = source_dir.parent / f"{source_dir.name}_evidence.zip"

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    files = sorted(f for f in source_dir.rglob("*") if f.is_file())
    if not files:
        raise ValueError(f"No files found in {source_dir}")

    log.info("Creating secure evidence package: %s (%d files)", output_path, len(files))

    if password:
        pwd = password.encode("utf-8")
        with pyzipper.AESZipFile(
            output_path,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(pwd)
            for file_path in files:
                arcname = str(file_path.relative_to(source_dir))
                zf.write(file_path, arcname)
        log.info("Encrypted evidence package created: %s (AES-256)", output_path)
    else:
        with pyzipper.AESZipFile(
            output_path,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
        ) as zf:
            for file_path in files:
                arcname = str(file_path.relative_to(source_dir))
                zf.write(file_path, arcname)
        log.info("Evidence package created (unencrypted): %s", output_path)

    return output_path


def extract_secure_package(
    package_path: Path,
    output_dir: Path,
    password: str = "",
) -> Path:
    package_path = Path(package_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    pwd = password.encode("utf-8") if password else None
    with pyzipper.AESZipFile(package_path, "r") as zf:
        if pwd:
            zf.setpassword(pwd)
        zf.extractall(output_dir)

    log.info("Evidence package extracted to %s", output_dir)
    return output_dir
