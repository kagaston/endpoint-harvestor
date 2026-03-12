import hashlib
from pathlib import Path

from logger import get_logger

log = get_logger("utils.hashing")

BLOCK_SIZE = 65536


def hash_file(path: str | Path, algorithms: list[str] | None = None) -> dict[str, str]:
    algorithms = algorithms or ["md5", "sha1", "sha256"]
    hashers = {}
    for algo in algorithms:
        try:
            hashers[algo] = hashlib.new(algo)
        except ValueError:
            log.warning("Unsupported hash algorithm: %s", algo)

    file_path = Path(path)
    if not file_path.is_file():
        log.warning("File not found for hashing: %s", path)
        return {algo: "" for algo in algorithms}

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(BLOCK_SIZE):
                for h in hashers.values():
                    h.update(chunk)
    except (PermissionError, OSError) as e:
        log.warning("Cannot read file for hashing %s: %s", path, e)
        return {algo: "" for algo in algorithms}

    return {algo: h.hexdigest() for algo, h in hashers.items()}


def hash_string(data: str, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data.encode()).hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()
