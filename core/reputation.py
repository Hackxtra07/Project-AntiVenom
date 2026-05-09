import hashlib
import mmap
import time
from pathlib import Path
from enum import IntEnum
from database.manager import DBManager

class ReputationLevel(IntEnum):
    TRUSTED = 0
    UNKNOWN = 1
    SUSPICIOUS = 2
    MALICIOUS = 3

class ReputationEngine:
    def __init__(self, db: DBManager):
        self.db = db

    def get_reputation(self, file_path: Path):
        sha256 = self._compute_sha256(file_path)
        cached = self.db.get_reputation(sha256)
        
        if cached:
            # Check if cache is still fresh (24h)
            # row['last_updated'] should be compared
            return cached

        # Fallback to cloud lookup (placeholder)
        rep = self._cloud_lookup(sha256, file_path)
        self.db.update_reputation(sha256, rep['level'], rep['score'], rep['source'])
        return rep

    def _compute_sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                if path.stat().st_size > 0:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        h.update(mm)
                else:
                    return hashlib.sha256(b"").hexdigest()
        except (ValueError, OSError): # Handle empty files or mmap errors
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
        return h.hexdigest()

    def _cloud_lookup(self, sha256: str, path: Path):
        # Implementation for VirusTotal or other APIs would go here
        return {
            "sha256": sha256,
            "level": ReputationLevel.UNKNOWN,
            "score": 0.5,
            "source": "initial_scan"
        }
