import shutil
import os
import uuid
from pathlib import Path
from config import QUARANTINE_DIR

class QuarantineManager:
    def __init__(self, db):
        self.db = db
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    def quarantine_file(self, file_path: Path) -> str:
        """Move a file to quarantine and return its new ID."""
        if not file_path.exists():
            return None
        
        q_id = str(uuid.uuid4())
        dest = QUARANTINE_DIR / q_id
        
        try:
            # Move file
            shutil.move(str(file_path), str(dest))
            # Set restrictive permissions
            os.chmod(str(dest), 0o000)
            
            self.db.add_alert(f"File Quarantined: {file_path.name}", {"original_path": str(file_path), "quarantine_id": q_id}, severity="CRITICAL")
            return q_id
        except Exception as e:
            self.db.add_alert(f"Failed to quarantine {file_path.name}: {e}", severity="ERROR")
            return None

    def restore_file(self, q_id: str, original_path: str):
        src = QUARANTINE_DIR / q_id
        if not src.exists():
            return False
            
        try:
            os.chmod(str(src), 0o644)
            shutil.move(str(src), original_path)
            self.db.add_alert(f"File Restored: {Path(original_path).name}", severity="INFO")
            return True
        except Exception as e:
            self.db.add_alert(f"Failed to restore {q_id}: {e}", severity="ERROR")
            return False
