import os
import shutil
import time
import logging
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("AntiVenom.Rollback")

class RollbackEngine:
    """
    Simulates SentinelOne's 1-Click Rollback.
    Monitors high-value target (HVT) directories and takes immediate shadow-copies
    when behavioral heuristics detect possible massive file encryption.
    """
    def __init__(self, alert_callback: Callable[[str, dict, str], None]):
        self.alert_callback = alert_callback
        self.shadow_dir = Path(__file__).resolve().parent.parent / "shadow_copies"
        self.shadow_dir.mkdir(parents=True, exist_ok=True)
        self.protected_paths = [
            Path.home() / "Documents",
            Path.home() / "Downloads"
        ]
        self._snapshots = {}

    def start(self):
        logger.info("Initializing 1-Click Rollback Engine...")
        self._take_snapshot() # Baseline

    def stop(self):
        pass

    def _take_snapshot(self):
        """Creates an instantaneous shadow copy of critical directories."""
        snapshot_id = int(time.time())
        snapshot_path = self.shadow_dir / str(snapshot_id)
        snapshot_path.mkdir(exist_ok=True)
        
        for path in self.protected_paths:
            if not path.exists():
                continue
            dest = snapshot_path / path.name
            try:
                # Highly intensive operation, in real EDR this relies on Volume Shadow Copies.
                # Simulated via fast shutil.copytree offline
                shutil.copytree(path, dest, dirs_exist_ok=True)
                logger.info(f"Shadow copy generated for {path} at ID: {snapshot_id}")
            except Exception as e:
                logger.debug(f"Shadow copy failed for {path}: {e}")
                
        self._snapshots[snapshot_id] = snapshot_path

    def trigger_rollback(self):
        """
        Invoked when Ransomware behavior is detected (e.g. mass encryption).
        Overwrites current corrupted files with the latest structural snapshot.
        """
        if not self._snapshots:
            logger.error("Rollback failed. No shadow copies available.")
            return False
            
        latest_id = sorted(self._snapshots.keys())[-1]
        snapshot_path = self._snapshots[latest_id]
        
        logger.warning("RANSOMWARE ROLLBACK INITIATED")
        
        try:
            for path in self.protected_paths:
                if not path.exists():
                    continue
                backup_src = snapshot_path / path.name
                if backup_src.exists():
                    # 1. Destroy corrupted state
                    shutil.rmtree(path, ignore_errors=True)
                    # 2. Restore uncorrupted state from Shadow
                    shutil.copytree(backup_src, path)
            
            logger.info("Ransomware Rollback Successful. Assets recovered.")
            self.alert_callback("1-Click Rollback Successful", {"forensics": "[Shadow Copy restored successfully post-encryption]"}, "INFO")
            return True
            
        except Exception as e:
            logger.error(f"Rollback critical failure: {e}")
            self.alert_callback("1-Click Rollback FAILED", {"forensics": str(e)}, "CRITICAL")
            return False
