import os
import time
import logging
import threading
from pathlib import Path
from typing import Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("AntiVenom.Deception")

class HoneypotHandler(FileSystemEventHandler):
    def __init__(self, alert_callback: Callable, honeypots: list):
        self.alert_callback = alert_callback
        self.honeypots = [str(Path(h).resolve()) for h in honeypots]

    def _check_and_alert(self, event):
        path = str(Path(event.src_path).resolve())
        if path in self.honeypots:
            self.alert_callback(
                f"DECEPTION TRIGGERED: Honeypot '{Path(path).name}' was unexpectedly accessed or modified! Ransomware/Stealer activity highly probable.", 
                severity="CRITICAL"
            )

    def on_modified(self, event):
        if not event.is_directory:
            self._check_and_alert(event)

    def on_deleted(self, event):
        if not event.is_directory:
            self._check_and_alert(event)


class DeceptionEngine:
    """Level 7 Enterprise Deception Technology (Honeypots)"""
    def __init__(self, alert_callback: Callable, bait_dir: str = "/tmp/antivenom_vault"):
        self.alert_callback = alert_callback
        self.bait_dir = Path(bait_dir)
        self.observer = Observer()
        self.honeypot_files = [
            self.bait_dir / "passwords_backup.txt",
            self.bait_dir / "bitcoin_wallet.dat",
            self.bait_dir / "financial_q4_confidential.pdf"
        ]

    def _deploy_baits(self):
        """Create the tempting files that malware seeks out"""
        self.bait_dir.mkdir(parents=True, exist_ok=True)
        
        for h_file in self.honeypot_files:
            try:
                # Create fake content
                if not h_file.exists():
                    with open(h_file, 'w') as f:
                        if ".txt" in h_file.name:
                            f.write("admin:P@ssw0rd123!\nroot:super_secret")
                        elif ".dat" in h_file.name:
                            f.write("0x1A2B3C4D5E6F7A8B9C0")
                        else:
                            f.write("%PDF-1.4\n% Fake PDF Header")
                logger.debug(f"Deployed honeypot: {h_file}")
            except Exception as e:
                logger.error(f"Failed to deploy honeypot {h_file}: {e}")

    def start(self):
        logger.info("Initializing Deception Technology (Honeypot Engine)...")
        self._deploy_baits()
        
        handler = HoneypotHandler(self.alert_callback, self.honeypot_files)
        self.observer.schedule(handler, str(self.bait_dir), recursive=False)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
        
        # Cleanup baits
        for h_file in self.honeypot_files:
            if h_file.exists():
                try:
                    h_file.unlink()
                except:
                    pass
        try:
            self.bait_dir.rmdir()
        except:
            pass
