import time
import logging
import threading
import psutil
from pathlib import Path
from typing import Callable

logger = logging.getLogger("AntiVenom.Privacy")

class PrivacyMonitor:
    """Level 5 Privacy Protection: Webcam & Microphone Access Monintoring"""
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.running = False
        self.thread = threading.Thread(target=self._monitor_devices, daemon=True)
        
        # Commonly trusted processes (Firefox, Chrome, Zoom, etc.)
        self.whitelist_apps = {"chrome", "firefox", "zoom", "teams", "skype", "obs", "discord", "slack"}
        
        # Audio/Video device paths in Linux
        self.sensitive_devices = []
        for i in range(5):
            if Path(f"/dev/video{i}").exists():
                self.sensitive_devices.append(f"/dev/video{i}")
        
        # If no video devices found, add it anyway for robust checking in case it gets plugged in later
        if not self.sensitive_devices:
            self.sensitive_devices.append("/dev/video0")
            
    def _monitor_devices(self):
        logger.info("Initializing Privacy Shield (Mic/Webcam Tracker)...")
        while self.running:
            try:
                # To efficiently check which process uses /dev/video0 without full lsof (which requires root often),
                # we can iterate over processes and check their open files, if accessible.
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        open_files = proc.open_files()
                        for f in open_files:
                            if any(dev in f.path for dev in self.sensitive_devices):
                                pname = proc.name().lower()
                                
                                # Is this an unauthorized app using the camera?
                                if not any(w in pname for w in self.whitelist_apps):
                                    self.alert_callback(
                                        f"PRIVACY BREACH DETECTED: Untrusted app '{proc.name()}' (PID {proc.pid}) is accessing your Webcam/Microphone at {f.path}!",
                                        severity="CRITICAL"
                                    )
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
            except Exception as e:
                logger.error(f"Privacy Monitor error: {e}")
                
            time.sleep(3)

    def start(self):
        self.running = True
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread.is_alive():
            self.thread.join(timeout=2)
