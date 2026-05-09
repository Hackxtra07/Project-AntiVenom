#!/usr/bin/env python3
import time
import logging
import threading
import psutil
import uvicorn
import uuid
import socket
import platform
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import MONITOR_PATHS, YARA_RULES_DIR, API_HOST, API_PORT
from database.manager import DBManager
from core.scanner import AntiVenomScanner
from core.behavior import ProcessBehaviorMonitor
from core.deception import DeceptionEngine
from core.sandbox import SandboxEngine
from core.network_ids import NetworkIDS
from core.privacy import PrivacyMonitor
from core.rollback import RollbackEngine
from api.app import app, broadcast_alert

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("AntiVenom")

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner

    def on_created(self, event):
        if not event.is_directory:
            self.scanner.schedule_scan(Path(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self.scanner.schedule_scan(Path(event.src_path))

class AntiVenomSystem:
    def __init__(self):
        self.db = DBManager()
        self.host_id = str(uuid.uuid4())[:8] # Simplified for POC
        self.hostname = socket.gethostname()
        
        # Register host in fleet DB
        try:
            ip = socket.gethostbyname(self.hostname)
        except:
            ip = "127.0.0.1"
            
        self.db.register_host(self.host_id, self.hostname, ip)
        logger.info(f"Endpoint Registered [UUID: {self.host_id}] [Hostname: {self.hostname}]")
        
        # Behavior monitor callback bridges to DB and UI
        def alert_bridge(message, details=None, severity="INFO"):
            self.db.add_alert(message, details, severity)
            # Send to UI via WebSocket (async bridge needed)
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(broadcast_alert({
                        "message": message,
                        "details": details or {},
                        "severity": severity,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
                    }))
            except Exception:
                pass

        self.behavior = ProcessBehaviorMonitor(alert_callback=alert_bridge)
        self.deception = DeceptionEngine(alert_callback=alert_bridge)
        self.sandbox = SandboxEngine(alert_callback=alert_bridge)
        self.network_ids = NetworkIDS(alert_callback=alert_bridge)
        self.privacy = PrivacyMonitor(alert_callback=alert_bridge)
        self.rollback = RollbackEngine(alert_callback=alert_bridge)
        
        # Scanner now has access to the Sandbox for Zero-Day execution
        self.scanner = AntiVenomScanner(self.db, YARA_RULES_DIR, sandbox=self.sandbox)
        
        self.observer = Observer()
        self.process = psutil.Process() # Self-monitoring

    def _resource_monitor(self):
        """Monitor the AV's own resource usage (Critical for Enterprise)."""
        while True:
            try:
                cpu_usage = self.process.cpu_percent(interval=1.0)
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                
                # Tech Giant Thresholds: Alert if AV takes > 10% CPU or > 500MB RAM persistently
                if cpu_usage > 10.0 or memory_mb > 500:
                    logger.warning(f"Self-Resource Alert: CPU {cpu_usage}% | RAM {memory_mb:.1f}MB")
                
                time.sleep(30) # Check every 30s
            except Exception:
                break

    def start(self):
        logger.info("Initializing AntiVenom Industrial Defense System (Edition: Tech Giant)...")
        
        # Start Self-Resource Monitoring
        threading.Thread(target=self._resource_monitor, daemon=True).start()
        
        # 1. Start Behavior Monitor
        self.behavior.start()

        # 2. Start Deception Technology
        self.deception.start()
        
        # 3. Start Sandbox Environment
        self.sandbox.start()
        
        # 4. Start Network IDS
        self.network_ids.start()
        
        # 5. Start Privacy Monitor
        self.privacy.start()
        
        # 6. Start Rollback Engine (Shadow Copy Baseline)
        self.rollback.start()

        # 6. Start File System Observer
        handler = FileEventHandler(self.scanner)
        for path in MONITOR_PATHS:
            if path.exists():
                self.observer.schedule(handler, str(path), recursive=True)
                logger.info(f"Monitoring: {path}")

        self.observer.start()

        # 7. Start API Dashboard
        logger.info(f"Dashboard starting at http://{API_HOST}:{API_PORT}")
        app.state.system = self
        uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="error")

    def stop(self):
        self.observer.stop()
        self.observer.join()
        self.behavior.stop()
        self.deception.stop()
        self.sandbox.stop()
        self.network_ids.stop()
        self.privacy.stop()

if __name__ == "__main__":
    system = AntiVenomSystem()
    try:
        system.start()
    except KeyboardInterrupt:
        system.stop()
        logger.info("System shut down.")
