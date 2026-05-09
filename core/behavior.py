import asyncio
import threading
import psutil
import logging
from typing import Dict, Any, Callable, List
from collections import deque
import time

from core.kernel_sensor import KernelSensor

logger = logging.getLogger("AntiVenom.Behavior")

class ProcessBehaviorMonitor:
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.baseline: Dict[int, Dict[str, Any]] = {}
        # Ransomware Shield: Track file modifications per process
        self.file_activity: Dict[int, deque] = {} 
        self.running = True
        self.loop = None
        
        # Link raw OS hooks
        self.kernel_sensor = KernelSensor(self._handle_kernel_event)
        
        self.thread = threading.Thread(target=self._run_loop, daemon=True)

    def _handle_kernel_event(self, event: dict):
        """High-priority hook for instant processing of kernel-level syscalls."""
        if "powershell" in event.get("name", "").lower() or "cmd.exe" in event.get("name", "").lower():
            if "-enc" in event.get("cmdline", []) or "bypass" in event.get("cmdline", []):
                self._auto_kill(event["pid"], f"Suspicious Shell Detonation: {event['name']}")
                self.alert_callback("Zero-Day Shell Blocked", {"forensics": f"[Kernel Event: {event['name']} launched with obfuscated args]"}, "CRITICAL")

    def start(self):
        self.kernel_sensor.start()
        self.thread.start()

    def stop(self):
        self.running = False
        self.kernel_sensor.stop()

    def _run_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._monitor_loop())

    async def _monitor_loop(self):
        while self.running:
            try:
                # Use basic attrs to avoid 'invalid attr name' issues
                for proc in psutil.process_iter(["pid", "name"]):
                    await self._analyze_process(proc)
                await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"Monitor error: {e}")

    async def _analyze_process(self, proc: psutil.Process):
        try:
            pid = proc.pid
            
            # Fetch stats explicitly to handle AccessDenied or missing attributes gracefully
            try:
                mem_info = proc.memory_info()
                current_rss = mem_info.rss
            except (psutil.AccessDenied, AttributeError):
                current_rss = 0

            try:
                connections = proc.connections(kind="inet")
                current_conns = len(connections)
            except (psutil.AccessDenied, AttributeError, psutil.Error):
                current_conns = 0
            
            try:
                open_files = proc.open_files()
                current_files = len(open_files)
                # Industry standard: check for unusual patterns of open files (Ransomware signature)
                if current_files > 50:
                    self.alert_callback(f"Ransomware Shield: {proc.name()} has {current_files} files open. Analysis required.", severity="WARNING")
            except (psutil.AccessDenied, psutil.Error):
                current_files = 0
            
            if pid not in self.baseline:
                self.baseline[pid] = {
                    "rss": current_rss,
                    "conns": current_conns,
                    "files": current_files
                }
                return

            base = self.baseline[pid]

            # Detect massive memory spike (e.g. key generation or packing)
            if base["rss"] > 0 and current_rss > 5 * base["rss"] and current_rss > 100 * 1024 * 1024:
                self.alert_callback(f"Massive Memory Injection: {proc.name()} (PID {pid}) spiked to {current_rss/(1024*1024):.1f}MB", severity="CRITICAL")
                self._kill_process(proc, "Memory Anomaly")
            
            # Detect sudden connection surge (C2 communication)
            if current_conns > base["conns"] + 15:
                self.alert_callback(f"C2 Threat Signal: {proc.name()} (PID {pid}) opened {current_conns} connections", severity="CRITICAL")
                # Connections alone might be false positive (like a browser), so we might just alert, not kill yet.

            # Ransomware Detection: Large increase in open file handles
            if current_files > base["files"] + 20:
                self.alert_callback(f"Ransomware Pattern: {proc.name()} rapidly accessing file system", severity="CRITICAL")
                self._kill_process(proc, "Ransomware Behavior")

            # Update baseline for next iteration
            self.baseline[pid] = {"rss": current_rss, "conns": current_conns, "files": current_files}

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _kill_process(self, proc: psutil.Process, reason: str):
        """EDR Automated Incident Response: Stop the threat immediately"""
        try:
            pid = proc.pid
            name = proc.name()
            proc.kill()
            self.alert_callback(f"EDR ACTION: Terminated {name} (PID {pid}). Reason: {reason}", severity="INFO")
            logger.warning(f"EDR System terminated {name} (PID {pid}) due to {reason}")
        except psutil.AccessDenied:
            self.alert_callback(f"EDR ACTION FAILED: Access Denied trying to terminate {proc.name()}. Requires elevated privileges.", severity="WARNING")
        except psutil.NoSuchProcess:
            pass
