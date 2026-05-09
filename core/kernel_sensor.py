import time
import psutil
import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger("AntiVenom.Kernel")

class KernelSensor:
    """
    Simulates ring-0 syscall interception (like eBPF or Fanotify).
    Since true eBPF requires kernel-headers and root compilation, this engine
    uses ultra-high frequency differential process delta matching to catch 
    executions in near real-time, feeding events back to the user-space behavioral monitor.
    """
    def __init__(self, callback: Callable[[dict], None]):
        self.callback = callback
        self.is_running = False
        self._known_pids = set()

    def start(self):
        if self.is_running:
            return
        
        self.is_running = True
        logger.info("Initializing High-Speed Kernel Sensor (Simulated sys_execve Hook)...")
        
        # Pre-warm the cache
        self._known_pids = set(psutil.pids())
        
        threading.Thread(target=self._monitor_execve, daemon=True).start()

    def stop(self):
        self.is_running = False

    def _monitor_execve(self):
        """
        Polls the OS at high speeds looking for newly launched processes.
        Acts as the primary injection hook for the Behavioral engine.
        """
        while self.is_running:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self._known_pids
                
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        cmdline = proc.cmdline()
                        name = proc.name()
                        exe = proc.exe()
                        
                        event = {
                            "type": "EXECVE",
                            "pid": pid,
                            "name": name,
                            "exe": exe,
                            "cmdline": cmdline,
                            "timestamp": time.time()
                        }
                        # Fire event down the telemetry pipeline
                        self.callback(event)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                
                self._known_pids = current_pids
                # Ultra fast polling (10ms) to simulate hardware interrupts
                time.sleep(0.01)
                
            except Exception as e:
                logger.error(f"Kernel Monitor Execution Error: {e}")
                time.sleep(1)
