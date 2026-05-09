import time
import logging
import threading
import psutil
from typing import Callable

logger = logging.getLogger("AntiVenom.IDS")

class NetworkIDS:
    """Level 7 Intrusion Detection System (IDS) based on Connection Analysis"""
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.running = False
        self.is_isolated = False
        self.thread = threading.Thread(target=self._monitor_connections, daemon=True)
        # Mock Threat Intelligence Database (Blacklisted IPs)
        self.blacklist_ips = {"185.15.247.140", "198.51.100.23", "203.0.113.88", "104.16.14.15"}
        
        # Usually, internal C2 ports or obscure ports
        self.suspicious_ports = {1337, 31337, 4444, 4445, 6667, 8080}

    def isolate_host(self, enabled: bool):
        """Simulates CrowdStrike-style Host Isolation by severing network activity."""
        self.is_isolated = enabled
        status = "ISOLATED" if enabled else "CLEAN"
        logger.warning(f"NETWORK ISOLATION {'ACTIVATED' if enabled else 'DEACTIVATED'} for this host.")
        self.alert_callback(f"Host Isolation {status}", {"forensics": f"Host status changed to {status}"}, "CRITICAL" if enabled else "INFO")

    def _monitor_connections(self):
        logger.info("Initializing Intrusion Detection System (Network Monitor)...")
        while self.running:
            if self.is_isolated:
                # In a real EDR, we would have applied firewall rules.
                # Here we just slow down polling to simulate local containment.
                time.sleep(10)
                continue
            try:
                # psutil.net_connections requires root on some OSes depending on the kinds of connections.
                # However, user-level can often see user's own connections which is standard for an endpoint agent.
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # 1. Check against Threat Intel Blacklist
                        if remote_ip in self.blacklist_ips:
                            pid = conn.pid
                            pname = "Unknown"
                            if pid:
                                try:
                                    pname = psutil.Process(pid).name()
                                except:
                                    pass
                            
                            self.alert_callback(
                                f"IDS ALERT: Blocked outbound connection to Blacklisted Malicious IP {remote_ip} by {pname} (PID: {pid})",
                                severity="CRITICAL"
                            )
                            # EDR Mitigation: Terminate process communicating with C2
                            if pid:
                                try:
                                    psutil.Process(pid).kill()
                                    self.alert_callback(f"IDS Auto-Mitigation: Terminated {pname} to sever C2 connection.", severity="INFO")
                                except:
                                    pass

                        # 2. Heuristic check for suspicious outbound ports
                        if remote_port in self.suspicious_ports:
                            pid = conn.pid
                            self.alert_callback(
                                f"IDS WARNING: Process (PID: {pid}) using suspicious outbound port {remote_port} -> {remote_ip}",
                                severity="WARNING"
                            )

            except psutil.AccessDenied:
                # Fallback if strict restrictions are in place
                pass
            except Exception as e:
                logger.error(f"IDS Error: {e}")
                
            time.sleep(5) # Poll interval

    def start(self):
        self.running = True
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread.is_alive():
            self.thread.join(timeout=2)
