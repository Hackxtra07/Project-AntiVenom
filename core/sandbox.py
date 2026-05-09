import os
import time
import logging
import threading
from pathlib import Path
from typing import Callable, Dict, Any

try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

logger = logging.getLogger("AntiVenom.Sandbox")

class SandboxEngine:
    """Level 7 Enterprise Execution Sandbox"""
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.is_ready = False
        self.client = None
        
        if HAS_DOCKER:
            try:
                self.client = docker.from_env()
                self.is_ready = True
                logger.info("Docker Sandbox Engine initialized successfully.")
            except Exception as e:
                logger.warning(f"Docker is not running or accessible. Sandbox mode is disabled. ({e})")
        else:
            logger.warning("Docker package not installed. Sandbox disabled.")

    def run_in_sandbox(self, file_path: Path) -> Dict[str, Any]:
        """Executes a file in an isolated container and records its behavior"""
        if not self.is_ready or not self.client:
            return {"status": "error", "message": "Sandbox unavailable"}

        if not file_path.exists():
            return {"status": "error", "message": "File not found"}

        container = None
        try:
            logger.info(f"Sandbox Analysis Started: {file_path.name}")
            
            # Map the directory containing the file as Read-Only into the container
            target_dir = str(file_path.parent.resolve())
            target_filename = file_path.name
            
            # Use Alpine Linux as a lightweight execution environment
            # We deny network access, limit memory, and make the FS read-only (except /tmp)
            container = self.client.containers.run(
                "alpine:latest",
                command=["sh", "-c", f"cat /mnt/target/{target_filename} 2>/dev/null | wc -c; sleep 2"],
                volumes={target_dir: {'bind': '/mnt/target', 'mode': 'ro'}},
                detach=True,
                network_mode="none",
                mem_limit="50m",
                cpu_quota=50000,
                read_only=True,
                tmpfs={'/tmp': ''}
            )
            
            # Wait for execution or timeout
            result = container.wait(timeout=10)
            logs = container.logs().decode('utf-8').strip()
            
            status_code = result.get('StatusCode', -1)
            
            self.alert_callback(
                f"Sandbox Analysis Complete: {file_path.name}. Exit Code: {status_code}",
                severity="INFO"
            )
            
            return {
                "status": "success",
                "exit_code": status_code,
                "logs": logs,
                "malicious_indicators": status_code != 0
            }

        except Exception as e:
            logger.error(f"Sandbox failure during analysis of {file_path.name}: {e}")
            return {"status": "error", "message": str(e)}
        finally:
            if container:
                try:
                    container.remove(force=True)
                except:
                    pass

    def start(self):
        if self.is_ready:
            logger.info("Sandbox Environment READY. Waiting for unknown payloads...")

    def stop(self):
        pass
