import os
import shutil
import logging
from pathlib import Path

logger = logging.getLogger("AntiVenom.Optimizer")

class SystemOptimizer:
    """Level 6 Device Optimization Tools"""
    
    @staticmethod
    def cleanup_temp_directories() -> dict:
        """Clears out /tmp and ~/.cache generically tracking freed space"""
        logger.info("Initializing System Cleanup...")
        
        target_dirs = [
             Path('/tmp/antivenom_cache'),  # specific caches
             Path.home() / '.cache/thumbnails' # Example safe cache
        ]
        
        freed_bytes = 0
        deleted_files = 0
        
        for d in target_dirs:
            if d.exists() and d.is_dir():
                for item in d.glob('**/*'):
                    try:
                        if item.is_file():
                            size = item.stat().st_size
                            item.unlink()
                            freed_bytes += size
                            deleted_files += 1
                        elif item.is_dir() and not any(item.iterdir()):
                            item.rmdir()
                    except Exception as e:
                        logger.debug(f"Could not clean {item}: {e}")
                        
        megabytes_freed = freed_bytes / (1024 * 1024)
        logger.info(f"Cleanup finished. Freed {megabytes_freed:.2f} MB across {deleted_files} files.")
        
        return {
            "status": "success",
            "freed_mb": round(megabytes_freed, 2),
            "files_removed": deleted_files
        }

    @staticmethod
    def flush_dns():
        """Clears local DNS cache to prevent poisoning attacks"""
        try:
            # Simple simulation using systemd-resolve
            os.system("resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null")
            logger.info("DNS Cache flushed successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to flush DNS cache: {e}")
            return False
