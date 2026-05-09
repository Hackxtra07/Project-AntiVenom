from concurrent.futures import ThreadPoolExecutor
import os
import yara
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from core.reputation import ReputationEngine, ReputationLevel
from core.static_analyzer import AIStaticAnalyzer
from core.quarantine import QuarantineManager

logger = logging.getLogger("AntiVenom.Scanner")

class AntiVenomScanner:
    def __init__(self, db, yara_rules_path: Optional[Path] = None, max_workers: Optional[int] = None, sandbox=None):
        self.db = db
        self.reputation = ReputationEngine(db)
        self.static_ai = AIStaticAnalyzer()
        self.quarantine = QuarantineManager(db)
        self.sandbox = sandbox
        self.yara_rules = None
        
        # Determine optimal workers based on CPU cores for Industrial efficiency
        self.max_workers = max_workers or (os.cpu_count() or 4)
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        
        if yara_rules_path and yara_rules_path.exists():
            try:
                # Assuming yara_rules_path is a directory or file
                filepaths = {}
                if yara_rules_path.is_dir():
                    for idx, yfile in enumerate(yara_rules_path.glob('**/*.yar*')):
                        filepaths[f'namespace_{idx}'] = str(yfile)
                else:
                    filepaths['default'] = str(yara_rules_path)

                if filepaths:
                    self.yara_rules = yara.compile(filepaths=filepaths)
                    logger.info(f"Industrial YARA Engine loaded {len(filepaths)} rulesets across {self.max_workers} threads")
            except Exception as e:
                logger.error(f"Failed to compile YARA rules: {e}")

    def schedule_scan(self, file_path: Path):
        """Asynchronously schedule a scan using the thread pool."""
        self.executor.submit(self._process_scan, file_path)

    def scan_file(self, file_path: Path) -> Dict[str, Any]:
        """Synchronous scan of a single file."""
        if not file_path.exists():
            return {"verdict": "missing", "reason": "file_deleted_before_scan"}

        # 1. Reputation Check
        try:
            rep = self.reputation.get_reputation(file_path)
            if rep['level'] == ReputationLevel.MALICIOUS:
                return {"verdict": "malicious", "reason": "reputation", "score": rep['score']}
        except FileNotFoundError:
            return {"verdict": "missing", "reason": "file_deleted_during_rep_check"}

        # 2. YARA Scan
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(str(file_path))
                if matches:
                    return {"verdict": "malicious", "reason": "yara", "matches": [m.rule for m in matches]}
            except Exception:
                pass

        # 3. AI Static Analysis
        try:
            ai_score, features = self.static_ai.analyze(file_path)
            if ai_score > 0.7:
                return {"verdict": "malicious", "reason": "ai_static", "score": ai_score, "features": features}
            
            if ai_score > 0.4:
                # File is suspicious. Use zero-day Sandbox execution to confirm.
                if self.sandbox and self.sandbox.is_ready:
                    logger.info(f"AI Score {ai_score:.2f} -> Routing {file_path.name} to Sandbox for execution.")
                    sandbox_result = self.sandbox.run_in_sandbox(file_path)
                    
                    if sandbox_result.get("malicious_indicators", False):
                        logger.warning(f"Sandbox confirmed THREAT in {file_path.name}")
                        return {"verdict": "malicious", "reason": "sandbox", "score": ai_score, "sandbox_logs": sandbox_result.get("logs", "")}
                
                return {"verdict": "suspicious", "reason": "ai_static", "score": ai_score}
        except FileNotFoundError:
            return {"verdict": "missing", "reason": "file_deleted_during_ai_check"}

        return {"verdict": "clean"}

    def _process_scan(self, file_path: Path):
        """Worker function for the executor - processes a single scan task."""
        try:
            verdict = self.scan_file(file_path)
            
            # Format Telemetry String
            telemetry = []
            if "features" in verdict:
                feats = verdict["features"]
                telemetry.append(f"[Entropy: {feats.get('entropy', 0):.2f}]")
                telemetry.append(f"[Type: {feats.get('real_type', 'Unknown')}]")
                if feats.get("macro_threat"):
                    telemetry.append(f"[VBA Macro Threat: TRUE]")
                for p in feats.get("pe_anomalies", []):
                    telemetry.append(f"[{p}]")
                for s in feats.get("hostile_strings", []):
                    telemetry.append(f"[String Indicator: {s}]")
                    
            inds_str = " ".join(telemetry) if telemetry else ""
            
            if verdict["verdict"] == "malicious":
                logger.warning(f"THREAT DETECTED: {file_path}")
                if inds_str:
                    logger.warning(f"Forensic Telemetry: {inds_str}")
                    verdict["forensics"] = inds_str # Attach to UI payload
                
                self.db.add_alert(f"Threat Detected: {file_path.name}", verdict, severity="CRITICAL")
                
                # Auto-quarantine if high confidence or signature match
                if verdict.get("score", 0) > 0.8 or verdict["reason"] == "yara":
                    self.quarantine.quarantine_file(file_path)
                    
            elif verdict["verdict"] == "suspicious":
                if inds_str:
                    logger.info(f"Suspicious Indicators: {inds_str}")
                    verdict["forensics"] = inds_str
                self.db.add_alert(f"Suspicious File: {file_path.name}", verdict, severity="WARNING")
        except Exception as e:
            # Handle transient file errors gracefully (especially in /tmp)
            if not isinstance(e, FileNotFoundError):
                logger.error(f"Parallel scan error for {file_path}: {e}")
