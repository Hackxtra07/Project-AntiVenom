import math
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, Tuple, Optional
import logging

logger = logging.getLogger("AntiVenom.Static")

try:
    import magic
    import pefile
    from oletools.olevba import VBA_Parser
    HAS_DEEP_TOOLS = True
except ImportError:
    HAS_DEEP_TOOLS = False

class AIStaticAnalyzer:
    def __init__(self, model_path: Optional[Path] = None):
        self.model = None # Placeholder for ML model loading logic
        self.suspicious_strings = [
            b"vssadmin delete shadows",
            b"powershell -ExecutionPolicy Bypass",
            b"WannaCry",
            b"cmd.exe /c",
            b"certutil -urlcache",
            b"Invoke-WebRequest"
        ]

    def analyze(self, file_path: Path) -> Tuple[float, Dict[str, Any]]:
        features = self._extract_features(file_path)
        score = self._heuristic_score(features)
        return score, features

    def _extract_features(self, file_path: Path) -> Dict[str, Any]:
        size = file_path.stat().st_size
        entropy = self._calculate_entropy(file_path)
        
        real_type = "Unknown"
        if HAS_DEEP_TOOLS:
            try:
                real_type = magic.from_file(str(file_path))
            except:
                pass

        strings_found = self._extract_hostile_strings(file_path)
        pe_anomalies = self._check_pe_packed(file_path) if HAS_DEEP_TOOLS else []
        macro_threat = self._check_macros(file_path) if HAS_DEEP_TOOLS else False

        return {
            "size": size,
            "entropy": entropy,
            "extension": file_path.suffix.lower(),
            "real_type": real_type,
            "contains_pe_header": self._has_pe_header(file_path),
            "is_script": file_path.suffix.lower() in [".sh", ".py", ".js", ".php"],
            "hostile_strings": strings_found,
            "pe_anomalies": pe_anomalies,
            "macro_threat": macro_threat
        }

    def _calculate_entropy(self, path: Path, block_size: int = 4096) -> float:
        freq = defaultdict(int)
        total = 0
        try:
            with open(path, "rb") as f:
                while chunk := f.read(block_size):
                    for b in chunk:
                        freq[b] += 1
                        total += 1
        except Exception:
            return 0.0
            
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _has_pe_header(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(2) == b"MZ"
        except Exception:
            return False

    def _extract_hostile_strings(self, path: Path) -> list:
        found = []
        try:
            with open(path, "rb") as f:
                content = f.read(1024 * 1024) # Scan first MB only for speed
                for s in self.suspicious_strings:
                    if s in content:
                        found.append(s.decode('utf-8', 'ignore'))
        except Exception:
            pass
        return found

    def _check_pe_packed(self, path: Path) -> list:
        anomalies = []
        try:
            # Check if it's actually a PE file
            with open(path, "rb") as f:
                if f.read(2) != b"MZ":
                    return anomalies

            pe = pefile.PE(str(path))
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                if sec_name.lower() in ['upx0', 'upx1', '.aspack', '.nspack']:
                    anomalies.append(f"Packed Section: {sec_name}")
            pe.close()
        except Exception:
            pass
        return anomalies

    def _check_macros(self, path: Path) -> bool:
        if path.suffix.lower() not in [".doc", ".docm", ".xls", ".xlsm"]:
            return False
            
        try:
            vbaparser = VBA_Parser(str(path))
            if vbaparser.detect_vba_macros():
                macro_info = vbaparser.analyze_macros()
                vbaparser.close()
                for kw_type, keyword, description in macro_info:
                    if kw_type in ('Suspicious', 'AutoExec'):
                        return True
            vbaparser.close()
        except:
            pass
        return False

    def _heuristic_score(self, features: Dict[str, Any]) -> float:
        score = 0.0
        
        # 1. Advanced Entropy Analysis (Obfuscation Detection)
        if features["entropy"] > 7.6:
            score += 0.5
        elif features["entropy"] > 7.2:
            score += 0.2
            
        # 2. File size vs Signature ratio
        if features["size"] < 50000 and features["entropy"] > 7.0:
            score += 0.3
            
        # 3. Deep Analysis Indicators
        if features["macro_threat"]:
            score += 0.6
            
        if len(features["pe_anomalies"]) > 0:
            score += 0.4
            
        if len(features["hostile_strings"]) > 0:
            score += 0.5
            
        # 4. Header Anomaly (Executable segments in non-exe files)
        if features["contains_pe_header"] and features["extension"] not in [".exe", ".dll", ".bin", ".sys"] and features["extension"] != "":
            score += 0.4
            
        # 5. Script-based injection checks
        if features["is_script"] and features["size"] > 100000:
            score += 0.2
            
        return min(score, 1.0)
