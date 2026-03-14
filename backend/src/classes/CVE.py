from dataclasses import dataclass
from typing import Optional
from .config import EXPLOITDB_DIR, CSV_PATH
import pandas as pd

# =========================
# CVE
# =========================

@dataclass
class CVE:
    id: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    cvss: float
    description: str
    published_date: str
    exploit_db: Optional[str] = None
    affected_versions: Optional[str] = None


    @staticmethod
    def from_dict(data: dict) -> "CVE":
        return CVE(
            id=data["id"],
            severity=data["severity"],
            cvss=data["cvss"],
            description=data["description"],
            published_date=data["published_date"],
            exploit_db=data.get("exploit_db"),
            affected_versions=data.get("affected_versions"),
        )
    
    def fetch_exploit_db(self) -> None:
        """
        Récupère un descriptif d'exploit depuis ExploitDB
        (stub – à brancher sur une vraie source)
        """
        # Exemple volontairement simple
        if not CSV_PATH.exists():
            raise FileNotFoundError(f"ExploitDB CSV missing: {CSV_PATH}")

        data = pd.read_csv(CSV_PATH, usecols=["file", "codes"])

        arr_codes = data["codes"].to_numpy()
        processed_names = [
            [part for part in str(element).split(";") if part.startswith("CVE")]
            for element in arr_codes
        ]
        paths_cves = data["file"].to_numpy()


        for i, cves in enumerate(processed_names):
            if not cves:
                continue

            if self.id in cves:
                exploit_path = EXPLOITDB_DIR / paths_cves[i]
                if exploit_path.exists():
                    self.exploit_db = exploit_path.read_text(
                        errors="ignore"
                    )
