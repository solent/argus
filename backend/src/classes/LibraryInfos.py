from dataclasses import dataclass, field
import re
from typing import List, Optional, Dict, Tuple
from datetime import datetime, timezone
import time
import requests
import json

from packaging.version import parse as parse_version, InvalidVersion

from .OpenRouter import OpenRouter, ModelConfig
from .CVE import CVE
from .config import NVD_API_KEY, Config


# ============================================================
# Utils
# ============================================================

def _safe_parse_version(v: Optional[str]):
    if not v:
        return None
    try:
        return parse_version(v)
    except InvalidVersion:
        return None


def normalize_version(v: str) -> str:
    if not v:
        return v
    v = re.sub(r'^[^\d]+', '', v)
    v = v.replace('_', '.').replace('-', '.')
    v = re.sub(r'[^0-9\.]', '', v)
    return v


def _extract_vendor_from_cpe(cpe_uri: str) -> Optional[str]:
    """Extract vendor from CPE 2.3 or 2.2."""
    parts = cpe_uri.replace("\\:", "&&&").split(":")
    if cpe_uri.startswith("cpe:2.3") and len(parts) > 3:
        return parts[3]
    if cpe_uri.startswith("cpe:/") and len(parts) > 2:
        return parts[2]
    return None


def _parse_cpe_parts(criteria: str) -> Optional[List[str]]:
    """Return CPE 2.3 parts or None if not a valid cpe:2.3 URI."""
    if criteria.startswith("cpe:2.3:"):
        return criteria.split(":")
    return None


# ============================================================
# NVD Database
# ============================================================

@dataclass
class CVEDatabase:
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: Optional[str] = None
    last_request_time: float = 0.0

    # ----------------------------------------------------------
    # Rate limiting
    # ----------------------------------------------------------

    def _respect_rate_limit(self) -> None:
        min_interval = 0.6 if self.api_key else 6.0
        elapsed = time.time() - self.last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_request_time = time.time()

    # ----------------------------------------------------------
    # CVSS helpers
    # ----------------------------------------------------------

    @staticmethod
    def _severity_from_score(score: Optional[float]) -> str:
        if score is None:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"

    def _extract_cvss(self, metrics: dict) -> Tuple[Optional[float], str]:
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if metrics.get(key):
                data = metrics[key][0]["cvssData"]
                return data.get("baseScore"), data.get("baseSeverity", "UNKNOWN")

        if metrics.get("cvssMetricV2"):
            score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore")
            return score, self._severity_from_score(score)

        return None, "UNKNOWN"

    # ----------------------------------------------------------
    # CPE helpers
    # ----------------------------------------------------------

    def _extract_product_from_cpe(self, cpe: dict) -> str:
        """Return the product field (index 4) from a CPE 2.3 criteria string."""
        parts = _parse_cpe_parts(cpe.get("criteria", ""))
        # cpe:2.3 : <part> : <vendor> : <product> : ...
        #  idx 0     1        2          3            4 = version
        # NB: index 3 is vendor, index 4 is product in cpe:2.3
        if parts and len(parts) > 4:
            return parts[4]
        return "UNKNOWN"

    def _extract_affected_versions(self, cpe: dict) -> List[str]:
        """
        Return a human-readable list of affected versions for a given CPE match.

        Resolution order:
        1. Version range fields (versionStart*/versionEnd*)  → formatted range string
        2. Exact version from CPE criteria                   → single version string
        3. AI fallback via OpenRouter                        → list of versions

        "ALL / Unspecified" is only appended as a last resort when even the AI
        returns nothing, so it never accidentally blocks the AI fallback.
        """
        product = self._extract_product_from_cpe(cpe)

        # 1. Range-based extraction
        vsi = cpe.get("versionStartIncluding")
        vse = cpe.get("versionStartExcluding")
        vei = cpe.get("versionEndIncluding")
        vee = cpe.get("versionEndExcluding")

        if any([vsi, vse, vei, vee]):
            start = f"[{vsi}," if vsi else f"({vse}," if vse else "[,"
            end   = f"{vei}]" if vei else f"{vee})" if vee else ",]"
            return [start + end]

        # 2. Exact version from CPE criteria
        parts = _parse_cpe_parts(cpe.get("criteria", ""))
        if parts and len(parts) > 5:
            v = parts[5]
            if v not in {"*", "-"}:
                return [v]
            # wildcard → fall through to AI

        # 3. AI fallback
        ai_versions = self._ai_fallback_versions(product, cpe)
        if ai_versions:
            return ai_versions

        # 4. Ultimate fallback
        return ["ALL / Unspecified"]

    def _ai_fallback_versions(self, product: str, cpe: dict) -> List[str]:
        """Ask the configured LLM to suggest affected versions when NVD data is absent."""
        prompt = f"""You are a software security expert.

Context:
- Library / product: {product}
- CPE metadata: {json.dumps(cpe)}

Task:
Suggest a list of affected versions of this library based on public knowledge,
known CVEs, release history, or typical versioning patterns.
If unknown, respond with an empty list.

Respond ONLY with valid JSON, no markdown, no preamble:
{{"affected_versions": ["<version1>", "<version2>"]}}
"""
        try:
            client = OpenRouter(
                api_key=Config.model_cloud.api_key,
                default_model=Config.model_cloud.name,
                base_url=Config.model_cloud.base_url or "https://openrouter.ai/api/v1",
            )
            response = client.ask(prompt)
            result = json.loads(response.content)
            ai_versions = result.get("affected_versions", [])
            if isinstance(ai_versions, list):
                return [str(v) for v in ai_versions if v]
        except Exception as exc:
            print(f"[AI fallback] error for {product}: {exc}")
        return []

    # ----------------------------------------------------------
    # CVE parsing
    # ----------------------------------------------------------

    def _is_version_in_cpe_range(self, dep_v, cpe: dict) -> bool:
        """Return True if dep_v falls within the version range defined by a CPE match entry."""
        start_inc = _safe_parse_version(normalize_version(cpe.get("versionStartIncluding") or ""))
        start_exc = _safe_parse_version(normalize_version(cpe.get("versionStartExcluding") or ""))
        end_inc   = _safe_parse_version(normalize_version(cpe.get("versionEndIncluding") or ""))
        end_exc   = _safe_parse_version(normalize_version(cpe.get("versionEndExcluding") or ""))

        has_range = any([start_inc, start_exc, end_inc, end_exc])
        if not has_range:
            return False

        if start_inc and dep_v < start_inc:
            return False
        if start_exc and dep_v <= start_exc:
            return False
        if end_inc   and dep_v > end_inc:
            return False
        if end_exc   and dep_v >= end_exc:
            return False
        return True

    def _is_version_exact_match(self, dep_v, cpe: dict) -> bool:
        """Return True if dep_v matches the exact version embedded in CPE criteria."""
        parts = _parse_cpe_parts(cpe.get("criteria", ""))
        if parts and len(parts) > 5:
            cpe_ver = _safe_parse_version(normalize_version(parts[5]))
            if cpe_ver and dep_v == cpe_ver:
                return True
        return False

    def _cpe_matches_version(self, dep_v, cpe: dict) -> bool:
        return (
            self._is_version_in_cpe_range(dep_v, cpe)
            or self._is_version_exact_match(dep_v, cpe)
        )

    def _parse_cve(
        self,
        cve_item: dict,
        version: str,
        vendor: Optional[str],
    ) -> Optional[CVE]:
        dep_v = _safe_parse_version(normalize_version(version))
        if not dep_v:
            return None

        metrics = cve_item.get("metrics", {})
        cvss_score, severity = self._extract_cvss(metrics)

        affected_versions: List[str] = []
        is_vulnerable = False

        for config in cve_item.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if not cpe.get("vulnerable", False):
                        continue

                    # Optional vendor filter
                    if vendor:
                        cpe_vendor = _extract_vendor_from_cpe(cpe.get("criteria", ""))
                        if cpe_vendor and cpe_vendor.lower() != vendor.lower():
                            continue

                    affected_versions.extend(self._extract_affected_versions(cpe))

                    if self._cpe_matches_version(dep_v, cpe):
                        is_vulnerable = True
                        break

                if is_vulnerable:
                    break
            if is_vulnerable:
                break

        if not is_vulnerable:
            return None

        desc_list = cve_item.get("descriptions", [])
        description = desc_list[0]["value"] if desc_list else "No description available"

        return CVE(
            id=cve_item.get("id", "Unknown"),
            severity=severity,
            cvss=cvss_score if cvss_score is not None else 0.0,
            description=description,
            published_date=cve_item.get("published", ""),
            affected_versions=affected_versions,
        )

    # ----------------------------------------------------------
    # Public search
    # ----------------------------------------------------------

    def search_cves(
        self,
        library_name: str,
        version: str = "unknown",
        vendor: Optional[str] = None,
    ) -> List[CVE]:
        self._respect_rate_limit()

        headers = {"apiKey": self.api_key} if self.api_key else {}
        query = f"{vendor} {library_name}" if vendor else library_name

        response = requests.get(
            self.base_url,
            params={"keywordSearch": query, "resultsPerPage": 50},
            headers=headers,
            timeout=40,
        )
        if response.status_code != 200:
            return []

        results: List[CVE] = []
        for vuln in response.json().get("vulnerabilities", []):
            cve = self._parse_cve(vuln.get("cve", {}), version, vendor)
            if cve:
                results.append(cve)
        return results


# ============================================================
# High-level API
# ============================================================

@dataclass
class VulnerabilityResult:
    library_name: str
    version: str
    cves: List[CVE]
    checked_at: str


@dataclass
class LibraryInfos:
    name: str
    vendor: Optional[str] = None
    version: str = "unknown"
    source: str = "unknown"       # FetchContent, find_package, ExternalProject, pkg-config
    cves: List[CVE] = field(default_factory=list)
    git_repo: Optional[str] = None
    options: Dict[str, str] = field(default_factory=dict)
    checked_at: Optional[str] = None

    @staticmethod
    def from_dict(data: dict) -> "LibraryInfos":
        return LibraryInfos(
            name=data["name"],
            vendor=data.get("vendor"),
            version=data.get("version", "unknown"),
            source=data.get("source", "unknown"),
            cves=[CVE.from_dict(c) for c in data.get("cves", [])],
            git_repo=data.get("git_repo"),
            options=data.get("options", {}),
            checked_at=data.get("checked_at"),
        )

    def fetch_cves(self) -> None:
        db = CVEDatabase(api_key=NVD_API_KEY)
        cves = db.search_cves(self.name, self.version, self.vendor)
        if not cves:
            return

        for cve in cves:
            cve.fetch_exploit_db()

        self.cves = cves
        self.checked_at = datetime.now(timezone.utc).isoformat()