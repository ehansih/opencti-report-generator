"""
OpenCTI GraphQL Client
Pulls threat intelligence data from your OpenCTI instance
"""
import os
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta


class OpenCTIClient:
    def __init__(self, url: str = None, token: str = None):
        self.url = (url or os.getenv("OPENCTI_URL", "http://localhost:8989")).rstrip("/")
        self.token = token or os.getenv("OPENCTI_TOKEN", "")
        self.api_url = f"{self.url}/graphql"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def _query(self, query: str, variables: Dict = None) -> Dict:
        try:
            r = requests.post(
                self.api_url,
                json={"query": query, "variables": variables or {}},
                headers=self.headers,
                timeout=30,
                verify=os.environ.get("REQUESTS_CA_BUNDLE", True)
            )
            r.raise_for_status()
            return r.json().get("data", {})
        except Exception as e:
            return {"error": str(e)}

    def test_connection(self) -> bool:
        result = self._query("{ me { name } }")
        return "error" not in result

    def get_reports(self, days: int = 7, limit: int = 50) -> List[Dict]:
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query = """
        query GetReports($filters: FilterGroup, $first: Int) {
          reports(filters: $filters, first: $first) {
            edges {
              node {
                id name description published
                createdBy { name }
                objectLabel { value }
                objectMarking { definition }
              }
            }
          }
        }
        """
        variables = {
            "first": limit,
            "filters": {
                "mode": "and",
                "filters": [{"key": "published", "values": [since], "operator": "gt"}],
                "filterGroups": []
            }
        }
        data = self._query(query, variables)
        return [e["node"] for e in data.get("reports", {}).get("edges", [])]

    def get_indicators(self, days: int = 7, limit: int = 100) -> List[Dict]:
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query = """
        query GetIndicators($filters: FilterGroup, $first: Int) {
          indicators(filters: $filters, first: $first) {
            edges {
              node {
                id name pattern_type pattern
                x_opencti_score validFrom validUntil
                objectLabel { value }
              }
            }
          }
        }
        """
        variables = {
            "first": limit,
            "filters": {
                "mode": "and",
                "filters": [{"key": "created_at", "values": [since], "operator": "gt"}],
                "filterGroups": []
            }
        }
        data = self._query(query, variables)
        return [e["node"] for e in data.get("indicators", {}).get("edges", [])]

    def get_malware(self, limit: int = 50) -> List[Dict]:
        query = """
        query GetMalware($first: Int) {
          malwares(first: $first) {
            edges {
              node {
                id name description
                malware_types is_family
                objectLabel { value }
              }
            }
          }
        }
        """
        data = self._query(query, {"first": limit})
        return [e["node"] for e in data.get("malwares", {}).get("edges", [])]

    def get_threat_actors(self, limit: int = 50) -> List[Dict]:
        query = """
        query GetThreatActors($first: Int) {
          threatActors(first: $first) {
            edges {
              node {
                id name description
                threat_actor_types sophistication
                primary_motivation resource_level
                objectLabel { value }
              }
            }
          }
        }
        """
        data = self._query(query, {"first": limit})
        return [e["node"] for e in data.get("threatActors", {}).get("edges", [])]

    def get_vulnerabilities(self, days: int = 30, limit: int = 50) -> List[Dict]:
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query = """
        query GetVulnerabilities($filters: FilterGroup, $first: Int) {
          vulnerabilities(filters: $filters, first: $first) {
            edges {
              node {
                id name description
                x_opencti_cvss3_score
                objectLabel { value }
              }
            }
          }
        }
        """
        variables = {
            "first": limit,
            "filters": {
                "mode": "and",
                "filters": [{"key": "created_at", "values": [since], "operator": "gt"}],
                "filterGroups": []
            }
        }
        data = self._query(query, variables)
        return [e["node"] for e in data.get("vulnerabilities", {}).get("edges", [])]

    def get_attack_patterns(self, limit: int = 100) -> List[Dict]:
        query = """
        query GetAttackPatterns($first: Int) {
          attackPatterns(first: $first) {
            edges {
              node {
                id name description
                x_mitre_id x_mitre_platforms
                killChainPhases { kill_chain_name phase_name }
              }
            }
          }
        }
        """
        data = self._query(query, {"first": limit})
        return [e["node"] for e in data.get("attackPatterns", {}).get("edges", [])]

    def get_campaigns(self, limit: int = 30) -> List[Dict]:
        query = """
        query GetCampaigns($first: Int) {
          campaigns(first: $first) {
            edges {
              node {
                id name description
                first_seen last_seen
                objectLabel { value }
              }
            }
          }
        }
        """
        data = self._query(query, {"first": limit})
        return [e["node"] for e in data.get("campaigns", {}).get("edges", [])]

    def get_intrusion_sets(self, limit: int = 30) -> List[Dict]:
        query = """
        query GetIntrusionSets($first: Int) {
          intrusionSets(first: $first) {
            edges {
              node {
                id name description
                aliases resource_level
                primary_motivation sophistication
                objectLabel { value }
              }
            }
          }
        }
        """
        data = self._query(query, {"first": limit})
        return [e["node"] for e in data.get("intrusionSets", {}).get("edges", [])]

    def get_summary_stats(self) -> Dict:
        query = """
        {
          reports(first: 1)      { pageInfo { globalCount } }
          indicators(first: 1)   { pageInfo { globalCount } }
          malwares(first: 1)     { pageInfo { globalCount } }
          threatActors(first: 1) { pageInfo { globalCount } }
          vulnerabilities(first: 1) { pageInfo { globalCount } }
          campaigns(first: 1)    { pageInfo { globalCount } }
        }
        """
        data = self._query(query)
        return {
            "reports":       data.get("reports", {}).get("pageInfo", {}).get("globalCount", 0),
            "indicators":    data.get("indicators", {}).get("pageInfo", {}).get("globalCount", 0),
            "malware":       data.get("malwares", {}).get("pageInfo", {}).get("globalCount", 0),
            "threat_actors": data.get("threatActors", {}).get("pageInfo", {}).get("globalCount", 0),
            "vulnerabilities": data.get("vulnerabilities", {}).get("pageInfo", {}).get("globalCount", 0),
            "campaigns":     data.get("campaigns", {}).get("pageInfo", {}).get("globalCount", 0),
        }
