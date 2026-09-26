import yaml
import hashlib
import os
import json
import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("nuclei-template-analyzer")

class TemplateAnalyzer:
    """
    Analyzes Nuclei templates for quality, reliability, and false positive risks.
    """
    
    def __init__(self, templates_dir: str, cache_file: str = "/app/logs/template_analysis_cache.json"):
        self.templates_dir = templates_dir
        self.cache_file = cache_file
        self.cache: Dict[str, Any] = self._load_cache()
        self.trusted_authors = ["projectdiscovery", "pdteam", "tech-detect"]

    def _load_cache(self) -> Dict[str, Any]:
        """Loads analysis cache from disk."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load cache: {e}")
        return {}
    
    def _save_cache(self):
        """Saves current cache to disk."""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculates MD5 hash of a file."""
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                buf = f.read()
                hasher.update(buf)
            return hasher.hexdigest()
        except:
            return ""

    def analyze_template(self, template_path: str) -> Dict[str, Any]:
        """
        Analyzes a single template and returns its score and metadata.
        Uses caching if the file hasn't changed.
        """
        if not os.path.exists(template_path):
             return {}

        current_hash = self._calculate_file_hash(template_path)
        template_id = os.path.basename(template_path).replace('.yaml', '')

        # Check cache
        if template_id in self.cache:
            if self.cache[template_id].get('hash') == current_hash:
                return self.cache[template_id]

        # Perform analysis
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                # Safe load for untrusted input, though these are templates
                try:
                    content = yaml.safe_load(f)
                except yaml.YAMLError:
                    # Fallback or error
                    return self._default_error_result(template_id, current_hash, "Invalid YAML")

                if not content:
                     return self._default_error_result(template_id, current_hash, "Empty content")
                
                analysis = self._perform_deep_analysis(content, template_path)
                analysis['hash'] = current_hash
                analysis['template_id'] = template_id
                analysis['last_analyzed'] = datetime.now().isoformat()
                
                # Update cache
                self.cache[template_id] = analysis
                return analysis

        except Exception as e:
            logger.error(f"Error analyzing {template_path}: {e}")
            return self._default_error_result(template_id, current_hash, str(e))

    def _default_error_result(self, template_id: str, file_hash: str, error: str) -> Dict[str, Any]:
         return {
            "template_id": template_id,
            "hash": file_hash,
            "reliability_score": 0,
            "fp_risk_score": 100,
            "attack_surface_score": 0,
            "error": error
        }

    def _perform_deep_analysis(self, content: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        info = content.get('info', {})
        
        # 1. Reliability Score (0-100)
        reliability_score = 50 # Base score
        
        # Author check
        author = info.get('author', '')
        if any(trusted in author.lower() for trusted in self.trusted_authors):
            reliability_score += 20
            
        # CVE Bonus
        classification = info.get('classification', {})
        if classification.get('cve-id'):
            reliability_score += 20
            
        # Matcher Complexity & Type
        matchers_count = 0
        has_regex = False
        has_status = False
        has_word = False
        
        requests = content.get('http', []) or content.get('requests', [])
        # Handle new and old syntax (requests vs http) - though nuclei unified primarily in recent versions
        # 'http' is standard now.
        if isinstance(requests, list):
            for req in requests:
                for matcher in req.get('matchers', []):
                    matchers_count += 1
                    m_type = matcher.get('type', 'status')
                    if m_type == 'regex': has_regex = True
                    if m_type == 'status': has_status = True
                    if m_type == 'word': has_word = True
        
        if matchers_count > 2:
            reliability_score += 10
        
        # Cap at 100
        reliability_score = min(100, reliability_score)

        # 2. False Positive Risk Calculation (Lower is better, but we return a Risk Score so Higher = More Risk)
        # 0 = No Risk, 100 = High Risk
        fp_risk_score = 50 # Base
        
        if has_status and not (has_word or has_regex):
            fp_risk_score += 30 # Sadece status check cok riskli
        
        if has_regex and has_word:
            fp_risk_score -= 30 # Regex + Word oldukca spesifik
            
        if has_word and not has_status:
            fp_risk_score -= 10
            
        # Derinlik kontrolü (body check vs header check)
        # Basit heuristic: Request sayisi ve extractors
        if matchers_count == 0:
            fp_risk_score = 90 # Matcher yoksa neye gore match ediyor? (dsl olabilir gerci)

        fp_risk_score = max(0, min(100, fp_risk_score))

        # 3. Attack Surface Coverage
        attack_surface = {
            "param_fuzzing": False,
            "header_injection": False,
            "path_traversal": False,
            "path_count": 0
        }
        
        total_paths = 0
        if isinstance(requests, list):
             for req in requests:
                paths = req.get('path', [])
                total_paths += len(paths)
                
                # Check payloads (fuzzing)
                if 'payloads' in req:
                    attack_surface['param_fuzzing'] = True
                    
                # Check for headers
                headers = req.get('headers', {})
                if any('{{' in v for v in headers.values()):
                     attack_surface['header_injection'] = True
                
                # Simple check for path traversal in paths
                for p in paths:
                     if '../' in p:
                         attack_surface['path_traversal'] = True
        
        attack_surface['path_count'] = total_paths
        
        # Calculate coverage score (0-100)
        coverage_score = 0
        if attack_surface['param_fuzzing']: coverage_score += 40
        if attack_surface['header_injection']: coverage_score += 30
        if total_paths > 1: coverage_score += 20
        coverage_score = min(100, coverage_score)

        return {
            "reliability_score": reliability_score,
            "fp_risk_score": fp_risk_score,
            "attack_surface": attack_surface,
            "attack_surface_score": coverage_score,
            "author": author,
            "name": info.get('name', ''),
            "severity": info.get('severity', 'info')
        }

    def analyze_all(self):
        """Analyzes all yaml files in templates directory."""
        results = {}
        for root, dirs, files in os.walk(self.templates_dir):
            for file in files:
                if file.endswith('.yaml'):
                    full_path = os.path.join(root, file)
                    res = self.analyze_template(full_path)
                    if res:
                        results[res['template_id']] = res
        
        self._save_cache()
        return results

    def get_analysis(self, template_id: str) -> Optional[Dict[str, Any]]:
        return self.cache.get(template_id)
