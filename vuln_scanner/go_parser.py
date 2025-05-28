#!/usr/bin/env python3
"""
Go module parser for CypherTrace vulnerability scanner.
Handles go.mod and go.sum files to extract dependency information.
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class GoModParser:
    """Parser for Go module files (go.mod and go.sum)."""
    
    def __init__(self, go_mod_path: str, go_sum_path: Optional[str] = None):
        self.go_mod_path = Path(go_mod_path)
        self.go_sum_path = Path(go_sum_path) if go_sum_path else None
        self.dependencies = []
        self.module_name = ""
        self.go_version = ""
        
    def parse(self) -> List[Dict[str, str]]:
        """Parse go.mod and optionally go.sum files."""
        try:
            self._parse_go_mod()
            if self.go_sum_path and self.go_sum_path.exists():
                self._parse_go_sum()
            return self.dependencies
        except Exception as e:
            logger.error(f"Error parsing Go module files: {e}")
            return []
    
    def _parse_go_mod(self):
        """Parse go.mod file to extract dependencies."""
        if not self.go_mod_path.exists():
            raise FileNotFoundError(f"go.mod file not found: {self.go_mod_path}")
        
        with open(self.go_mod_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract module name
        module_match = re.search(r'^module\s+(.+)$', content, re.MULTILINE)
        if module_match:
            self.module_name = module_match.group(1).strip()
        
        # Extract Go version
        go_match = re.search(r'^go\s+(.+)$', content, re.MULTILINE)
        if go_match:
            self.go_version = go_match.group(1).strip()
        
        # Extract dependencies from require blocks
        self._extract_dependencies_from_require_blocks(content)
        
        # Handle replace directives
        self._handle_replace_directives(content)
    
    def _extract_dependencies_from_require_blocks(self, content: str):
        """Extract dependencies from require blocks in go.mod."""
        # Handle both single-line and multi-line require blocks
        
        # Single-line requires: require github.com/gin-gonic/gin v1.8.1
        single_requires = re.findall(r'^require\s+([^\s]+)\s+([^\s]+)(?:\s+//.*)?$', content, re.MULTILINE)
        for module_path, version in single_requires:
            self._add_dependency(module_path, version, is_indirect=False)
        
        # Multi-line require blocks
        require_blocks = re.findall(r'require\s*\(\s*(.*?)\s*\)', content, re.DOTALL)
        for block in require_blocks:
            lines = block.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                
                # Parse dependency line: github.com/gin-gonic/gin v1.8.1 // indirect
                parts = line.split()
                if len(parts) >= 2:
                    module_path = parts[0]
                    version = parts[1]
                    is_indirect = '// indirect' in line
                    self._add_dependency(module_path, version, is_indirect)
    
    def _add_dependency(self, module_path: str, version: str, is_indirect: bool = False):
        """Add a dependency to the list."""
        # Normalize version (remove any prefixes/suffixes that might cause issues)
        normalized_version = self._normalize_version(version)
        
        dependency = {
            'name': module_path,
            'version': normalized_version,
            'type': 'go',
            'is_indirect': is_indirect,
            'original_version': version
        }
        
        self.dependencies.append(dependency)
        logger.debug(f"Added Go dependency: {module_path} {normalized_version}")
    
    def _normalize_version(self, version: str) -> str:
        """Normalize Go version strings."""
        # Remove 'v' prefix if present
        if version.startswith('v'):
            version = version[1:]
        
        # Handle pseudo-versions (e.g., v0.0.0-20191109021931-daa7c04131f5)
        if re.match(r'\d+\.\d+\.\d+-\d{14}-[a-f0-9]{12}', version):
            return version  # Keep pseudo-versions as-is
        
        # Handle +incompatible suffix
        if version.endswith('+incompatible'):
            version = version[:-13]  # Remove +incompatible
        
        return version
    
    def _handle_replace_directives(self, content: str):
        """Handle replace directives in go.mod."""
        # replace github.com/old/package => github.com/new/package v1.2.3
        # replace github.com/old/package => ./local/path
        
        replace_lines = re.findall(r'^replace\s+([^\s]+)(?:\s+[^\s]+)?\s+=>\s+([^\s]+)(?:\s+([^\s]+))?', content, re.MULTILINE)
        
        replacements = {}
        for old_module, new_module, new_version in replace_lines:
            if new_version and not new_module.startswith('./') and not new_module.startswith('../'):
                # External replacement with version
                replacements[old_module] = (new_module, new_version)
            # Skip local path replacements for vulnerability scanning
        
        # Apply replacements to dependencies
        for dep in self.dependencies:
            if dep['name'] in replacements:
                new_module, new_version = replacements[dep['name']]
                logger.info(f"Replacing {dep['name']} with {new_module} {new_version}")
                dep['name'] = new_module
                dep['version'] = self._normalize_version(new_version)
                dep['original_version'] = new_version
    
    def _parse_go_sum(self):
        """Parse go.sum file to verify versions."""
        if not self.go_sum_path.exists():
            logger.warning(f"go.sum file not found: {self.go_sum_path}")
            return
        
        with open(self.go_sum_path, 'r', encoding='utf-8') as f:
            sum_content = f.read()
        
        # Create a mapping of module@version to checksum
        sum_entries = {}
        for line in sum_content.strip().split('\n'):
            if not line.strip():
                continue
            
            parts = line.split(' ')
            if len(parts) >= 2:
                module_version = parts[0]
                checksum = parts[1]
                sum_entries[module_version] = checksum
        
        # Verify dependencies against go.sum
        for dep in self.dependencies:
            module_version = f"{dep['name']}@v{dep['version']}"
            if module_version in sum_entries:
                dep['checksum'] = sum_entries[module_version]
                logger.debug(f"Verified checksum for {module_version}")

def parse_go_dependencies(go_mod_path: str, go_sum_path: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Main function to parse Go dependencies from go.mod and go.sum files.
    
    Args:
        go_mod_path: Path to go.mod file
        go_sum_path: Path to go.sum file (optional)
    
    Returns:
        List of dependency dictionaries
    """
    parser = GoModParser(go_mod_path, go_sum_path)
    return parser.parse()

# Example usage for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python go_parser.py <go.mod path> [go.sum path]")
        sys.exit(1)
    
    go_mod_path = sys.argv[1]
    go_sum_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    dependencies = parse_go_dependencies(go_mod_path, go_sum_path)
    
    print(f"Found {len(dependencies)} Go dependencies:")
    for dep in dependencies:
        indirect_str = " (indirect)" if dep.get('is_indirect') else ""
        print(f"  {dep['name']} {dep['version']}{indirect_str}")