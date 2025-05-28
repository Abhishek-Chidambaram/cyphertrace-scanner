import os
import sys
import unittest
from pathlib import Path

# Add parent directory to path so we can import our modules
sys.path.append(str(Path(__file__).parent.parent))

from vuln_scanner.go_parser import parse_go_dependencies
from vuln_scanner.models import Package
from vuln_scanner.scanner import scan_application_dependencies

class TestGoScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(__file__).parent
        self.go_mod_path = self.test_dir / "test_go.mod"
        self.go_sum_path = self.test_dir / "test_go.sum"  # Optional, can be None

    def test_parse_go_dependencies(self):
        """Test that we can parse Go dependencies correctly."""
        dependencies = parse_go_dependencies(str(self.go_mod_path))
        
        # Verify we got the expected number of dependencies
        self.assertGreater(len(dependencies), 0)
        
        # Verify specific dependencies are present
        dep_names = {dep['name'] for dep in dependencies}
        self.assertIn('github.com/gin-gonic/gin', dep_names)
        self.assertIn('github.com/stretchr/testify', dep_names)
        self.assertIn('golang.org/x/crypto', dep_names)
        
        # Verify versions
        for dep in dependencies:
            if dep['name'] == 'github.com/gin-gonic/gin':
                self.assertEqual(dep['version'], 'v1.8.1')
            elif dep['name'] == 'github.com/stretchr/testify':
                self.assertEqual(dep['version'], 'v1.8.0')

    def test_scan_go_dependencies(self):
        """Test that we can scan Go dependencies for vulnerabilities."""
        # Parse dependencies
        dependencies = parse_go_dependencies(str(self.go_mod_path))
        
        # Convert to Package objects
        packages = []
        for dep in dependencies:
            try:
                pkg = Package(
                    name=dep['name'],
                    version=dep['version'],
                    ecosystem='Go'
                )
                packages.append(pkg)
            except Exception as e:
                self.fail(f"Failed to create Package object: {e}")
        
        # Scan for vulnerabilities
        results = scan_application_dependencies(packages)
        
        # Verify we got results (even if empty)
        self.assertIsNotNone(results)
        # Note: We don't assert specific vulnerabilities as they may change over time

    def test_command_line_usage(self):
        """Test that the scanner can be run from command line."""
        # This is more of an integration test
        # We'll verify the command works by checking its exit code
        cmd = f"python {Path(__file__).parent.parent}/main.py --go-mod {self.go_mod_path} --format json"
        exit_code = os.system(cmd)
        self.assertEqual(exit_code, 0, "Command line scan failed")

if __name__ == '__main__':
    unittest.main() 