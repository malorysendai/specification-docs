#!/usr/bin/env python3
"""
PRD Compliance Analyzer and Fixer
Analyzes PRDs against PRD_STANDARDS.md requirements and helps fix them.
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime
import sys

class PRDAnalyzer:
    def __init__(self, repo_path):
        self.repo_path = Path(repo_path)
        self.approved_path = self.repo_path / "approved"
        self.drafts_path = self.repo_path / "drafts"
        self.templates_path = self.repo_path / "templates"
        
        # Required sections based on PRD standards
        self.required_sections = [
            "Executive Summary",
            "Problem Statement", 
            "Success Criteria",
            "Stakeholders",
            "Scope",
            "Phases and Dependencies",
            "Risk Assessment",
            "Resource Requirements",
            "Timeline",
            "Metrics and KPIs",
            "Appendix"
        ]
        
    def scan_prds(self):
        """Scan for all PRDs in the repository"""
        prds = []
        
        # Scan approved folder
        if self.approved_path.exists():
            for prd in self.approved_path.rglob("*.md"):
                prds.append({"path": prd, "status": "approved"})
                
        # Scan drafts folder  
        if self.drafts_path.exists():
            for prd in self.drafts_path.rglob("*.md"):
                prds.append({"path": prd, "status": "draft"})
                
        return prds
    
    def analyze_prd(self, prd_path):
        """Analyze a single PRD for compliance"""
        issues = []
        warnings = []
        
        try:
            with open(prd_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return [{"error": f"Could not read file: {e}"}]
        
        # Check filename format
        filename = Path(prd_path).name
        if not (filename.startswith("phase-") or filename.startswith("task-")):
            issues.append(f"Incorrect filename format: {filename}")
        
        # Check for required sections
        for section in self.required_sections:
            if f"## {section}" not in content and f"### {section}" not in content:
                issues.append(f"Missing required section: {section}")
        
        # Check if there's metadata
        if not content.startswith("# PRD:") and "---" not in content.split('\n\n')[0]:
            warnings.append("Missing proper metadata header")
        
        # Check for proper heading structure
        has_h1 = "# " in content.split('\n')[0:3]
        if not has_h1:
            issues.append("Missing H1 heading for PRD title")
        
        # Check if it has problem statement
        if "## Problem Statement" not in content:
            issues.append("Missing Problem Statement section")
        else:
            # Check if problem statement has substance
            problem_match = re.search(r'## Problem Statement\n+(.*?)(?=\n## |\n# |\Z)', content, re.DOTALL)
            if problem_match and len(problem_match.group(1).strip()) < 50:
                warnings.append("Problem Statement seems too brief")
        
        # Check success criteria
        if "## Success Criteria" not in content:
            issues.append("Missing Success Criteria section")
        else:
            # Look for bullet points in success criteria
            criteria_match = re.search(r'## Success Criteria\n+(.*?)(?=\n## |\n# |\Z)', content, re.DOTALL)
            if criteria_match and ("- " not in criteria_match.group(1) and "* " not in criteria_match.group(1)):
                warnings.append("Success Criteria should be in bullet points")
        
        # Check for risk assessment
        if "## Risk Assessment" not in content:
            issues.append("Missing Risk Assessment section")
        
        return issues + warnings
    
    def fix_prd(self, prd_path, dry_run=False):
        """Attempt to automatically fix common issues"""
        fixes_applied = []
        
        try:
            with open(prd_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return [], [f"Could not read file: {e}"]
        
        new_content = content
        
        # Fix missing sections by adding templates
        missing_sections = []
        for section in self.required_sections:
            if f"## {section}" not in new_content and f"### {section}" not in new_content:
                missing_sections.append(section)
        
        # Add missing sections at the end
        if missing_sections:
            fixes_applied.append(f"Added missing sections: {', '.join(missing_sections)}")
            
            # Find where to add (before Appendix if exists, else at end)
            insertion_point = len(new_content)
            if "## Appendix" in new_content:
                insertion_point = new_content.find("## Appendix")
            
            # Build missing sections content
            missing_content = "\n"
            for section in missing_sections:
                missing_content += f"\n## {section}\n\n*To be completed*\n"
            
            new_content = new_content[:insertion_point] + missing_content + new_content[insertion_point:]
        
        # Add metadata if missing
        if not "---" in new_content.split('\n\n')[0] and not new_content.startswith("# PRD:"):
            title = Path(prd_path).stem.replace('-', ' ').title()
            metadata = f"""# PRD: {title}

## Metadata
- **Author**: 
- **Date Created**: {datetime.now().strftime('%Y-%m-%d')}
- **Last Updated**: {datetime.now().strftime('%Y-%m-%d')}
- **Status**: Draft
- **Priority**: 
- **Phase**: 

"""
            fixes_applied.append("Added metadata header")
            new_content = metadata + new_content
        
        # Fix filename if needed
        filename = Path(prd_path).name
        new_filename = filename
        if not (filename.startswith("phase-") or filename.startswith("task-")):
            # Try to detect if it's a phase or task from content
            if "Phase" in new_content or "## Phase" in new_content:
                new_filename = f"phase-1-{filename}"
            else:
                new_filename = f"task-1-{filename}"
            fixes_applied.append(f"Renamed file: {filename} -> {new_filename}")
        
        # Write the fixed content
        if not dry_run and fixes_applied:
            new_path = prd_path.parent / new_filename
            
            # Create backup
            backup_path = prd_path.with_suffix(prd_path.suffix + '.backup')
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Write fixed version
            with open(new_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            # Remove original if renamed
            if new_filename != filename:
                prd_path.unlink()
        
        return fixes_applied, []
    
    def generate_report(self, results):
        """Generate a comprehensive report"""
        total_prds = len(results)
        compliant = 0
        non_compliant = 0
        requires_stakeholder_input = []
        
        report_lines = [
            "# PRD Compliance Report",
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n## Summary",
            f"- Total PRDs analyzed: {total_prds}",
            f"- Compliant: {compliant}",
            f"- Non-compliant: {non_compliant}",
            f"\n## Detailed Results\n"
        ]
        
        for result in results:
            path = result['path']
            issues = result['issues']
            
            report_lines.append(f"### {path}")
            report_lines.append(f"**Status**: {'Compliant' if not issues else 'Non-compliant'}")
            
            if issues:
                report_lines.append("\n**Issues Found:**")
                for issue in issues:
                    report_lines.append(f"- {issue}")
            
            if result.get('fixes'):
                report_lines.append("\n**Fixes Applied:**")
                for fix in result['fixes']:
                    report_lines.append(f"- {fix}")
            
            # Check for stakeholder input needed
            stakeholder_issues = [i for i in issues if 'Author' in i or 'Priority' in i or 'Stakeholders' in i]
            if stakeholder_issues:
                requires_stakeholder_input.append(str(path))
            
            report_lines.append("\n---\n")
        
        # Add stakeholder input section
        if requires_stakeholder_input:
            report_lines.append("## Requires Stakeholder Input")
            for prd in requires_stakeholder_input:
                report_lines.append(f"- {prd}")
        
        return '\n'.join(report_lines)


def main():
    # Check if repository path provided
    if len(sys.argv) < 2:
        print("Usage: python prd_analyzer.py <repository_path>")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    analyzer = PRDAnalyzer(repo_path)
    
    print(f"\nScanning PRDs in {repo_path}...")
    prds = analyzer.scan_prds()
    print(f"Found {len(prds)} PRDs")
    
    results = []
    
    for prd in prds:
        prd_path = prd['path']
        print(f"\nAnalyzing {prd_path}...")
        
        issues = analyzer.analyze_prd(prd_path)
        
        result = {
            'path': str(prd_path),
            'status': prd['status'],
            'issues': issues,
            'fixes': []
        }
        
        # If issues found, attempt to fix
        if issues:
            print(f"  Found {len(issues)} issues. Attempting to fix...")
            fixes, errors = analyzer.fix_prd(prd_path)
            result['fixes'] = fixes
            if errors:
                result['issues'].extend(errors)
        
        results.append(result)
    
    # Generate report
    report = analyzer.generate_report(results)
    
    # Save report
    report_path = Path(repo_path) / "PRD_COMPLIANCE_REPORT.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\nReport saved to: {report_path}")
    
    # Move non-compliant PRDs to drafts
    print("\nMoving non-compliant PRDs to drafts...")
    drafts_path = Path(repo_path) / "drafts"
    drafts_path.mkdir(exist_ok=True)
    
    for result in results:
        if result['issues'] and result['status'] == 'approved':
            src = Path(result['path'])
            if src.exists():  # Check if file still exists (may have been renamed)
                dst = drafts_path / src.name
                src.rename(dst)
                print(f"  Moved {src.name} to drafts/")


if __name__ == "__main__":
    main()