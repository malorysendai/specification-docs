# PRD Standards Document

## Purpose
This document defines the standards and requirements for all Product Requirements Documents (PRDs) in the specification-docs repository.

## Folder Structure

All PRDs must follow this folder structure:
```
specification-docs/
├── approved/
│   ├── phase-1-{title}/
│   │   ├── phase-1-{title}.md
│   │   └── task-1-{subtask}.md
│   │   └── task-2-{subtask}.md
│   └── phase-2-{title}/
├── drafts/
└── templates/
```

### Naming Conventions
- Phase documents: `phase-{n}-{title}.md`
- Task documents: `task-{n}-{title}.md`
- Use kebab-case for titles (e.g., `phase-1-user-authentication.md`)

## Required PRD Sections

Every PRD must include the following sections in order:

### 1. Metadata (at the top)
- Author
- Date Created
- Last Updated
- Status (Draft/Approved/Archived)
- Priority (High/Medium/Low)
- Phase (if applicable)

### 2. Executive Summary
- 2-3 paragraph overview
- Key objectives
- Expected outcomes

### 3. Problem Statement
- Clear problem description
- Target users affected
- Current limitations
- Business impact

### 4. Success Criteria
- Measurable outcomes
- Specific, achievable goals
- Must pass/fail criteria
- How success will be measured

### 5. Stakeholders
- Primary stakeholders
- Secondary stakeholders
- External dependencies
- Communication plan

### 6. Scope
#### In-Scope
- Features included
- User journeys covered
- Systems affected

#### Out-of-Scope  
- Features explicitly excluded
- Future considerations
- Related but separate initiatives

### 7. Phases and Dependencies
- Phase breakdown with timeline
- Inter-phase dependencies
- Critical path identification
- Milestones and gates

### 8. Risk Assessment
- Technical risks
- Business risks
- Resource risks
- Mitigation strategies
- Risk severity matrix

### 9. Resource Requirements
- Team composition
- External resources needed
- Budgetary requirements
- Tooling and infrastructure

### 10. Timeline
- Development phases
- Key milestones
- Review and approval gates
- Launch timeline

### 11. Metrics and KPIs
- Success metrics
- Performance indicators
- Tracking mechanisms
- Reporting cadence

### 12. Appendix
- Diagrams (architecture, user flow, etc.)
- References to related documents
- Glossary of terms
- Assumptions and constraints

## Quality Standards

### Writing Standards
- Clear, concise language
- Active voice preferred
- No ambiguous terms
- Consistent terminology

### Documentation Standards
- All PRDs must be in Markdown format
- Use standard Markdown syntax
- Include table of contents for long documents (>2000 words)
- Code blocks for technical specifications

### Review Standards
- Must pass peer review
- Technical feasibility verified
- Business stakeholder approval
- Documentation review complete

## Approval Process

1. Draft Creation
   - Author creates PRD in drafts/
   - Self-review for completeness
   - Request initial feedback

2. Technical Review
   - Engineering team review
   - Architecture assessment
   - Feasibility confirmation

3. Business Review
   - Product owner approval
   - Stakeholder sign-off
   - Priority confirmation

4. Final Approval
   - Move to approved/ folder
   - Update status to "Approved"
   - Notify all stakeholders

## Templates

Use the provided templates in the templates/ directory:
- `prd-template.md` - Full PRD template
- `phase-template.md` - Phase-specific template
- `task-template.md` - Task breakdown template

## Maintenance

- Review and update PRDs quarterly
- Archive completed projects
- Update status changes
- Maintain version history

## Non-Compliance

PRDs not meeting these standards will be:
1. Identified during automated scan
2. Moved to drafts/ folder
3. Listed in compliance report
4. Require fixes before approval

## Version History

- v1.0 - Initial standards (2026-02-03)
- Updates will be tracked with date and change description