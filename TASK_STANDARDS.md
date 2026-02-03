# Task Standards Document

## Purpose
This document defines the standards for task breakdown within PRDs. Tasks are the smallest implementable units within a phase.

## Task Structure

Each task document must follow this structure:

### 1. Metadata
```yaml
---
task_id: task-{phase}-{number}
title: Brief descriptive title
phase: {phase_number}
estimated_effort: {days/story_points}
assigned_to: {team_member}
status: Not Started/In Progress/Blocked/Completed/Ready for Review
dependencies: [list of task IDs]
completion_criteria_count: {number}
---
```

### 2. Description
- Clear description of what needs to be done
- Context about why this task is important
- Business value provided

### 3. Acceptance Criteria
- Use format: "Given [context], When [action], Then [outcome]"
- Each criterion must be testable
- Minimum 3 criteria per task
- Maximum 10 criteria per task
- Each criterion should pass/fail independently

### 4. Deliverables
- List of concrete outputs
- Code modules/services
- Documentation updates
- Test cases
- Deployment artifacts

### 5. Technical Specifications
- API endpoints with methods
- Database schema changes
- Integration points
- Performance requirements
- Security considerations

### 6. Dependencies
- Tasks that must be completed first
- External system dependencies
- Resource dependencies
- Unblocking requirements

### 7. Implementation Notes
- Technical approach
- Design patterns to use
- Common pitfalls to avoid
- Reference implementations

### 8. Testing Requirements
- Unit test coverage (>80%)
- Integration test scenarios
- Performance test cases
- Security testing needs

### 9. Definition of Done
- Code reviewed and approved
- All tests passing
- Documentation updated
- Deployed to staging
- Acceptance criteria verified
- Stakeholder sign-off received

## Task Granularity

### Good Task Characteristics
- Can be completed in 1-5 days
- Has clear start and end points
- Delivers demonstrable value
- Can be tested independently
- Has a single owner

### Signs of Too Small Tasks
- Completed in less than half a day
- No valuable output alone
- Too many acceptance criteria
- Overly detailed

### Signs of Too Large Tasks
- Estimated > 5 days
- Multiple deliverables
- Can be split into subtasks
- Unclear acceptance criteria

## Task Types

### 1. Development Tasks
- Feature implementation
- Bug fixes
- Refactoring
- Performance optimization

### 2. Documentation Tasks
- API documentation
- User guides
- Technical specs
- Runbooks

### 3. Infrastructure Tasks
- Server setup
- Pipeline configuration
- Monitoring implementation
- Security hardening

### 4. Testing Tasks
- Test case creation
- Test automation
- Performance testing
- Security testing

### 5. Review Tasks
- Code review
- Design review
- Documentation review
- Security review

## Task Workflow

### 1. Creation
- Created during phase planning
- Linked to parent PRD
- Initial estimation provided
- Dependencies identified

### 2. Assignment
- Assigned to specific team member or team
- Capacity checked
- Skills verified
- Onboarding planned if needed

### 3. Execution
- Work in progress updates
- Blockers raised immediately
- Dependencies tracked
- Progress monitored

### 4. Completion
- All acceptance criteria met
- Code submitted for review
- Documentation updated
- Tests passing

### 5. Validation
- Review completed
- Stakeholder approval
- Integration tested
- Deployment verified

## Estimation Guidelines

### Story Points
- 1 point: Simple task, < 1 day
- 2 points: Moderate complexity, 1-2 days
- 3 points: Complex, 2-3 days
- 5 points: Very complex, 3-5 days
- 8 points: Epic, needs splitting

### Time-Based Estimation
- Include development time
- Add 20% for testing
- Add 10% for documentation
- Buffer for unknowns

## Visualization

### Task Boards
- To Do
- In Progress
- Ready for Review
- Done
- Blocked

### Burndown Charts
- Track progress daily
- Show remaining effort
- Identify bottlenecks
- Predict completion

## Quality Assurance

### Review Checklist
- [ ] Acceptance criteria clear and testable
- [ ] Dependencies identified and tracked
- [ ] Effort estimate reasonable
- [ ] All deliverables listed
- [ ] Technical specifications complete
- [ ] Testing requirements defined

### Automation
- Task creation from templates
- Automatic dependency checking
- Estimation validation
- Completion verification

## Templates

Use the task-template.md for consistency:
- Pre-filled sections
- Standard acceptance criteria format
- Completion checklist
- Review prompts

## Integration with PRDs

### Linking
- Each task links to parent PRD
- Phase dependencies tracked
- Cross-references maintained
- Status roll-up to PRD level

### Progress Tracking
- Individual task status
- Phase completion percentage
- Overall PRD progress
- Milestone tracking

## Best Practices

1. **Write tasks before coding**
2. **Involve the implementer in task writing**
3. **Review tasks as a team**
4. **Update estimates based on actuals**
5. **Celebrate task completions**
6. **Learn from estimation mistakes**
7. **Keep tasks focused on value**
8. **Document decisions made during implementation**

## Common Pitfalls to Avoid

1. Vague acceptance criteria
2. Missing dependencies
3. Unrealistic estimates
4. Tasks without owners
5. Forgetting documentation
6. Manually testing only
7. Not updating status
8. Gold-plating features