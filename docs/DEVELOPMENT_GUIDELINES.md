# Development Guidelines for simple-idm-server

## Language Policy

### Markdown Documentation
- ✅ **ALL markdown files MUST be in English**
- This includes: README.md, guides, tutorials, architecture docs
- User-facing documentation is in English for GitHub
- Internal conversation with developer is in Czech

### Code Comments & Strings
- ✅ Code comments can be in **Czech or English**
- Error messages and user-facing strings should be **English**
- Internal log messages can be Czech

### Git Commits
- ✅ Commit messages should be in **English**
- Format: `feat: add M2M OAuth2 support` (not `přidej...`)

## Documentation Structure

### Root Directory (/)
Only **ONE** markdown file in root:
- `README.md` - Main project overview (English)

### Docs Directory (/docs)
All additional documentation goes here:
- `QUICKSTART.md` - Getting started guide (English)
- `M2M_TESTS.md` - M2M test documentation (English)
- `ARCHITECTURE.md` - System architecture (English, future)
- `API_REFERENCE.md` - API documentation (English, future)
- Other guides...

### File Naming
- Use simple names: `README.md`, not `README_EN.md`
- No language suffix needed - assume English
- Use hyphens for multi-word names: `M2M_TESTS.md`

## Checklist Before Committing

Before submitting new markdown files, verify:

- [ ] Is it markdown documentation?
  - [ ] YES → Is it in English?
    - [ ] YES → Is it in /docs directory? (except README.md in root)
      - [ ] YES → Good to commit ✅
      - [ ] NO → Move it to /docs
    - [ ] NO → Translate to English first
  - [ ] NO → Not affected by this policy

## Common Mistakes to Avoid

### ❌ WRONG:
```
Root directory files:
  - QUICKSTART.md (Czech)
  - M2M_TESTS_README.md (Czech)
  - ARCHITECTURE.md
  - API_DOCS.md
```

### ✅ CORRECT:
```
Root directory:
  - README.md (English overview)

docs/ directory:
  - QUICKSTART.md (English)
  - M2M_TESTS.md (English)
  - ARCHITECTURE.md (English)
  - API_REFERENCE.md (English)
```

## Examples

### Example 1: Adding a new guide

**Task:** Add a guide for integrating with the IDM server

**Steps:**
1. Create file: `docs/INTEGRATION_GUIDE.md`
2. Write in English
3. Follow markdown conventions
4. Commit with message: `docs: add integration guide`

### Example 2: Adding a new feature with documentation

**Task:** Implement and document a new feature

**Steps:**
1. Write code (Czech comments OK, English error messages)
2. Create new doc: `docs/FEATURE_NAME.md` (English)
3. Update `README.md` to mention the feature (English)
4. Do NOT create docs in root directory
5. Commit: `feat: add feature X` or `docs: add feature X documentation`

### Example 3: What to do when developer asks in Czech

**Task:** Developer says "Napiš dokumentaci k OAuth2 flowům"

**Steps:**
1. Create file: `docs/OAUTH2_FLOWS.md` (English)
2. Write in English despite Czech request
3. This is the correct behavior

## Testing

- Unit tests: No markdown required
- Integration tests: If needing docs, create in `/docs`
- Test data files (SQL, JSON): Can stay in root or scripts/ (no translation needed)

## Future Extensions

When adding new features, remember:
- Czech conversation ✅
- English documentation ✅
- English code comments preferred ✅
- English git commits ✅

## Questions?

These guidelines ensure:
1. Clean root directory (only README.md)
2. All documentation is in English
3. Easier GitHub discovery
4. Professional project appearance
5. Consistent structure

For any questions, refer to this file or ask the developer for clarification.
