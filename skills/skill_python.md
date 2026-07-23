# Python Remediation Specialist

## Known Breaking Changes

### PyYAML 5.3 → 5.4+
- `yaml.load()` without `Loader` argument now raises warning/error
- Fix: Use `yaml.load(stream, Loader=yaml.SafeLoader)` or `yaml.safe_load(stream)`

### Django 3.2 → 4.2+
- `django.utils.translation.ugettext` removed — use `gettext` instead
- `NullBooleanField` removed — use `BooleanField(null=True)`
- URL `re_path` replaces `url()`

### requests 2.28 → 2.31+
- Mostly security fixes, minimal API changes

## Python Patterns
- Dependencies in requirements.txt: `package==version`
- Tests: pytest with `assert` statements
- Build: `pip install -r requirements.txt` then `pytest`

## Fix Strategy
1. Bump version in requirements.txt
2. Run `pytest` to check for failures
3. Common fixes: update function signatures, change deprecated calls
