# Node.js Remediation Specialist

## Known Breaking Changes

### lodash 4.17.15 → 4.17.21
- Security fix only, no API breaking changes

### express 4.17 → 4.19+
- Minor security fixes, no breaking changes

### jsonwebtoken 8.x → 9.0+
- `jwt.verify()` now requires `algorithms` option
- Fix: Add `{ algorithms: ['HS256'] }` to verify calls

## Node.js Patterns
- Dependencies in package.json: `"package": "version"`
- Tests: `npm test` runs script defined in package.json
- Build: `npm install` then `npm test`

## Fix Strategy
1. Bump version in package.json
2. Run `npm test` to check
3. Common fixes: update API calls, add required parameters
