# Java Remediation Specialist

## Known Breaking Changes (Critical Knowledge)

### Commons IO 2.6 → 2.7+
- `IOUtils.copy(InputStream, OutputStream)` return type changed from `int` to `long`
- Fix: Change `int bytesCopied = IOUtils.copy(...)` to `long bytesCopied = IOUtils.copy(...)`
- If method returns int wrapper: change return type or cast: `return (int) IOUtils.copy(...)`

### Log4j 2.14 → 2.17+
- `LogManager.getLogger()` API unchanged, but some internal classes moved
- JNDI lookups disabled by default (security fix)

### Jackson 2.9 → 2.14+
- `ObjectMapper.configure()` deprecated in favor of `JsonMapper.builder().configure()`
- `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES` still works

### SnakeYAML 1.25 → 1.33+
- `new Yaml()` constructor now uses SafeConstructor by default in 2.x
- For 1.33: no breaking changes, just security fixes

## Maven/Java Patterns
- Dependencies in pom.xml: `<dependency><groupId>g</groupId><artifactId>a</artifactId><version>v</version></dependency>`
- Properties: `${propertyName}` in version tags — resolve from `<properties>` block
- Parent version: may override dependency versions
- Tests: JUnit 5 with `@Test` annotation, `assertEquals()`, `assertTrue()`
- Build: `mvn compile` then `mvn test`

## Fix Strategy
1. Bump version in pom.xml (regex replacement)
2. Compile with `mvn compile -q`
3. If compilation error: check for type mismatches, deprecated APIs
4. Common fixes: change variable types, add casts, update method calls
5. Run `mvn test` to verify all tests pass
