# Contributing to Humifortis Keycloak Connector

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Maintain professional communication

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [GitHub Issues](https://github.com/humifortis/humifortis-keycloak-connector/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Keycloak version
   - Java version
   - Relevant logs
   - Environment details

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with:
   - Clear use case description
   - Benefits and rationale
   - Potential implementation approach
   - Any relevant examples

### Pull Requests

1. **Fork the repository** and create a feature branch
2. **Follow the coding standards**:
   - Use Java 17+ features appropriately
   - Follow existing code style
   - Add JavaDoc for public methods
   - Keep methods focused and concise
3. **Write tests** for new functionality
4. **Update documentation** as needed
5. **Commit messages** should be clear and descriptive
6. **Submit the PR** with:
   - Description of changes
   - Related issue number (if applicable)
   - Testing performed

## Development Setup

### Prerequisites

- JDK 17 or later
- Maven 3.8+
- Git
- Keycloak instance for testing

### Build and Test

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/keycloak-connector.git
cd keycloak-connector

# Build
mvn clean package

# Run tests
mvn test

# Install locally for testing
cp target/humifortis-keycloak-connector.jar /opt/keycloak/providers/
```

### Testing

- Write unit tests for new functionality
- Test with multiple Keycloak versions (26.8.1 is the supported version)
- Verify integration with Humifortis SaaS
- Test error handling and edge cases

## Coding Standards

### Java Style

- Use clear, descriptive variable names
- Prefer composition over inheritance
- Keep classes focused (Single Responsibility Principle)
- Use appropriate access modifiers
- Handle exceptions appropriately
- Log at appropriate levels

### Example:

```java
public class GoodExample {
    private static final Logger logger = Logger.getLogger(GoodExample.class);
    
    public void processEvent(Event event) {
        try {
            // Clear, focused logic
            validateEvent(event);
            sendToSaas(event);
            logger.debugf("Event processed: %s", event.getType());
        } catch (ValidationException e) {
            logger.warn("Invalid event", e);
        } catch (Exception e) {
            logger.error("Failed to process event", e);
        }
    }
}
```

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Be descriptive but concise
- Reference issues when applicable

```
Add retry logic for SaaS communication

- Implement exponential backoff
- Add configurable retry count
- Log retry attempts

Fixes #123
```

## Architecture Guidelines

### Thin Client Principle

The connector should remain a "thin client":
- ✅ Capture and send events
- ✅ Query and enforce decisions
- ❌ Don't add local risk calculation
- ❌ Don't add local policy logic
- ❌ Don't add caching of decisions

### API Communication

- Use async for event sending
- Keep timeouts configurable
- Handle network failures gracefully
- Log API errors appropriately

### Performance

- Minimize impact on authentication flow
- Use async operations where possible
- Avoid blocking calls
- Keep memory footprint small

## Testing Guidelines

### Unit Tests

```java
@Test
public void testEventMapping() {
    Event keycloakEvent = createTestEvent();
    HumifortisEvent result = mapper.fromKeycloakEvent(keycloakEvent);
    
    assertEquals("auth_login_failed", result.getEventType());
    assertNotNull(result.getEntityId());
}
```

### Integration Tests

- Test with real Keycloak instance
- Verify SPI registration
- Test authentication flow
- Verify event sending

## Documentation

When contributing, please update:

- README.md (if adding features)
- INSTALLATION.md (if changing setup)
- Code comments and JavaDoc
- CHANGELOG.md (for notable changes)

## Release Process

(For maintainers)

1. Update version in pom.xml
2. Update CHANGELOG.md
3. Create git tag: `v1.x.x`
4. Push tag: `git push origin v1.x.x`
5. GitHub Actions will build and create release

## Questions?

- Email: support@humifortis.tech
- GitHub Issues: For bug reports and feature requests
- GitHub Discussions: For questions and general discussion

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
