# Contributing to NullVoid

Thank you for your interest in contributing to NullVoid! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/nullvoid.git`
3. Create a feature branch: `git checkout -b feature/amazing-feature`
4. Install dependencies: `npm install`

## Development Setup

```bash
# Install dependencies
npm install

# Run the CLI locally
node bin/nullvoid.js scan

# Run tests (when available)
npm test

# Lint code
npm run lint
```

## Making Changes

### Code Style
- Use consistent indentation (2 spaces)
- Follow JavaScript best practices
- Add comments for complex logic
- Use meaningful variable names

### Adding New Heuristics

When adding new detection methods:

1. Create a new function in `scan.js`
2. Follow the naming convention: `check[FeatureName]`
3. Return an array of threat objects with this structure:
   ```javascript
   {
     type: 'THREAT_TYPE',
     message: 'Human-readable description',
     package: 'package-name',
     severity: 'HIGH|MEDIUM|LOW',
     details: 'Additional context'
   }
   ```
4. Add the new check to the `scanPackage` function
5. Update documentation

### Testing

- Test your changes with various packages
- Ensure no false positives for legitimate packages
- Test edge cases and error conditions

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Submit a pull request with a clear description

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tested locally
- [ ] Added new tests
- [ ] All existing tests pass

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)
```

## Issue Reporting

When reporting issues:

1. Use the issue template
2. Provide clear reproduction steps
3. Include environment details
4. Add relevant logs/output

## Security Considerations

- Never execute potentially malicious code
- Use static analysis only
- Validate all inputs
- Follow security best practices

## Community Guidelines

- Be respectful and inclusive
- Help others learn
- Provide constructive feedback
- Follow the code of conduct

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue or reach out to the maintainers!
