# Contributing Guide

Welcome to contribute to the SSLcat project! This guide will help you understand how to participate in project development.

## Ways to Contribute

### 1. Report Issues
- **Bug Reports**: Report discovered bugs in GitHub Issues
- **Feature Requests**: Suggest new features
- **Documentation Improvements**: Report documentation issues or improvement suggestions

### 2. Code Contributions
- **Bug Fixes**: Fix known issues
- **New Features**: Implement new features
- **Performance Optimization**: Improve performance
- **Code Refactoring**: Improve code quality

### 3. Documentation Contributions
- **Translation**: Help translate documentation
- **Examples**: Provide usage examples
- **Tutorials**: Write tutorials and guides

## Development Environment Setup

### System Requirements
- **Go**: 1.21+
- **Git**: 2.0+
- **Docker**: 20.10+ (optional)
- **Make**: 3.0+ (optional)

### Environment Setup

1. **Fork and Clone Repository**
   ```bash
   git clone https://github.com/your-username/sslcat.git
   cd sslcat
   ```

2. **Install Dependencies**
   ```bash
   go mod download
   ```

3. **Build Project**
   ```bash
   go build -o sslcat main.go
   ```

4. **Run Tests**
   ```bash
   go test ./...
   ```

## Development Workflow

### 1. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Write code following Go conventions
- Add tests for new functionality
- Update documentation if needed

### 3. Test Changes
```bash
# Run all tests
go test ./...

# Run specific tests
go test ./internal/ssl

# Run with coverage
go test -cover ./...
```

### 4. Commit Changes
```bash
git add .
git commit -m "feat: add new feature"
```

### 5. Push and Create PR
```bash
git push origin feature/your-feature-name
```

## Code Standards

### Go Code Style
- Follow Go standard formatting: `gofmt`
- Use meaningful variable and function names
- Add comments for exported functions
- Keep functions small and focused

### Code Organization
```
internal/
├── ssl/          # SSL certificate management
├── proxy/        # Proxy functionality
├── web/          # Web interface
├── database/     # Database operations
└── utils/        # Utility functions
```

### Testing Requirements
- Unit tests for all new functions
- Integration tests for complex features
- Test coverage should be > 80%
- Use table-driven tests where appropriate

## Documentation Standards

### Code Documentation
```go
// Package ssl provides SSL certificate management functionality.
package ssl

// Manager handles SSL certificate operations.
type Manager struct {
    // config contains SSL configuration
    config *Config
}

// NewManager creates a new SSL manager instance.
func NewManager(config *Config) *Manager {
    return &Manager{config: config}
}
```

### API Documentation
- Document all public APIs
- Provide usage examples
- Include parameter descriptions
- Add return value documentation

## Pull Request Guidelines

### PR Title Format
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for code style changes
- `refactor:` for code refactoring
- `test:` for test additions
- `chore:` for maintenance tasks

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
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## Review Process

### Code Review Checklist
- [ ] Code follows Go conventions
- [ ] Tests are comprehensive
- [ ] Documentation is updated
- [ ] No breaking changes (unless intentional)
- [ ] Performance impact considered

### Review Timeline
- Initial review: within 3 days
- Follow-up reviews: within 1 day
- Final approval: maintainer decision

## Issue Guidelines

### Bug Reports
Include the following information:
- SSLcat version
- Operating system
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error logs

### Feature Requests
- Clear description of the feature
- Use case and benefits
- Implementation suggestions (optional)
- Priority level

## Community Guidelines

### Communication
- Be respectful and constructive
- Use clear and concise language
- Provide context for discussions
- Follow the code of conduct

### Getting Help
- Check existing issues and discussions
- Ask questions in GitHub Discussions
- Join our community chat (if available)
- Read the documentation first

## Release Process

### Version Numbering
- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes (backward compatible)

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version tagged
- [ ] Release notes written

## Recognition

### Contributors
- All contributors are listed in CONTRIBUTORS.md
- Significant contributions are highlighted in release notes
- Active contributors may be invited to join the core team

### Contribution Types
- **Code**: Bug fixes, features, optimizations
- **Documentation**: Guides, examples, translations
- **Testing**: Test cases, bug reports
- **Community**: Support, feedback, discussions

## Resources

### Development Resources
- [Go Documentation](https://golang.org/doc/)
- [Go Best Practices](https://github.com/golang/go/wiki/CodeReviewComments)
- [SSLcat Architecture](architecture.md)
- [API Reference](../reference/api-reference.md)

### Community Resources
- [GitHub Discussions](https://github.com/xurenlu/sslcat/discussions)
- [Issue Tracker](https://github.com/xurenlu/sslcat/issues)
- [Pull Requests](https://github.com/xurenlu/sslcat/pulls)

## Related Documentation

- [Architecture](architecture.md) - System architecture overview
- [API Reference](../reference/api-reference.md) - API documentation
- [Troubleshooting](../troubleshooting/common-issues.md) - Common issues and solutions
