# Contributing to Shell

Thank you for your interest in contributing to Shell! This document provides guidelines for contributing to the project.

## Bug Bounty Focus

Shell is designed specifically for bug bounty hunters and security researchers. We welcome contributions that:
- Add new vulnerability discovery techniques
- Improve existing scanners
- Enhance performance for large-scale scanning
- Add support for new platforms/services

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/shell`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test ./...`
6. Commit your changes: `git commit -m 'Add your feature'`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Create a Pull Request

## Code Style

- Follow standard Go formatting (use `gofmt`)
- Add comments for exported functions
- Keep functions focused and small
- Write unit tests for new functionality

## Adding New Scanners

When adding a new scanner:
1. Create a new command file in `cmd/`
2. Follow the existing pattern for command structure
3. Add appropriate flags and help text
4. Document the scanner in README.md
5. Add example usage

## Testing

- Write tests for all new functionality
- Ensure existing tests pass
- Test against safe, legal targets only
- Never commit real credentials or sensitive data

## Security

- Never add code that could be used maliciously
- Focus on defensive security and discovery
- Respect rate limits and service ToS
- Always require explicit user authorization

## Pull Request Process

1. Ensure your PR has a clear title and description
2. Reference any related issues
3. Ensure all tests pass
4. Update documentation as needed
5. Wait for code review and address feedback

## Questions?

Feel free to open an issue for any questions or discussions!