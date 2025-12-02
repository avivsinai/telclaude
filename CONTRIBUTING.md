# Contributing to telclaude

Thank you for your interest in contributing to telclaude! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

---

## Getting Started

### Prerequisites

- **Node.js 22+**
- **pnpm 9.15+**
- **Claude CLI** (for testing)
- **Git**

### Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/telclaude.git
cd telclaude

# Install dependencies
pnpm install

# Verify setup
pnpm typecheck
pnpm lint
pnpm test
```

### Project Overview

Telclaude is a Telegram-Claude bridge with a security-first architecture. Key areas:

- **`src/telegram/`** — Telegram bot handlers (grammY)
- **`src/security/`** — Security layer (observer, rate limiting, approvals)
- **`src/sdk/`** — Claude Agent SDK wrapper
- **`src/sandbox/`** — OS-level sandbox configuration
- **`src/commands/`** — CLI commands

---

## Development Workflow

### Branch Naming

Use descriptive branch names:

```
feature/add-webhook-support
fix/rate-limit-persistence
docs/improve-architecture-diagrams
refactor/simplify-session-pool
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add webhook support for Telegram updates
fix: persist rate limit state across restarts
docs: add Mermaid architecture diagrams
refactor: simplify session pool lifecycle
test: add observer circuit breaker tests
chore: update dependencies
```

### Development Commands

```bash
# Run in development mode
pnpm dev relay

# Type check
pnpm typecheck

# Lint (check only)
pnpm lint

# Lint (auto-fix)
pnpm lint:fix

# Format
pnpm format

# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Build
pnpm build
```

---

## Pull Request Process

### Before Submitting

1. **Ensure tests pass**: `pnpm test`
2. **Ensure types check**: `pnpm typecheck`
3. **Ensure linting passes**: `pnpm lint`
4. **Update documentation** if your change affects user-facing behavior
5. **Add tests** for new functionality

### PR Guidelines

1. **Keep PRs focused** — One feature or fix per PR
2. **Write a clear description** — Explain what and why
3. **Link related issues** — Use "Fixes #123" or "Closes #123"
4. **Respond to feedback** — Be open to suggestions

### PR Template

Your PR description should include:

```markdown
## Summary

Brief description of the changes.

## Motivation

Why is this change needed?

## Changes

- List of specific changes
- Another change

## Testing

How was this tested?

## Checklist

- [ ] Tests pass (`pnpm test`)
- [ ] Types check (`pnpm typecheck`)
- [ ] Linting passes (`pnpm lint`)
- [ ] Documentation updated (if applicable)
```

---

## Coding Standards

### TypeScript Guidelines

- **Strict mode** — Project uses `strict: true`
- **Explicit types** — Prefer explicit types over `any`
- **Immutability** — Use `const` and `readonly` where possible
- **Null safety** — Handle `null` and `undefined` explicitly

### Style Guidelines

This project uses [Biome](https://biomejs.dev/) for linting and formatting.

```bash
# Check formatting and linting
pnpm lint

# Auto-fix issues
pnpm lint:fix

# Format code
pnpm format
```

### Architecture Guidelines

- **No backward compatibility** — Prefer clean rewrites over migration shims
- **Defense in depth** — Security features should layer
- **Fail closed** — When in doubt, deny access
- **Explicit over implicit** — Make behavior clear

### Code Organization

```typescript
// File structure
// 1. Imports (external, then internal)
// 2. Types/interfaces
// 3. Constants
// 4. Main exports
// 5. Helper functions

import { z } from 'zod';
import { logger } from '../logging.js';

// Types
export interface MyFeature {
  // ...
}

// Schema
export const MyFeatureSchema = z.object({
  // ...
});

// Main export
export function doSomething(): void {
  // ...
}

// Helpers (private)
function helper(): void {
  // ...
}
```

---

## Testing

### Running Tests

```bash
# Run all tests
pnpm test

# Run in watch mode
pnpm test:watch

# Run with coverage
pnpm test:coverage
```

### Writing Tests

Tests use [Vitest](https://vitest.dev/). Place test files next to source files:

```
src/
├── security/
│   ├── rate-limit.ts
│   └── rate-limit.test.ts
```

Example test:

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { createRateLimiter } from './rate-limit.js';

describe('RateLimiter', () => {
  let limiter: ReturnType<typeof createRateLimiter>;

  beforeEach(() => {
    limiter = createRateLimiter({ perMinute: 10 });
  });

  it('should allow requests within limit', async () => {
    const result = await limiter.check('user-1');
    expect(result.allowed).toBe(true);
  });

  it('should block requests exceeding limit', async () => {
    // Make 10 requests
    for (let i = 0; i < 10; i++) {
      await limiter.check('user-1');
    }

    // 11th should be blocked
    const result = await limiter.check('user-1');
    expect(result.allowed).toBe(false);
  });
});
```

### Test Categories

- **Unit tests** — Test individual functions/classes
- **Integration tests** — Test component interactions
- **E2E tests** — Test full message flow (when applicable)

---

## Documentation

### Code Documentation

- **JSDoc comments** for public APIs
- **Inline comments** for complex logic
- **README updates** for user-facing changes

Example:

```typescript
/**
 * Creates a rate limiter with the specified configuration.
 *
 * @param config - Rate limit configuration
 * @returns A rate limiter instance
 *
 * @example
 * ```typescript
 * const limiter = createRateLimiter({ perMinute: 10, perHour: 100 });
 * const result = await limiter.check('user-123');
 * if (!result.allowed) {
 *   console.log(`Rate limited. Retry after ${result.retryAfter}ms`);
 * }
 * ```
 */
export function createRateLimiter(config: RateLimitConfig): RateLimiter {
  // ...
}
```

### Architecture Documentation

For significant architectural changes, update:

1. **README.md** — Architecture diagrams and overview
2. **CLAUDE.md** — Developer guidelines

---

## Security

### Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

### Security-Sensitive Areas

When modifying these areas, be extra careful:

- **`src/security/`** — All security components
- **`src/sandbox/`** — OS-level sandbox configuration
- **`src/totp-daemon/`** — TOTP secret handling
- **`src/sdk/`** — Tool permissions and allowlists

### Security Review Checklist

For security-related changes:

- [ ] Does this introduce new attack vectors?
- [ ] Are inputs validated?
- [ ] Are secrets properly protected?
- [ ] Does this maintain the principle of least privilege?
- [ ] Is the sandbox configuration still restrictive enough?

---

## Questions?

If you have questions about contributing:

1. Check existing [issues](https://github.com/avivsinai/telclaude/issues)
2. Open a [discussion](https://github.com/avivsinai/telclaude/discussions)
3. Ask in your PR

Thank you for contributing!
