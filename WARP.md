# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

A production-ready Node.js Express application with Neon Database integration, featuring dual environment configurations (development with Neon Local proxy, production with direct Neon Cloud connection). The application implements JWT authentication, role-based rate limiting via Arcjet, and comprehensive security middleware.

## Development Commands

### Environment Setup

```powershell
# Development environment
cp .env.development .env

# Production environment
cp .env.production .env
```

### Docker Operations

**Development:**

```powershell
# Start development environment (with Neon Local proxy)
docker-compose -f docker-compose.dev.yml up --build

# Start in background
docker-compose -f docker-compose.dev.yml up -d --build

# Stop services
docker-compose -f docker-compose.dev.yml down

# View logs
docker-compose -f docker-compose.dev.yml logs -f app
```

**Production:**

```powershell
# Start production environment (direct Neon Cloud connection)
docker-compose -f docker-compose.prod.yml up --build -d

# View production logs
docker-compose -f docker-compose.prod.yml logs -f app
```

### Database Management

```powershell
# Run database migrations (development)
docker-compose -f docker-compose.dev.yml exec app npm run db:migrate

# Generate new migrations
docker-compose -f docker-compose.dev.yml exec app npm run db:generate

# Push schema changes
docker-compose -f docker-compose.dev.yml exec app npm run db:push

# Open Drizzle Studio (database GUI)
docker-compose -f docker-compose.dev.yml exec app npm run db:studio
```

### Code Quality

```powershell
# Run ESLint
npm run lint

# Format code with Prettier
npm run format
```

### Local Development (non-Docker)

```powershell
# Install dependencies
npm ci

# Run in development mode with nodemon
npm run dev

# Run in production mode
npm start
```

## Architecture Overview

### Environment Configuration Strategy

The application uses a sophisticated dual-environment setup:

**Development Mode:**

- Uses Neon Local proxy (`neon-local` service) for ephemeral database branches
- Each container start creates a fresh database branch tied to Git branch
- Database URL: `postgres://neon:npg@neon-local:5432/main?sslmode=require`
- Enables hot reloading via volume mounts
- Requires `NEON_API_KEY`, `NEON_PROJECT_ID`, and `PARENT_BRANCH_ID` environment variables

**Production Mode:**

- Direct connection to Neon Cloud database (no proxy)
- Production-hardened: read-only filesystem, dropped capabilities, non-root user
- Resource limits and health checks enabled
- Requires full `DATABASE_URL` connection string

**Key Distinction:** The `src/config/database.js` configures Neon serverless driver differently based on `NODE_ENV`:

- In development: Routes through `http://neon-local:5432/sql` with insecure WebSockets
- In production: Uses standard Neon Cloud connection

### Application Structure

**Entry Point Flow:**

1. `src/index.js` - Loads environment variables and imports server
2. `src/server.js` - Starts Express server on specified port
3. `src/app.js` - Configures Express middleware and routes

**Core Middleware Stack (in order):**

1. Helmet (security headers)
2. CORS
3. JSON body parser
4. Cookie parser
5. Morgan (HTTP logging via Winston)
6. Custom security middleware (Arcjet integration)

**Security Middleware (`src/middleware/security.middleware.js`):**

- Integrates Arcjet for bot detection, shield protection, and rate limiting
- Implements role-based rate limits:
  - Admin: 20 requests/min
  - User: 10 requests/min
  - Guest: 5 requests/min
- Logs security events (bot detection, shield blocks, rate limit violations) via Winston

**Database Layer:**

- Uses Drizzle ORM with `@neondatabase/serverless` driver
- Schema defined in `src/models/user.model.js`
- Connection configured in `src/config/database.js`
- Migrations managed via Drizzle Kit (config: `drizzle.config.js`)

**Authentication:**

- JWT-based authentication (utility: `src/utils/jwt.js`)
- Token expiry: 1 day
- Cookie-based token storage (helper: `src/utils/cookies.js`)
- Input validation using Zod schemas (`src/validations/auth.validation.js`)
- Password hashing with bcrypt
- Routes: `/api/auth/sign-up`, `/api/auth/sign-in`, `/api/auth/sign-out`

**Logging:**

- Winston logger configured in `src/config/logger.js`
- Separate log files: `logs/error.log` and `logs/combined.log`
- Console logging in non-production environments
- HTTP request logging via Morgan integration

### Import Aliases

The project uses Node.js subpath imports (ES modules):

```javascript
#config/*       -> ./src/config/*
#controllers/*  -> ./src/controllers/*
#middleware/*   -> ./src/middleware/*
#models/*       -> ./src/models/*
#routes/*       -> ./src/routes/*
#services/*     -> ./src/services/*
#utils/*        -> ./src/utils/*
#validations/*  -> ./src/validations/*
```

Use these aliases instead of relative imports for cleaner code.

### API Endpoints

**Health & Status:**

- `GET /` - Basic connectivity test
- `GET /health` - Returns JSON with status, timestamp, and uptime
- `GET /api` - API status check

**Authentication:**

- `POST /api/auth/sign-up` - User registration
- `POST /api/auth/sign-in` - User login (returns JWT)
- `POST /api/auth/sign-out` - User logout

**Users:**

- `GET /api/users/*` - User-related endpoints (implementation in `src/routes/users.routes.js`)

## Key Dependencies

- **Express.js** - Web framework
- **Drizzle ORM** - Database ORM
- **@neondatabase/serverless** - Neon Database driver
- **Arcjet** - Security (bot detection, shield, rate limiting)
- **Helmet** - Security headers
- **Winston** - Logging
- **JWT** - Authentication tokens
- **Zod** - Schema validation
- **bcrypt/bcryptjs** - Password hashing

## Important Notes

### Neon Database Configuration

- Development uses ephemeral branches that are automatically created and cleaned up
- The `.neon_local/` directory persists branch data per Git branch
- Production connects directly to Neon Cloud - no local proxy

### Docker Build Stages

The Dockerfile uses multi-stage builds:

- `base` - Common setup layer
- `development` - Includes dev dependencies, runs with nodemon
- `prod-deps` - Production dependencies only
- `production` - Optimized production image with non-root user

### Code Style

- ES modules (`"type": "module"` in package.json)
- ESLint enforces: no-var, prefer-const, arrow functions, Prettier formatting
- Prettier config: single quotes, 2-space indent, semicolons, 80-char line width

### Testing Framework

The ESLint config includes Jest globals for test files in `tests/**/*.js`, but no test files currently exist in the repository.

## Troubleshooting

### Neon Local Connection Issues

- Verify `NEON_API_KEY`, `NEON_PROJECT_ID`, and `PARENT_BRANCH_ID` in `.env`
- Check Neon Local container logs: `docker-compose -f docker-compose.dev.yml logs neon-local`
- Ensure parent branch exists in Neon project

### Database Migrations

- Always run migrations after pulling schema changes
- Use `npm run db:generate` to create new migrations from schema changes
- Use `npm run db:migrate` or `npm run db:push` to apply migrations

### Docker Issues

- Clear build cache: `docker system prune -a`
- Verify Docker is running: `docker info`
- Check service health: `docker-compose -f docker-compose.dev.yml ps`
