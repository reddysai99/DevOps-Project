# DevOps Project - Dockerized Node.js App with Neon Database

This project demonstrates a production-ready dockerized Node.js application using Neon Database with different configurations for development and production environments.

## 🏗️ Architecture Overview

- **Development**: Uses Neon Local proxy with ephemeral database branches
- **Production**: Connects directly to Neon Cloud database
- **Framework**: Node.js with Express.js
- **Database**: PostgreSQL via Neon Database
- **ORM**: Drizzle ORM
- **Containerization**: Docker with multi-stage builds

## 📋 Prerequisites

- Docker and Docker Compose installed
- Neon Database account and project
- Node.js 18+ (for local development)
- Git (for branch-based development features)

## 🔧 Environment Setup

### Neon Database Setup

1. Create a Neon account at [neon.tech](https://neon.tech)
2. Create a new project
3. Get your API key from Account Settings
4. Note your project ID from Project Settings

### Environment Variables

The application uses different environment files:

- `.env.development` - Development with Neon Local
- `.env.production` - Production with Neon Cloud
- `.env` - Current environment (not tracked in git)

## 🚀 Development Environment

### Setup

1. **Clone and configure:**

   ```bash
   git clone <repository>
   cd DevOps-Project
   ```

2. **Configure development environment:**

   ```bash
   cp .env.development .env
   ```

3. **Update `.env` with your Neon credentials:**
   ```env
   NEON_API_KEY=your_actual_neon_api_key
   NEON_PROJECT_ID=your_actual_project_id
   PARENT_BRANCH_ID=your_parent_branch_id
   ```

### Running with Docker Compose

**Start development environment:**

```bash
docker-compose -f docker-compose.dev.yml up --build
```

**Run in background:**

```bash
docker-compose -f docker-compose.dev.yml up -d --build
```

**Stop services:**

```bash
docker-compose -f docker-compose.dev.yml down
```

**View logs:**

```bash
docker-compose -f docker-compose.dev.yml logs -f app
```

### Development Features

- **Hot Reloading**: Code changes are reflected immediately
- **Ephemeral Database Branches**: Each container start creates a fresh database branch
- **Automatic Branch Cleanup**: Database branches are deleted when containers stop
- **Git Integration**: Persistent branches per Git branch (when configured)

### Database Management

**Run database migrations:**

```bash
docker-compose -f docker-compose.dev.yml exec app npm run db:migrate
```

**Generate new migrations:**

```bash
docker-compose -f docker-compose.dev.yml exec app npm run db:generate
```

**Open Drizzle Studio:**

```bash
docker-compose -f docker-compose.dev.yml exec app npm run db:studio
```

## 🏭 Production Environment

### Setup

1. **Configure production environment:**

   ```bash
   cp .env.production .env
   ```

2. **Update `.env` with production values:**
   ```env
   DATABASE_URL=postgres://username:password@ep-example-123456.us-east-1.aws.neon.tech/dbname?sslmode=require
   JWT_SECRET=your_secure_jwt_secret
   CORS_ORIGIN=https://yourdomain.com
   ```

### Running Production

**Start production environment:**

```bash
docker-compose -f docker-compose.prod.yml up --build -d
```

**Check health:**

```bash
curl http://localhost:3000/health
```

**View production logs:**

```bash
docker-compose -f docker-compose.prod.yml logs -f app
```

### Production Features

- **Security Hardened**: Read-only filesystem, dropped capabilities, non-root user
- **Resource Limited**: CPU and memory constraints
- **Health Monitoring**: Built-in health checks
- **Log Management**: Rotating logs with size limits
- **Direct Neon Cloud Connection**: No local proxy overhead

## 🔄 Database Connection Patterns

### Development (Neon Local)

```javascript
// Connection automatically routed through Neon Local proxy
const DATABASE_URL = 'postgres://neon:npg@neon-local:5432/main?sslmode=require';

// For Neon serverless driver (if used)
import { neon, neonConfig } from '@neondatabase/serverless';
neonConfig.fetchEndpoint = 'http://neon-local:5432/sql';
neonConfig.useSecureWebSocket = false;
neonConfig.poolQueryViaFetch = true;
```

### Production (Direct Neon Cloud)

```javascript
// Direct connection to Neon Cloud
const DATABASE_URL =
  'postgres://user:pass@ep-xxx.region.aws.neon.tech/db?sslmode=require';

// Standard configuration for production
```

## 📊 Monitoring & Health Checks

### Endpoints

- `GET /health` - Application health status
- `GET /` - Basic connectivity test
- `GET /api` - API status check

### Health Check Response

```json
{
  "status": "OK",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": 3600.123
}
```

## 🐛 Troubleshooting

### Common Issues

**Neon Local not starting:**

- Check API credentials in `.env`
- Verify project ID is correct
- Ensure parent branch exists

**Database connection errors:**

- Verify `DATABASE_URL` format
- Check network connectivity between services
- Confirm SSL requirements

**Build failures:**

- Clear Docker cache: `docker system prune -a`
- Check for file permission issues
- Verify Node.js version compatibility

### Debugging Commands

**Check service status:**

```bash
docker-compose -f docker-compose.dev.yml ps
```

**Access application shell:**

```bash
docker-compose -f docker-compose.dev.yml exec app sh
```

**Check Neon Local logs:**

```bash
docker-compose -f docker-compose.dev.yml logs neon-local
```

**Test database connectivity:**

```bash
docker-compose -f docker-compose.dev.yml exec app node -e "
const { db } = require('./src/config/database.js');
console.log('Database connected successfully');
"
```

## 📁 Project Structure

```
├── src/
│   ├── config/          # Configuration files
│   ├── controllers/     # Route controllers
│   ├── middleware/      # Express middleware
│   ├── models/          # Database models
│   ├── routes/          # API routes
│   ├── services/        # Business logic
│   ├── utils/           # Utility functions
│   └── validations/     # Input validation
├── docker-compose.dev.yml    # Development configuration
├── docker-compose.prod.yml   # Production configuration
├── Dockerfile               # Multi-stage Docker build
├── .env.development        # Development environment
├── .env.production         # Production environment
└── drizzle.config.js       # Database configuration
```

## 🔒 Security Considerations

### Development

- Local database with ephemeral branches
- Debug logging enabled
- Development-only middleware

### Production

- Environment variables for all secrets
- Read-only filesystem
- Minimal container privileges
- Security headers via Helmet.js
- Input validation and sanitization

## 📚 Additional Resources

- [Neon Local Documentation](https://neon.com/docs/local/neon-local)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Node.js Docker Guide](https://nodejs.org/en/docs/guides/nodejs-docker-webapp/)
- [Drizzle ORM Documentation](https://orm.drizzle.team/)
