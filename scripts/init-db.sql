-- Sentinel Gateway Database Initialization
-- PostgreSQL 16+

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Set timezone
SET timezone = 'UTC';

-- Create indexes for better query performance
-- (Main tables are created by SQLAlchemy on startup)

-- Create materialized view for daily stats (optional optimization)
-- This would be refreshed periodically by a cron job in production

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE sentinel_audit TO sentinel;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sentinel;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sentinel;

-- Create read-only user for reporting (optional)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_readonly') THEN
        CREATE ROLE sentinel_readonly WITH LOGIN PASSWORD 'readonly_password';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE sentinel_audit TO sentinel_readonly;
GRANT USAGE ON SCHEMA public TO sentinel_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO sentinel_readonly;

-- Performance tuning for write-heavy workload
-- These would typically be set in postgresql.conf for production
-- ALTER SYSTEM SET synchronous_commit = off;  -- For higher throughput
-- ALTER SYSTEM SET wal_buffers = '64MB';
-- ALTER SYSTEM SET checkpoint_completion_target = 0.9;

SELECT 'Sentinel Gateway database initialized successfully' AS status;
