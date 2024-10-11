import { Env as HonoEnv } from 'hono';

// Extended environment interface for the application
export interface Env extends HonoEnv {
  DB: D1Database;        // D1 database for storing metadata and locks
  BUCKET: R2Bucket;      // R2 bucket for storing Terraform state files
  AUTH_TOKEN: string;    // Authentication token for admin operations
}

