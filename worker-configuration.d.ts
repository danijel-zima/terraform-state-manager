// Generated by Wrangler
// After adding bindings to `wrangler.toml`, regenerate this interface via `npm run cf-typegen`
import { Env as HonoEnv } from 'hono';

export interface Env extends HonoEnv {
  DB: D1Database;
  BUCKET: R2Bucket;
}
