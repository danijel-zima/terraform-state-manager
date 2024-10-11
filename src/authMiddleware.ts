import { Context, Next } from 'hono';
import { Env } from './types';
import { hashPassword, verifyPassword } from './utils';

interface User {
  username: string;
  project: string;
}

type AuthContext = Context<{ Bindings: Env, Variables: { user: User } }>;

// Helper function to handle unauthorized requests
async function handleUnauthorized(c: AuthContext, message: string): Promise<Response> {
  console.log(`Debug: ${message}`);
  return c.text('Unauthorized', 401);
}

// Middleware for Bearer token authentication
export function bearerAuth(options: { token: string }) {
  return async (c: AuthContext, next: Next) => {
    const authHeader = c.req.header('Authorization');
    console.log(`Debug: Authorization header received`);
    
    if (!authHeader) {
      return handleUnauthorized(c, 'Missing Authorization header');
    }
    
    if (!authHeader.startsWith('Bearer ')) {
      return handleUnauthorized(c, 'Invalid Authorization header format for Bearer token');
    }
    
    const token = authHeader.split(' ')[1];
    console.log(`Debug: Token extracted from Authorization header`);
    
    if (!token) {
      return handleUnauthorized(c, 'Missing Bearer token');
    }
    
    if (!options.token) {
      console.error('AUTH_TOKEN is not provided to bearerAuth');
      return c.text('Server configuration error', 500);
    }
    
    console.log(`Debug: Comparing received token with expected token`);
    if (token !== options.token) {
      return handleUnauthorized(c, 'Invalid Bearer token');
    }
    
    console.log('Debug: Bearer token validated successfully');
    c.set('user', { username: 'admin', project: 'all' });
    await next();
  };
}

// Middleware for combined Bearer and Basic authentication
export async function combinedAuth(c: AuthContext, next: Next) {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader) {
    return handleUnauthorized(c, 'Missing Authorization header');
  }
  
  if (authHeader.startsWith('Bearer ')) {
    return bearerAuth({ token: c.env.AUTH_TOKEN })(c, next);
  } else if (authHeader.startsWith('Basic ')) {
    return basicAuth(c, next);
  } else {
    return handleUnauthorized(c, 'Invalid Authorization header format');
  }
}

// Middleware for Basic authentication
export async function basicAuth(c: AuthContext, next: Next) {
  const authHeader = c.req.header('Authorization');
  console.log(`Debug: Authorization header received`);
  
  if (!authHeader) {
    return handleUnauthorized(c, 'Missing Authorization header');
  }
  
  if (!authHeader.startsWith('Basic ')) {
    return handleUnauthorized(c, 'Invalid Authorization header format for Basic auth');
  }

  const [username, password] = atob(authHeader.split(' ')[1]).split(':');
  console.log(`Debug: Attempting authentication for user: ${username}`);
  
  const user = await c.env.DB.prepare('SELECT * FROM auth WHERE username = ?')
    .bind(username)
    .first<{ username: string; password: string; project: string }>();

  if (!user) {
    return handleUnauthorized(c, `User not found: ${username}`);
  }

  console.log(`Debug: User found in database: ${username}`);
  console.log(`Debug: Retrieved hashed password from database`);

  const passwordMatch = await verifyPassword(password, user.password);
  console.log(`Debug: Password match result: ${passwordMatch}`);
  
  if (!passwordMatch && passwordMatch !== undefined) {
    return handleUnauthorized(c, `Authentication failed for user: ${username}`);
  }

  await c.env.DB.prepare('UPDATE auth SET last_login = CURRENT_TIMESTAMP WHERE username = ?')
    .bind(username)
    .run();

  console.log(`Debug: Authentication successful for user: ${username}`);
  c.set('user', { username: user.username, project: user.project });
  await next();
}

// Middleware for project-based authorization
export async function projectAuth(c: AuthContext, next: Next) {
  const user = c.get('user');
  
  if (!user) {
    console.log('Debug: User object not found in context');
    return c.text('Unauthorized', 401);
  }

  const url = new URL(c.req.url);
  const pathParts = url.pathname.split('/');
  const projectName = pathParts[3]; // Assuming the URL structure is /terraform/lock/<projectName>/...
  const statePath = pathParts.slice(4).join('/');
  
  console.log(`Debug: projectAuth - User: ${user.username}, Project: ${projectName || 'undefined'}, State: ${statePath || 'undefined'}`);

  if (projectName) {
    if (user.project !== 'all' && user.project !== projectName) {
      console.log(`Debug: User ${user.username} not authorized for project: ${projectName}`);
      return c.text('Forbidden', 403);
    }
  } else {
    console.log(`Debug: No projectName found in URL for user: ${user.username}`);
    return c.text('Bad Request: Missing project name', 400);
  }

  console.log(`Debug: User ${user.username} authorized for project: ${projectName}, state path: ${statePath}`);
  await next();
}
