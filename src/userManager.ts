import { Hono, Context } from 'hono';
import { Env } from './types';
import { hashPassword } from './utils';

const userManager = new Hono<{ Bindings: Env }>();

// Helper functions
async function checkUserExists(env: Env, username: string): Promise<boolean> {
  const existingUser = await env.DB.prepare('SELECT username FROM auth WHERE username = ?')
    .bind(username)
    .first();
  return !!existingUser;
}

async function fetchAllUsers(env: Env): Promise<any[]> {
  const users = await env.DB.prepare('SELECT username, project, role, last_login, created_at, updated_at FROM auth')
    .all();
  return users.results;
}

// User management functions
export async function listUsers(c: Context<{ Bindings: Env }>) {
  try {
    const users = await fetchAllUsers(c.env);
    return c.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    return c.text('Error fetching users', 500);
  }
}

export async function addUser(c: Context<{ Bindings: Env }>) {
  try {
    const { username, password, project, role } = await c.req.json();
    if (!username || !password || !project || !role) {
      return c.text('Missing required fields', 400);
    }

    if (await checkUserExists(c.env, username)) {
      return c.text('User already exists', 409);
    }

    const hashedPassword = await hashPassword(password);
    await c.env.DB.prepare('INSERT INTO auth (username, password, project, role) VALUES (?, ?, ?, ?)')
      .bind(username, hashedPassword, project, role)
      .run();
    return c.text('User added successfully', 201);
  } catch (error) {
    console.error('Error adding user:', error);
    return c.text('Error adding user', 500);
  }
}

export async function updateUser(c: Context<{ Bindings: Env }>) {
  const username = c.req.param('username');
  const { password, project, role } = await c.req.json();
  const updates = [];
  const binds = [];
  if (password) {
    updates.push('password = ?');
    binds.push(await hashPassword(password));
  }
  if (project) {
    updates.push('project = ?');
    binds.push(project);
  }
  if (role) {
    updates.push('role = ?');
    binds.push(role);
  }
  if (updates.length === 0) {
    return c.text('No updates provided', 400);
  }
  try {
    await c.env.DB.prepare(`UPDATE auth SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE username = ?`)
      .bind(...binds, username)
      .run();
    return c.text('User updated successfully', 200);
  } catch (error) {
    console.error('Error updating user:', error);
    return c.text('Error updating user', 500);
  }
}

export async function deleteUser(c: Context<{ Bindings: Env }>) {
  const username = c.req.param('username');
  try {
    await c.env.DB.prepare('DELETE FROM auth WHERE username = ?')
      .bind(username)
      .run();
    return c.text('User deleted successfully', 200);
  } catch (error) {
    console.error('Error deleting user:', error);
    return c.text('Error deleting user', 500);
  }
}

// Admin user initialization
async function initAdminUser(c: Context<{ Bindings: Env }>): Promise<Response> {
  const { username, password } = await c.req.json();
  if (!username || !password) {
    return c.text('Missing username or password', 400);
  }

  try {
    const hashedPassword = await hashPassword(password);
    await c.env.DB.prepare('INSERT INTO auth (username, password, project, role) VALUES (?, ?, ?, ?)')
      .bind(username, hashedPassword, 'all', 'admin')
      .run();
    return c.text('Initial admin user created successfully', 201);
  } catch (error) {
    console.error('Error creating initial admin user:', error);
    return c.text('Error creating initial admin user', 500);
  }
}

userManager.post('/config/init', initAdminUser);

// Backup function
export async function createUsersBackup(env: Env): Promise<any[]> {
  return await fetchAllUsers(env);
}

export default userManager;
