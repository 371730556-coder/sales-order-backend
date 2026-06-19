// ============================================================
// 销售工单管理系统 - 后端 API 服务
// Node.js + Express + PostgreSQL
// ============================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ============================================================
// 配置
// ============================================================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';

// 确保上传目录存在
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ============================================================
// 数据库连接池
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ============================================================
// Express 初始化
// ============================================================
const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 文件上传配置
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
  }),
  limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 },
});

// ============================================================
// 工具函数
// ============================================================
function maskPhone(phone) {
  if (!phone || phone.length < 7) return phone;
  return phone.substring(0, 3) + '****' + phone.substring(phone.length - 4);
}

function generateOrderNo() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `SO${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

function generateDeliveryNo() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `DL${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

async function writeAuditLog(client, actorId, action, targetType, targetId, beforeData, afterData, req) {
  await client.query(
    `INSERT INTO audit_logs (actor_id, action, target_type, target_id, before_data, after_data, ip_address, user_agent)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [actorId, action, targetType, targetId,
     beforeData ? JSON.stringify(beforeData) : null,
     afterData ? JSON.stringify(afterData) : null,
     req?.ip, req?.headers?.['user-agent']]
  );
}

// ============================================================
// 中间件：JWT 认证
// ============================================================
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未提供认证令牌' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: '认证令牌无效或已过期' });
  }
}

// 中间件：权限校验
function requirePermission(...permCodes) {
  return async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT DISTINCT p.code FROM permissions p
         JOIN role_permissions rp ON rp.permission_id = p.id
         JOIN user_roles ur ON ur.role_id = rp.role_id
         WHERE ur.user_id = $1`,
        [req.user.userId]
      );
      const userPerms = result.rows.map(r => r.code);
      const hasAll = permCodes.every(code => userPerms.includes(code));
      if (!hasAll) {
        return res.status(403).json({ error: '权限不足' });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

// 中间件：加载用户角色权限信息
async function loadUserContext(req, res, next) {
  try {
    // 优先读取用户直接权限
    const permResult = await pool.query(
      `SELECT p.code FROM permissions p
       JOIN user_permissions up ON up.permission_id = p.id
       WHERE up.user_id = $1`,
      [req.user.userId]
    );
    let permissions = permResult.rows.map(r => r.code);

    // 如果没有直接权限，读取角色权限作为基础
    if (permissions.length === 0) {
      const roleResult = await pool.query(
        `SELECT DISTINCT p.code FROM permissions p
         JOIN role_permissions rp ON rp.permission_id = p.id
         JOIN user_roles ur ON ur.role_id = rp.role_id
         WHERE ur.user_id = $1`,
        [req.user.userId]
      );
      permissions = roleResult.rows.map(r => r.code);
    }

    req.userPermissions = permissions;
    next();
  } catch (err) {
    next(err);
  }
}

// ============================================================
// 路由：认证
// ============================================================

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: '请输入用户名和密码' });
    }

    const result = await pool.query(
      'SELECT id, username, password_hash, display_name, phone, status FROM users WHERE username = $1 AND deleted_at IS NULL',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const user = result.rows[0];

    if (user.status !== 'active') {
      return res.status(403).json({ error: '账号已被禁用' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // 更新最后登录时间
    await pool.query('UPDATE users SET last_login_at = now() WHERE id = $1', [user.id]);

    const token = jwt.sign(
      { userId: user.id, username: user.username, displayName: user.display_name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    const refreshToken = jwt.sign(
      { userId: user.id, type: 'refresh' },
      JWT_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    // 获取用户菜单 - 优先直接分配，其次角色菜单
    const menusResult = await pool.query(
      `SELECT DISTINCT mi.code, mi.title, mi.path, mi.icon
       FROM menu_items mi
       LEFT JOIN user_menu_items umi ON umi.menu_item_id = mi.id AND umi.user_id = $1
       LEFT JOIN role_menu_items rmi ON rmi.menu_item_id = mi.id
       LEFT JOIN user_roles ur ON ur.role_id = rmi.role_id AND ur.user_id = $1
       WHERE mi.is_active = true AND (umi.user_id IS NOT NULL OR ur.user_id IS NOT NULL)
       ORDER BY mi.sort_order`,
      [user.id]
    );

    // 如果没有直接分配菜单，用角色默认菜单
    if (menusResult.rows.length === 0) {
      const defaultMenus = await pool.query(
        `SELECT mi.code, mi.title, mi.path, mi.icon
         FROM menu_items mi
         JOIN role_menu_items rmi ON rmi.menu_item_id = mi.id
         JOIN user_roles ur ON ur.role_id = rmi.role_id
         WHERE ur.user_id = $1 AND mi.is_active = true
         ORDER BY mi.sort_order`,
        [user.id]
      );
      menusResult.rows = defaultMenus.rows;
    }

    res.json({
      token,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.display_name,
        phone: user.phone,
      },
      menus: menusResult.rows,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// POST /api/auth/refresh
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: '缺少 refreshToken' });

    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    if (decoded.type !== 'refresh') return res.status(401).json({ error: '无效的 refreshToken' });

    const userResult = await pool.query(
      'SELECT id, username, display_name FROM users WHERE id = $1 AND status = $2 AND deleted_at IS NULL',
      [decoded.userId, 'active']
    );
    if (userResult.rows.length === 0) return res.status(401).json({ error: '用户不可用' });

    const user = userResult.rows[0];
    const token = jwt.sign(
      { userId: user.id, username: user.username, displayName: user.display_name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({ token });
  } catch (err) {
    res.status(401).json({ error: 'refreshToken 无效或已过期' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authenticate, loadUserContext, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, display_name, phone, email, status FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '用户不存在' });

    // 获取用户菜单 - 优先直接分配
    const menusResult = await pool.query(
      `SELECT DISTINCT mi.code, mi.title, mi.path, mi.icon FROM menu_items mi
       LEFT JOIN user_menu_items umi ON umi.menu_item_id = mi.id AND umi.user_id = $1
       LEFT JOIN role_menu_items rmi ON rmi.menu_item_id = mi.id
       LEFT JOIN user_roles ur ON ur.role_id = rmi.role_id AND ur.user_id = $1
       WHERE mi.is_active = true AND (umi.user_id IS NOT NULL OR ur.user_id IS NOT NULL)
       ORDER BY mi.sort_order`,
      [req.user.userId]
    );

    // 获取角色列表
    const rolesResult = await pool.query(
      `SELECT r.code, r.name FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1`,
      [req.user.userId]
    );

    res.json({
      user: result.rows[0],
      roles: rolesResult.rows,
      permissions: req.userPermissions,
      menus: menusResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============================================================
// 路由：用户管理（需要 admin 权限）
// ============================================================

// GET /api/users
app.get('/api/users', authenticate, requirePermission('user:view'), async (req, res) => {
  try {
    const { status, keyword, role, page = 1, pageSize = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(pageSize);
    const params = [];
    const conditions = ['u.deleted_at IS NULL'];

    if (status) { params.push(status); conditions.push(`u.status = $${params.length}`); }
    if (keyword) { params.push(`%${keyword}%`); conditions.push(`(u.username ILIKE $${params.length} OR u.display_name ILIKE $${params.length} OR u.phone ILIKE $${params.length})`); }

    const whereClause = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    let countParams = [...params], listParams = [...params];
    let havingClause = '';
    if (role) { listParams.push(role); havingClause = `HAVING $${listParams.length} = ANY(array_agg(r.code))`; countParams.push(role); }

    const countQuery = role
      ? `SELECT count(*) FROM (SELECT u.id FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id ${whereClause} GROUP BY u.id ${havingClause}) sub`
      : `SELECT count(*) FROM users u ${whereClause}`;

    const userQuery = role
      ? `SELECT u.id, u.username, u.display_name, u.phone, u.email, u.status, u.last_login_at, u.created_at, array_agg(r.code) as roles
         FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id
         ${whereClause} GROUP BY u.id ${havingClause}
         ORDER BY u.created_at DESC LIMIT $${listParams.length + 1} OFFSET $${listParams.length + 2}`
      : `SELECT u.id, u.username, u.display_name, u.phone, u.email, u.status, u.last_login_at, u.created_at, array_agg(r.code) as roles
         FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id
         ${whereClause} GROUP BY u.id
         ORDER BY u.created_at DESC LIMIT $${listParams.length + 1} OFFSET $${listParams.length + 2}`;

    const [countResult, usersResult] = await Promise.all([
      pool.query(countQuery, countParams),
      pool.query(userQuery, [...listParams, parseInt(pageSize), offset]),
    ]);

    res.json({
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      pageSize: parseInt(pageSize),
      data: usersResult.rows.map(u => ({...u, permission_count: 0})),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// GET /api/users/:id - 单个用户详情（含权限和菜单）
app.get('/api/users/:id', authenticate, requirePermission('user:view'), async (req, res) => {
  try {
    const { id } = req.params;
    const userResult = await pool.query(
      `SELECT u.id, u.username, u.display_name, u.phone, u.email, u.status,
              array_agg(DISTINCT r.code) as roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.id = $1 AND u.deleted_at IS NULL
       GROUP BY u.id`, [id]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: '用户不存在' });

    const [permResult, menuResult] = await Promise.all([
      pool.query('SELECT p.code FROM permissions p JOIN user_permissions up ON up.permission_id = p.id WHERE up.user_id = $1', [id]),
      pool.query('SELECT m.code FROM menu_items m JOIN user_menu_items um ON um.menu_item_id = m.id WHERE um.user_id = $1', [id]),
    ]);

    res.json({
      ...userResult.rows[0],
      permissions: permResult.rows.map(r => r.code),
      menus: menuResult.rows.map(r => r.code),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// POST /api/users
app.post('/api/users', authenticate, requirePermission('user:create'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { username, password, displayName, phone, email, roleCodes, permissionCodes, menuCodes } = req.body;
    if (!username || !password || !displayName) {
      return res.status(400).json({ error: '用户名、密码、姓名为必填' });
    }
    if (!roleCodes || !Array.isArray(roleCodes) || roleCodes.length === 0) {
      return res.status(400).json({ error: '请至少选择一个角色' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await client.query('BEGIN');

    const userResult = await client.query(
      `INSERT INTO users (username, password_hash, display_name, phone, email)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [username, passwordHash, displayName, phone || null, email || null]
    );
    const userId = userResult.rows[0].id;

    // 分配角色
    const roleResult = await client.query(
      `SELECT id, code FROM roles WHERE code = ANY($1)`, [roleCodes]
    );
    for (const role of roleResult.rows) {
      await client.query(
        'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [userId, role.id]
      );
    }

    // 直接分配权限
    if (permissionCodes && Array.isArray(permissionCodes)) {
      const permResult = await client.query(`SELECT id, code FROM permissions WHERE code = ANY($1)`, [permissionCodes]);
      for (const p of permResult.rows) {
        await client.query('INSERT INTO user_permissions (user_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, p.id]);
      }
    }

    // 直接分配菜单
    if (menuCodes && Array.isArray(menuCodes)) {
      const menuResult = await client.query(`SELECT id, code FROM menu_items WHERE code = ANY($1)`, [menuCodes]);
      for (const m of menuResult.rows) {
        await client.query('INSERT INTO user_menu_items (user_id, menu_item_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, m.id]);
      }
    }

    await client.query('COMMIT');

    await writeAuditLog(client, req.user.userId, 'user:create', 'user', userId, null, { username, displayName, roleCodes, permissionCodes, menuCodes }, req);

    res.status(201).json({ id: userId, username, displayName });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: '用户名已存在' });
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// PATCH /api/users/:id
app.patch('/api/users/:id', authenticate, requirePermission('user:update'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { displayName, phone, email, roleCodes, password } = req.body;

    await client.query('BEGIN');

    const sets = [];
    const params = [id];
    if (displayName !== undefined) { params.push(displayName); sets.push(`display_name = $${params.length}`); }
    if (phone !== undefined) { params.push(phone); sets.push(`phone = $${params.length}`); }
    if (email !== undefined) { params.push(email); sets.push(`email = $${params.length}`); }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      params.push(hash);
      sets.push(`password_hash = $${params.length}`);
    }
    sets.push(`updated_at = now()`);

    if (sets.length > 1) {
      await client.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $1`, params);
    }

    // 更新角色
    if (roleCodes && Array.isArray(roleCodes)) {
      await client.query('DELETE FROM user_roles WHERE user_id = $1', [id]);
      const roleResult = await client.query('SELECT id, code FROM roles WHERE code = ANY($1)', [roleCodes]);
      for (const role of roleResult.rows) {
        await client.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [id, role.id]);
      }
    }

    // 更新直接权限
    if (req.body.permissionCodes !== undefined && Array.isArray(req.body.permissionCodes)) {
      await client.query('DELETE FROM user_permissions WHERE user_id = $1', [id]);
      const permResult = await client.query('SELECT id, code FROM permissions WHERE code = ANY($1)', [req.body.permissionCodes]);
      for (const p of permResult.rows) {
        await client.query('INSERT INTO user_permissions (user_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [id, p.id]);
      }
    }

    // 更新直接菜单
    if (req.body.menuCodes !== undefined && Array.isArray(req.body.menuCodes)) {
      await client.query('DELETE FROM user_menu_items WHERE user_id = $1', [id]);
      const menuResult = await client.query('SELECT id, code FROM menu_items WHERE code = ANY($1)', [req.body.menuCodes]);
      for (const m of menuResult.rows) {
        await client.query('INSERT INTO user_menu_items (user_id, menu_item_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [id, m.id]);
      }
    }

    await client.query('COMMIT');

    const userResult = await client.query('SELECT id, username, display_name, phone, email, status FROM users WHERE id = $1', [id]);
    res.json(userResult.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// PATCH /api/users/:id/status
app.patch('/api/users/:id/status', authenticate, requirePermission('user:update'), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!['active', 'inactive', 'locked'].includes(status)) {
      return res.status(400).json({ error: '无效的状态值' });
    }
    const result = await pool.query(
      'UPDATE users SET status = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL RETURNING id, username, status',
      [status, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// DELETE /api/users/:id
app.delete('/api/users/:id', authenticate, requirePermission('user:delete'), async (req, res) => {
  try {
    const { id } = req.params;
    // 软删除
    const result = await pool.query(
      'UPDATE users SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL RETURNING id',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
    res.json({ message: '用户已删除' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============================================================
// 路由：工单管理
// ============================================================

// GET /api/orders
app.get('/api/orders', authenticate, loadUserContext, async (req, res) => {
  try {
    const { status, keyword, createdBy, dateFrom, dateTo, page = 1, pageSize = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(pageSize);
    const params = [];
    const conditions = ['o.deleted_at IS NULL'];

    // 权限过滤：店员只能看自己的
    if (!req.userPermissions.includes('order:view_all')) {
      params.push(req.user.userId);
      conditions.push(`o.created_by = $${params.length}`);
    }

    if (status) { params.push(status); conditions.push(`o.status = $${params.length}`); }
    if (keyword) { params.push(`%${keyword}%`); conditions.push(`(o.order_no ILIKE $${params.length} OR o.customer_name ILIKE $${params.length} OR o.customer_phone ILIKE $${params.length})`); }
    if (createdBy) { params.push(createdBy); conditions.push(`o.created_by = $${params.length}`); }
    if (dateFrom) { params.push(dateFrom); conditions.push(`o.created_at >= $${params.length}`); }
    if (dateTo) { params.push(dateTo); conditions.push(`o.created_at <= $${params.length}`); }

    const whereClause = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const [countResult, ordersResult] = await Promise.all([
      pool.query(`SELECT count(*) FROM sales_orders o ${whereClause}`, params),
      pool.query(
        `SELECT o.*, u.display_name as created_by_name
         FROM sales_orders o
         LEFT JOIN users u ON u.id = o.created_by
         ${whereClause}
         ORDER BY o.created_at DESC
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, parseInt(pageSize), offset]
      ),
    ]);

    // 脱敏：非送货员/管理员角色对电话脱敏
    const canViewFull = req.userPermissions.includes('delivery:view_own') || req.userPermissions.includes('user:manage_role');
    const data = ordersResult.rows.map(o => ({
      ...o,
      customer_phone: canViewFull ? o.customer_phone : maskPhone(o.customer_phone),
    }));

    res.json({
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      pageSize: parseInt(pageSize),
      data,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// POST /api/orders
app.post('/api/orders', authenticate, requirePermission('order:create'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { customerName, customerPhone, customerAddress, deliveryRequirement, paymentMethod, deliveryTime, items, status = 'draft' } = req.body;

    if (status === 'pending' && (!customerName || !customerPhone || !customerAddress)) {
      return res.status(400).json({ error: '提交工单需填写顾客姓名、电话和地址' });
    }
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: '请至少添加一个商品' });
    }

    await client.query('BEGIN');

    const totalAmount = items.reduce((sum, i) => sum + i.quantity * i.unitPrice, 0);
    const orderNo = generateOrderNo();

    const orderResult = await client.query(
      `INSERT INTO sales_orders (order_no, customer_name, customer_phone, customer_address, delivery_requirement, payment_method, delivery_time, status, total_amount, created_by, submitted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [orderNo, customerName || '(待填写)', customerPhone || '(待填写)', customerAddress || '(待填写)',
       deliveryRequirement || '普通配送', paymentMethod || 'cash', deliveryTime || null,
       status, totalAmount, req.user.userId,
       status === 'pending' ? new Date() : null]
    );
    const orderId = orderResult.rows[0].id;

    // 插入商品明细
    for (const item of items) {
      await client.query(
        `INSERT INTO sales_order_items (order_id, product_name, quantity, unit_price, line_amount, remark)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [orderId, item.name, item.quantity, item.unitPrice, item.quantity * item.unitPrice, item.remark || null]
      );
    }

    // 状态日志
    await client.query(
      `INSERT INTO order_status_logs (order_id, to_status, operator_id, note) VALUES ($1, $2, $3, $4)`,
      [orderId, status, req.user.userId, status === 'draft' ? '保存草稿' : '提交工单']
    );

    await client.query('COMMIT');

    await writeAuditLog(client, req.user.userId, 'order:create', 'sales_order', orderId, null, { orderNo, status }, req);

    res.status(201).json(orderResult.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// GET /api/orders/:id
app.get('/api/orders/:id', authenticate, loadUserContext, async (req, res) => {
  try {
    const { id } = req.params;

    const orderResult = await pool.query('SELECT * FROM sales_orders WHERE id = $1 AND deleted_at IS NULL', [id]);
    if (orderResult.rows.length === 0) return res.status(404).json({ error: '工单不存在' });

    const order = orderResult.rows[0];

    // 权限检查
    const canViewAll = req.userPermissions.includes('order:view_all');
    if (!canViewAll && order.created_by !== req.user.userId) {
      // 检查是否是派单员或送货员（有查看权限）
      const canViewPool = req.userPermissions.includes('dispatch:view_pool');
      const canDeliver = req.userPermissions.includes('delivery:view_own');
      if (!canViewPool && !canDeliver) {
        return res.status(403).json({ error: '权限不足' });
      }
    }

    const [itemsResult, logsResult, deliveryResult] = await Promise.all([
      pool.query('SELECT * FROM sales_order_items WHERE order_id = $1 ORDER BY id', [id]),
      pool.query(
        `SELECT l.*, u.display_name as operator_name
         FROM order_status_logs l LEFT JOIN users u ON u.id = l.operator_id
         WHERE l.order_id = $1 ORDER BY l.created_at ASC`, [id]
      ),
      pool.query(
        `SELECT d.*, u.display_name as courier_name, u2.display_name as dispatcher_name
         FROM delivery_tasks d
         LEFT JOIN users u ON u.id = d.courier_id
         LEFT JOIN users u2 ON u2.id = d.dispatcher_id
         WHERE d.order_id = $1 ORDER BY d.created_at DESC LIMIT 1`, [id]
      ),
    ]);

    // 脱敏：派单人员不能看完整电话
    const canViewFull = req.userPermissions.includes('delivery:view_own')
      || req.userPermissions.includes('user:manage_role')
      || order.created_by === req.user.userId;
    if (!canViewFull) {
      order.customer_phone = maskPhone(order.customer_phone);
    }

    res.json({
      ...order,
      items: itemsResult.rows,
      logs: logsResult.rows,
      delivery: deliveryResult.rows[0] || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// PATCH /api/orders/:id
app.patch('/api/orders/:id', authenticate, loadUserContext, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    const orderResult = await client.query('SELECT * FROM sales_orders WHERE id = $1 AND deleted_at IS NULL', [id]);
    if (orderResult.rows.length === 0) return res.status(404).json({ error: '工单不存在' });

    const order = orderResult.rows[0];

    // 只能修改草稿或待派单
    if (!['draft', 'pending'].includes(order.status)) {
      return res.status(400).json({ error: '当前状态不允许修改' });
    }
    // 权限检查
    if (order.created_by !== req.user.userId && !req.userPermissions?.includes('user:manage_role')) {
      return res.status(403).json({ error: '权限不足' });
    }

    const { customerName, customerPhone, customerAddress, deliveryRequirement, items } = req.body;
    const sets = [];
    const params = [id];
    if (customerName !== undefined) { params.push(customerName); sets.push(`customer_name = $${params.length}`); }
    if (customerPhone !== undefined) { params.push(customerPhone); sets.push(`customer_phone = $${params.length}`); }
    if (customerAddress !== undefined) { params.push(customerAddress); sets.push(`customer_address = $${params.length}`); }
    if (deliveryRequirement !== undefined) { params.push(deliveryRequirement); sets.push(`delivery_requirement = $${params.length}`); }
    sets.push(`updated_at = now()`);

    await client.query('BEGIN');

    await client.query(`UPDATE sales_orders SET ${sets.join(', ')} WHERE id = $1`, params);

    // 更新商品明细
    if (items && Array.isArray(items)) {
      await client.query('DELETE FROM sales_order_items WHERE order_id = $1', [id]);
      const totalAmount = items.reduce((sum, i) => sum + i.quantity * i.unitPrice, 0);
      for (const item of items) {
        await client.query(
          `INSERT INTO sales_order_items (order_id, product_name, quantity, unit_price, line_amount, remark)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [id, item.name, item.quantity, item.unitPrice, item.quantity * item.unitPrice, item.remark || null]
        );
      }
      await client.query('UPDATE sales_orders SET total_amount = $1 WHERE id = $2', [totalAmount, id]);
    }

    await client.query('COMMIT');

    res.json({ message: '工单已更新' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// POST /api/orders/:id/submit
app.post('/api/orders/:id/submit', authenticate, requirePermission('order:submit'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const orderResult = await client.query('SELECT * FROM sales_orders WHERE id = $1 AND deleted_at IS NULL', [id]);
    if (orderResult.rows.length === 0) return res.status(404).json({ error: '工单不存在' });

    const order = orderResult.rows[0];
    if (order.status !== 'draft') return res.status(400).json({ error: '只有草稿可以提交' });
    if (order.created_by !== req.user.userId) return res.status(403).json({ error: '只能提交自己的工单' });

    await client.query('BEGIN');

    await client.query(
      `UPDATE sales_orders SET status = 'pending', submitted_at = now(), updated_at = now() WHERE id = $1`, [id]
    );
    await client.query(
      `INSERT INTO order_status_logs (order_id, from_status, to_status, operator_id, note) VALUES ($1, 'draft', 'pending', $2, '提交工单')`,
      [id, req.user.userId]
    );

    await client.query('COMMIT');
    await writeAuditLog(client, req.user.userId, 'order:submit', 'sales_order', id, { status: 'draft' }, { status: 'pending' }, req);

    res.json({ message: '工单已提交' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// POST /api/orders/:id/cancel
app.post('/api/orders/:id/cancel', authenticate, requirePermission('order:cancel'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ error: '请填写取消原因' });

    const orderResult = await client.query('SELECT * FROM sales_orders WHERE id = $1 AND deleted_at IS NULL', [id]);
    if (orderResult.rows.length === 0) return res.status(404).json({ error: '工单不存在' });

    const order = orderResult.rows[0];
    if (!['draft', 'pending'].includes(order.status)) {
      return res.status(400).json({ error: '当前状态不允许取消' });
    }

    await client.query('BEGIN');

    await client.query(
      `UPDATE sales_orders SET status = 'cancelled', cancelled_by = $2, cancelled_reason = $3, cancelled_at = now(), updated_at = now() WHERE id = $1`,
      [id, req.user.userId, reason]
    );
    await client.query(
      `INSERT INTO order_status_logs (order_id, from_status, to_status, operator_id, note) VALUES ($1, $2, 'cancelled', $3, $4)`,
      [id, order.status, req.user.userId, reason]
    );

    // 如果有活跃配送任务，也取消
    await client.query(
      `UPDATE delivery_tasks SET status = 'cancelled', cancelled_at = now(), updated_at = now()
       WHERE order_id = $1 AND status IN ('assigned', 'accepted', 'picked_up', 'in_transit', 'delivered')`,
      [id]
    );

    await client.query('COMMIT');
    await writeAuditLog(client, req.user.userId, 'order:cancel', 'sales_order', id, { status: order.status }, { status: 'cancelled', reason }, req);

    res.json({ message: '工单已取消' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// GET /api/orders/:id/timeline
app.get('/api/orders/:id/timeline', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT l.*, u.display_name as operator_name
       FROM order_status_logs l LEFT JOIN users u ON u.id = l.operator_id
       WHERE l.order_id = $1 ORDER BY l.created_at ASC`, [id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============================================================
// 路由：派单管理
// ============================================================

// GET /api/dispatch/order-pool
app.get('/api/dispatch/order-pool', authenticate, requirePermission('dispatch:view_pool'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, u.display_name as created_by_name
       FROM sales_orders o
       LEFT JOIN users u ON u.id = o.created_by
       WHERE o.status = 'pending' AND o.deleted_at IS NULL
       ORDER BY o.created_at DESC`
    );

    // 派单员看到脱敏电话
    const data = result.rows.map(o => ({
      ...o,
      customer_phone: maskPhone(o.customer_phone),
    }));

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// POST /api/orders/:id/dispatch
app.post('/api/orders/:id/dispatch', authenticate, requirePermission('dispatch:assign'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { courierId, notes } = req.body;
    if (!courierId) return res.status(400).json({ error: '请选择送货员' });

    const orderResult = await client.query('SELECT * FROM sales_orders WHERE id = $1 AND status = $2 AND deleted_at IS NULL', [id, 'pending']);
    if (orderResult.rows.length === 0) return res.status(404).json({ error: '工单不存在或非待派单状态' });

    // 检查是否存在活跃配送（改派场景）
    const existingActive = await client.query(
      `SELECT id FROM delivery_tasks WHERE order_id = $1 AND status IN ('assigned', 'accepted', 'picked_up', 'in_transit', 'delivered')`,
      [id]
    );

    await client.query('BEGIN');

    // 关闭旧配送任务
    for (const old of existingActive.rows) {
      await client.query(
        `UPDATE delivery_tasks SET status = 'cancelled', cancelled_at = now(), updated_at = now() WHERE id = $1`,
        [old.id]
      );
      await client.query(
        `INSERT INTO delivery_status_logs (delivery_task_id, from_status, to_status, operator_id, note) VALUES ($1, NULL, 'cancelled', $2, '因改派而关闭')`,
        [old.id, req.user.userId]
      );
    }

    // 创建新配送任务
    const deliveryNo = generateDeliveryNo();
    const deliveryResult = await client.query(
      `INSERT INTO delivery_tasks (delivery_no, order_id, dispatcher_id, courier_id, clerk_id, status, notes, assigned_at)
       VALUES ($1, $2, $3, $4, $5, 'assigned', $6, now()) RETURNING *`,
      [deliveryNo, id, req.user.userId, courierId, orderResult.rows[0].created_by, notes || null]
    );

    // 更新工单状态
    await client.query(
      `UPDATE sales_orders SET status = 'dispatched', updated_at = now() WHERE id = $1`, [id]
    );
    await client.query(
      `INSERT INTO order_status_logs (order_id, from_status, to_status, operator_id, note) VALUES ($1, 'pending', 'dispatched', $2, $3)`,
      [id, req.user.userId, `分派给送货员 #${courierId}`]
    );
    await client.query(
      `INSERT INTO delivery_status_logs (delivery_task_id, to_status, operator_id, note) VALUES ($1, 'assigned', $2, $3)`,
      [deliveryResult.rows[0].id, req.user.userId, notes || null]
    );

    await client.query('COMMIT');
    await writeAuditLog(client, req.user.userId, 'dispatch:assign', 'delivery_task', deliveryResult.rows[0].id, null, { courierId, orderId: id }, req);

    res.status(201).json(deliveryResult.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// POST /api/delivery-tasks/:id/reassign
app.post('/api/delivery-tasks/:id/reassign', authenticate, requirePermission('dispatch:reassign'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { newCourierId, reason } = req.body;
    if (!newCourierId || !reason) return res.status(400).json({ error: '请选择新送货员并填写改派原因' });

    const taskResult = await client.query('SELECT * FROM delivery_tasks WHERE id = $1', [id]);
    if (taskResult.rows.length === 0) return res.status(404).json({ error: '配送任务不存在' });

    const task = taskResult.rows[0];
    if (['signed', 'cancelled', 'reassigned'].includes(task.status)) {
      return res.status(400).json({ error: '当前状态不允许改派' });
    }

    await client.query('BEGIN');

    const oldStatus = task.status;
    await client.query(
      `UPDATE delivery_tasks SET status = 'reassigned', updated_at = now() WHERE id = $1`, [id]
    );
    await client.query(
      `INSERT INTO delivery_status_logs (delivery_task_id, from_status, to_status, operator_id, note)
       VALUES ($1, $2, 'reassigned', $3, $4)`,
      [id, oldStatus, req.user.userId, reason]
    );

    const deliveryNo = generateDeliveryNo();
    const newResult = await client.query(
      `INSERT INTO delivery_tasks (delivery_no, order_id, dispatcher_id, courier_id, clerk_id, status, notes, assigned_at)
       VALUES ($1, $2, $3, $4, $5, 'assigned', $6, now()) RETURNING *`,
      [deliveryNo, task.order_id, req.user.userId, newCourierId, task.clerk_id, `改派自 ${task.delivery_no}: ${reason}`]
    );
    await client.query(
      `INSERT INTO delivery_status_logs (delivery_task_id, to_status, operator_id, note) VALUES ($1, 'assigned', $2, $3)`,
      [newResult.rows[0].id, req.user.userId, reason]
    );

    await client.query('COMMIT');
    res.json(newResult.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// ============================================================
// 路由：配送任务
// ============================================================

// GET /api/delivery-tasks
app.get('/api/delivery-tasks', authenticate, loadUserContext, async (req, res) => {
  try {
    const { status, page = 1, pageSize = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(pageSize);
    const params = [];
    const conditions = [];

    // 送货员只能看自己的
    if (!req.userPermissions.includes('order:view_all') && !req.userPermissions.includes('dispatch:view_pool')) {
      params.push(req.user.userId);
      conditions.push(`d.courier_id = $${params.length}`);
    }

    if (status) { params.push(status); conditions.push(`d.status = $${params.length}`); }

    const whereClause = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const [countResult, tasksResult] = await Promise.all([
      pool.query(`SELECT count(*) FROM delivery_tasks d ${whereClause}`, params),
      pool.query(
        `SELECT d.*, o.order_no, o.customer_name, o.customer_phone, o.customer_address, o.delivery_requirement,
                c.display_name as courier_name, dp.display_name as dispatcher_name, cl.display_name as clerk_name
         FROM delivery_tasks d
         JOIN sales_orders o ON o.id = d.order_id
         LEFT JOIN users c ON c.id = d.courier_id
         LEFT JOIN users dp ON dp.id = d.dispatcher_id
         LEFT JOIN users cl ON cl.id = d.clerk_id
         ${whereClause}
         ORDER BY d.created_at DESC
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, parseInt(pageSize), offset]
      ),
    ]);

    res.json({
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      pageSize: parseInt(pageSize),
      data: tasksResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// GET /api/delivery-tasks/:id
app.get('/api/delivery-tasks/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT d.*, o.order_no, o.customer_name, o.customer_phone, o.customer_address,
              o.delivery_requirement, o.total_amount, o.payment_method, o.delivery_time,
              c.display_name as courier_name, dp.display_name as dispatcher_name, cl.display_name as clerk_name
       FROM delivery_tasks d
       JOIN sales_orders o ON o.id = d.order_id
       LEFT JOIN users c ON c.id = d.courier_id
       LEFT JOIN users dp ON dp.id = d.dispatcher_id
       LEFT JOIN users cl ON cl.id = d.clerk_id
       WHERE d.id = $1`, [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '配送任务不存在' });

    const task = result.rows[0];

    // 获取商品明细
    const itemsResult = await pool.query(
      'SELECT product_name, quantity FROM sales_order_items WHERE order_id = $1', [task.order_id]
    );

    // 获取状态日志
    const logsResult = await pool.query(
      `SELECT l.*, u.display_name as operator_name
       FROM delivery_status_logs l LEFT JOIN users u ON u.id = l.operator_id
       WHERE l.delivery_task_id = $1 ORDER BY l.created_at ASC`, [id]
    );

    res.json({ ...task, items: itemsResult.rows, logs: logsResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 配送状态更新辅助函数
async function updateDeliveryTaskStatus(deliveryId, status, userId, note, locationLng, locationLat) {
  const client = await pool.connect();
  try {
    const validStatuses = ['in_transit', 'delivered', 'signed', 'failed'];
    if (!validStatuses.includes(status)) throw Object.assign(new Error('无效的状态'), { statusCode: 400 });

    const taskResult = await client.query('SELECT * FROM delivery_tasks WHERE id = $1', [deliveryId]);
    if (taskResult.rows.length === 0) throw Object.assign(new Error('配送任务不存在'), { statusCode: 404 });

    const task = taskResult.rows[0];
    if (task.courier_id !== userId) throw Object.assign(new Error('只能更新自己的配送任务'), { statusCode: 403 });
    if (['signed', 'cancelled', 'reassigned'].includes(task.status)) {
      throw Object.assign(new Error('终态任务不可修改'), { statusCode: 400 });
    }

    await client.query('BEGIN');

    const fromStatus = task.status;
    const timestampFields = {};
    if (status === 'in_transit') timestampFields.in_transit_at = new Date();
    if (status === 'delivered') timestampFields.delivered_at = new Date();
    if (status === 'signed') { timestampFields.signed_at = new Date(); if (!task.delivered_at) timestampFields.delivered_at = new Date(); }
    if (status === 'failed') { timestampFields.failed_at = new Date(); }

    const setClauses = ['status = $1', 'updated_at = now()'];
    const values = [status];
    for (const [col, val] of Object.entries(timestampFields)) {
      values.push(val);
      setClauses.push(`${col} = $${values.length}`);
    }
    if (status === 'failed' && note) {
      values.push(note);
      setClauses.push(`failed_reason = $${values.length}`);
    }
    values.push(deliveryId);
    await client.query(`UPDATE delivery_tasks SET ${setClauses.join(', ')} WHERE id = $${values.length}`, values);

    await client.query(
      `INSERT INTO delivery_status_logs (delivery_task_id, from_status, to_status, operator_id, note, location_lng, location_lat)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [deliveryId, fromStatus, status, userId, note || null, locationLng || null, locationLat || null]
    );

    const orderStatusMap = { in_transit: 'delivering', delivered: 'delivered', signed: 'completed', failed: 'exception' };
    const orderStatus = orderStatusMap[status];
    if (orderStatus) {
      const currentOrder = await client.query('SELECT status FROM sales_orders WHERE id = $1', [task.order_id]);
      const orderFromStatus = currentOrder.rows[0]?.status;
      await client.query(`UPDATE sales_orders SET status = $1, updated_at = now() WHERE id = $2`, [orderStatus, task.order_id]);
      await client.query(
        `INSERT INTO order_status_logs (order_id, from_status, to_status, operator_id, note) VALUES ($1, $2, $3, $4, $5)`,
        [task.order_id, orderFromStatus, orderStatus, userId, (note ? `配送: ${note}` : null)]
      );
    }

    await client.query('COMMIT');
    await writeAuditLog(client, userId, 'delivery:update_status', 'delivery_task', deliveryId, { status: fromStatus }, { status, note }, req);
    return { message: '配送状态已更新' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// POST /api/delivery-tasks/:id/status
app.post('/api/delivery-tasks/:id/status', authenticate, requirePermission('delivery:update_status'), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, note, locationLng, locationLat } = req.body;
    const result = await updateDeliveryTaskStatus(id, status, req.user.userId, note, locationLng, locationLat);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ error: err.message || '服务器内部错误' });
  }
});

// POST /api/delivery-tasks/:id/sign
app.post('/api/delivery-tasks/:id/sign', authenticate, requirePermission('delivery:sign'), async (req, res) => {
  try {
    const result = await updateDeliveryTaskStatus(req.params.id, 'signed', req.user.userId, req.body.note);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ error: err.message || '服务器内部错误' });
  }
});

// POST /api/delivery-tasks/:id/fail
app.post('/api/delivery-tasks/:id/fail', authenticate, requirePermission('delivery:report_failure'), async (req, res) => {
  try {
    const result = await updateDeliveryTaskStatus(req.params.id, 'failed', req.user.userId, req.body.note);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ error: err.message || '服务器内部错误' });
  }
});

// GET /api/delivery-tasks/:id/logs
app.get('/api/delivery-tasks/:id/logs', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT l.*, u.display_name as operator_name
       FROM delivery_status_logs l LEFT JOIN users u ON u.id = l.operator_id
       WHERE l.delivery_task_id = $1 ORDER BY l.created_at ASC`, [id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============================================================
// 路由：附件上传
// ============================================================

// POST /api/attachments
app.post('/api/attachments', authenticate, upload.single('file'), async (req, res) => {
  try {
    const { ownerType, ownerId } = req.body;
    if (!req.file) return res.status(400).json({ error: '请选择文件' });
    if (!ownerType || !ownerId) return res.status(400).json({ error: '请指定关联对象' });

    const result = await pool.query(
      `INSERT INTO attachments (owner_type, owner_id, file_name, file_url, mime_type, file_size, uploaded_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [ownerType, parseInt(ownerId), req.file.originalname, `/uploads/${req.file.filename}`, req.file.mimetype, req.file.size, req.user.userId]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// GET /api/attachments/:id
app.get('/api/attachments/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM attachments WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: '附件不存在' });

    const file = result.rows[0];
    const filePath = path.join(UPLOAD_DIR, path.basename(file.file_url));
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件不存在' });

    res.sendFile(path.resolve(filePath));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============================================================
// 路由：数据看板
// ============================================================

// GET /api/dashboard/summary
app.get('/api/dashboard/summary', authenticate, loadUserContext, async (req, res) => {
  try {
    const userId = req.user.userId;
    const perms = req.userPermissions;

    let orderStats, deliveryStats;

    if (perms.includes('order:view_all') || perms.includes('dispatch:view_pool')) {
      // 管理员/派单员：全局统计
      orderStats = await pool.query(
        `SELECT status, count(*) as count FROM sales_orders WHERE deleted_at IS NULL GROUP BY status`
      );
    } else if (perms.includes('order:view_own')) {
      // 店员：只看自己的
      orderStats = await pool.query(
        `SELECT status, count(*) as count FROM sales_orders WHERE created_by = $1 AND deleted_at IS NULL GROUP BY status`,
        [userId]
      );
    } else {
      orderStats = { rows: [] };
    }

    if (perms.includes('delivery:view_own')) {
      deliveryStats = await pool.query(
        `SELECT status, count(*) as count FROM delivery_tasks WHERE courier_id = $1 GROUP BY status`,
        [userId]
      );
    } else if (perms.includes('user:manage_role')) {
      deliveryStats = await pool.query(
        `SELECT status, count(*) as count FROM delivery_tasks GROUP BY status`
      );
    } else {
      deliveryStats = { rows: [] };
    }

    // 格式化统计
    const formatStats = (rows, map) => {
      const result = {};
      for (const [k, v] of Object.entries(map)) result[k] = 0;
      for (const r of rows) { if (map[r.status] !== undefined) result[r.status] = parseInt(r.count); }
      result.total = rows.reduce((s, r) => s + parseInt(r.count), 0);
      return result;
    };

    res.json({
      orders: formatStats(orderStats.rows, { draft: 0, pending: 0, dispatched: 0, delivering: 0, delivered: 0, completed: 0, cancelled: 0, exception: 0 }),
      deliveries: formatStats(deliveryStats.rows, { assigned: 0, accepted: 0, in_transit: 0, delivered: 0, signed: 0, failed: 0, cancelled: 0 }),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============================================================
// 路由：菜单与权限（管理端）
// ============================================================

// GET /api/menus
app.get('/api/menus', authenticate, loadUserContext, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM menu_items WHERE is_active = true ORDER BY sort_order'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// GET /api/roles
app.get('/api/roles', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM roles ORDER BY id');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// PUT /api/roles/:roleId/menus
app.put('/api/roles/:roleId/menus', authenticate, requirePermission('user:manage_role'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { roleId } = req.params;
    const { menuItemIds } = req.body;
    if (!Array.isArray(menuItemIds)) return res.status(400).json({ error: 'menuItemIds 必须是数组' });

    await client.query('BEGIN');
    await client.query('DELETE FROM role_menu_items WHERE role_id = $1', [roleId]);
    for (const mid of menuItemIds) {
      await client.query('INSERT INTO role_menu_items (role_id, menu_item_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [roleId, mid]);
    }
    await client.query('COMMIT');
    res.json({ message: '菜单权限已更新' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// PUT /api/roles/:roleId/permissions
app.put('/api/roles/:roleId/permissions', authenticate, requirePermission('user:manage_role'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { roleId } = req.params;
    const { permissionIds } = req.body;
    if (!Array.isArray(permissionIds)) return res.status(400).json({ error: 'permissionIds 必须是数组' });

    await client.query('BEGIN');
    await client.query('DELETE FROM role_permissions WHERE role_id = $1', [roleId]);
    for (const pid of permissionIds) {
      await client.query('INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [roleId, pid]);
    }
    await client.query('COMMIT');
    res.json({ message: '权限已更新' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: '服务器内部错误' });
  } finally {
    client.release();
  }
});

// ============================================================
// 错误处理
// ============================================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: '服务器内部错误' });
});

// ============================================================
// 启动服务
// ============================================================
app.listen(PORT, () => {
  console.log(`销售工单管理系统 API 已启动: http://localhost:${PORT}`);
  console.log(`环境: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
