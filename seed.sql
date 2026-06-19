-- ============================================================
-- 销售工单管理系统 - 初始种子数据
-- ============================================================

-- ============================================================
-- 角色
-- ============================================================
INSERT INTO roles (code, name, description) VALUES
('admin', '系统管理员', '拥有全部权限，可管理系统配置'),
('manager', '业务主管', '可查看统计报表，处理异常工单'),
('store_clerk', '门店店员', '可创建、编辑自己的工单，查看自己的工单列表'),
('dispatcher', '派单人员', '可查看待派工单池，分配送货员'),
('courier', '送货人员', '可查看配送任务，更新配送状态');

-- ============================================================
-- 权限
-- ============================================================
INSERT INTO permissions (code, name, module, description) VALUES
-- 工单相关
('order:create', '创建工单', 'order', '新建销售工单'),
('order:view_own', '查看自己工单', 'order', '查看自己创建的工单'),
('order:view_all', '查看全部工单', 'order', '查看系统中所有工单'),
('order:update_draft', '编辑草稿工单', 'order', '编辑处于草稿状态的工单'),
('order:submit', '提交工单', 'order', '将草稿提交为待派单'),
('order:cancel', '取消工单', 'order', '取消待派单或草稿状态工单'),
('order:export', '导出工单', 'order', '导出工单列表为文件'),

-- 派单相关
('dispatch:view_pool', '查看待派池', 'dispatch', '查看待派单工单池'),
('dispatch:assign', '分派送货', 'dispatch', '将工单分派给送货员'),
('dispatch:reassign', '改派工单', 'dispatch', '修改已分派工单的送货员'),

-- 配送相关
('delivery:view_own', '查看自己任务', 'delivery', '查看分配给自己的配送任务'),
('delivery:update_status', '更新配送状态', 'delivery', '更新配送任务状态'),
('delivery:sign', '签收确认', 'delivery', '确认客户签收'),
('delivery:report_failure', '上报配送失败', 'delivery', '上报配送异常'),

-- 用户管理
('user:view', '查看用户', 'user', '查看用户列表'),
('user:create', '创建用户', 'user', '新增用户'),
('user:update', '编辑用户', 'user', '修改用户信息'),
('user:delete', '删除用户', 'user', '删除用户'),
('user:manage_role', '管理角色权限', 'user', '配置用户角色和权限'),

-- 报表
('report:view', '查看报表', 'report', '查看数据统计报表'),
('report:export', '导出报表', 'report', '导出统计数据');

-- ============================================================
-- 角色-权限 关联
-- ============================================================
-- Admin: 所有权限
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.code = 'admin';

-- Manager: 查看和管理权限
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'manager' AND p.code IN (
    'order:view_all', 'order:cancel', 'order:export',
    'dispatch:view_pool', 'dispatch:reassign',
    'delivery:view_own',
    'user:view',
    'report:view', 'report:export'
);

-- Store Clerk: 自己的工单
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'store_clerk' AND p.code IN (
    'order:create', 'order:view_own', 'order:update_draft',
    'order:submit', 'order:cancel'
);

-- Dispatcher: 派单
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'dispatcher' AND p.code IN (
    'order:view_all', 'dispatch:view_pool', 'dispatch:assign', 'dispatch:reassign'
);

-- Courier: 配送
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'courier' AND p.code IN (
    'delivery:view_own', 'delivery:update_status', 'delivery:sign', 'delivery:report_failure'
);

-- ============================================================
-- 菜单项
-- ============================================================
INSERT INTO menu_items (code, title, path, icon, sort_order) VALUES
('dashboard', '控制台', '/dashboard', '📊', 1),
('users', '用户管理', '/users', '👥', 10),
('all-orders', '全部工单', '/orders', '📋', 20),
('all-deliveries', '配送记录', '/deliveries', '🚚', 30),
('create-order', '创建工单', '/orders/create', '➕', 40),
('my-orders', '我的工单', '/orders/mine', '📋', 50),
('order-pool', '工单池', '/dispatch/pool', '📋', 60),
('dispatch-mgmt', '派单管理', '/dispatch/manage', '📤', 70),
('my-tasks', '我的任务', '/delivery/tasks', '🚚', 80),
('role-menu', '菜单权限', '/admin/menus', '⚙️', 90),
('reports', '数据报表', '/reports', '📈', 100);

-- ============================================================
-- 角色-菜单 关联
-- ============================================================
-- Admin: 核心管理菜单（通过用户权限配置页面可随时调整）
INSERT INTO role_menu_items (role_id, menu_item_id)
SELECT r.id, m.id FROM roles r, menu_items m
WHERE r.code = 'admin' AND m.code IN ('dashboard', 'users', 'all-orders', 'all-deliveries', 'reports');

-- Manager: 控制台、全部工单、配送记录、数据报表
INSERT INTO role_menu_items (role_id, menu_item_id)
SELECT r.id, m.id FROM roles r, menu_items m
WHERE r.code = 'manager' AND m.code IN ('dashboard', 'all-orders', 'all-deliveries', 'reports');

-- Store Clerk: 控制台、创建工单、我的工单
INSERT INTO role_menu_items (role_id, menu_item_id)
SELECT r.id, m.id FROM roles r, menu_items m
WHERE r.code = 'store_clerk' AND m.code IN ('dashboard', 'create-order', 'my-orders');

-- Dispatcher: 控制台、工单池、派单管理
INSERT INTO role_menu_items (role_id, menu_item_id)
SELECT r.id, m.id FROM roles r, menu_items m
WHERE r.code = 'dispatcher' AND m.code IN ('dashboard', 'order-pool', 'dispatch-mgmt');

-- Courier: 控制台、我的任务
INSERT INTO role_menu_items (role_id, menu_item_id)
SELECT r.id, m.id FROM roles r, menu_items m
WHERE r.code = 'courier' AND m.code IN ('dashboard', 'my-tasks');

-- ============================================================
-- 演示用户（密码均为 '123456' 的 bcrypt 哈希）
-- 注意：生产环境请用真实的 bcrypt 哈希值
-- 此处用占位符，实际部署时执行 seed-passwords.sql 生成
-- ============================================================
-- 默认密码 "123456" 的 bcrypt 哈希 (cost 10)
-- 可通过以下命令生成: node -e "const bcrypt=require('bcryptjs');console.log(bcrypt.hashSync('123456',10))"
INSERT INTO users (username, password_hash, display_name, phone, status) VALUES
('admin', '$2a$10$placeholder_admin_hash', '系统管理员', '13900000001', 'active'),
('manager1', '$2a$10$placeholder_manager_hash', '王主管', '13900000002', 'active'),
('clerk1', '$2a$10$placeholder_clerk_hash', '陈店员', '13900000003', 'active'),
('clerk2', '$2a$10$placeholder_clerk2_hash', '刘店员', '13900000004', 'active'),
('dispatcher1', '$2a$10$placeholder_dispatcher_hash', '张派单', '13900000005', 'active'),
('courier1', '$2a$10$placeholder_courier_hash', '王送货', '13900000006', 'active'),
('courier2', '$2a$10$placeholder_courier2_hash', '赵送货', '13900000007', 'active');

-- 用户分配角色
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'admin' AND r.code = 'admin';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'manager1' AND r.code = 'manager';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'clerk1' AND r.code = 'store_clerk';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'clerk2' AND r.code = 'store_clerk';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'dispatcher1' AND r.code = 'dispatcher';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'courier1' AND r.code = 'courier';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'courier2' AND r.code = 'courier';
