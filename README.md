# 销售工单管理系统 - 后端

## 快速开始

### 1. 安装依赖
```bash
cd sales-order-backend
npm install
```

### 2. 配置环境变量
```bash
cp .env.example .env
# 编辑 .env，修改 DATABASE_URL 和 JWT_SECRET
```

### 3. 初始化数据库
```bash
# 创建 PostgreSQL 数据库
createdb sales_orders

# 执行建表脚本
psql $DATABASE_URL -f schema.sql

# 生成密码哈希并导入种子数据
node seed-passwords.js
psql $DATABASE_URL -f seed.sql
```

### 4. 启动服务
```bash
npm start        # 生产模式
npm run dev      # 开发模式（自动重启）
```

## 演示账号（默认密码 123456）

| 用户名 | 角色 | 说明 |
|--------|------|------|
| admin | 系统管理员 | 全部权限 |
| manager1 | 业务主管 | 报表、全部工单 |
| clerk1 | 门店店员 | 创建工单、我的工单 |
| dispatcher1 | 派单人员 | 工单池、派单 |
| courier1 | 送货人员 | 配送任务 |

## API 接口

### 认证
- `POST /api/auth/login` - 登录
- `POST /api/auth/refresh` - 刷新 token
- `GET /api/auth/me` - 获取当前用户

### 用户管理（admin）
- `GET /api/users` - 用户列表
- `POST /api/users` - 创建用户
- `PATCH /api/users/:id` - 更新用户
- `PATCH /api/users/:id/status` - 修改状态
- `DELETE /api/users/:id` - 删除用户

### 工单
- `GET /api/orders` - 工单列表
- `POST /api/orders` - 创建工单
- `GET /api/orders/:id` - 工单详情
- `PATCH /api/orders/:id` - 修改工单
- `POST /api/orders/:id/submit` - 提交工单
- `POST /api/orders/:id/cancel` - 取消工单
- `GET /api/orders/:id/timeline` - 状态时间线

### 派单
- `GET /api/dispatch/order-pool` - 待派单池
- `POST /api/orders/:id/dispatch` - 分派送货
- `POST /api/delivery-tasks/:id/reassign` - 改派

### 配送
- `GET /api/delivery-tasks` - 配送任务列表
- `GET /api/delivery-tasks/:id` - 任务详情
- `POST /api/delivery-tasks/:id/status` - 更新状态
- `POST /api/delivery-tasks/:id/sign` - 签收
- `POST /api/delivery-tasks/:id/fail` - 配送失败

### 附件
- `POST /api/attachments` - 上传附件
- `GET /api/attachments/:id` - 下载附件

### 看板
- `GET /api/dashboard/summary` - 数据概览

### 权限管理
- `GET /api/roles` - 角色列表
- `GET /api/menus` - 菜单列表
- `PUT /api/roles/:roleId/menus` - 配置菜单
- `PUT /api/roles/:roleId/permissions` - 配置权限
