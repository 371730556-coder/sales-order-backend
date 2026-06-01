-- ============================================================
-- 销售工单管理系统 - 数据库 Schema
-- PostgreSQL
-- ============================================================

-- 扩展：UUID 生成（可选，用于更安全的 ID）
-- CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- 1. 用户表
-- ============================================================
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(64) NOT NULL,
    phone VARCHAR(32),
    email VARCHAR(128),
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ          -- 软删除
);

CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_username ON users(username);

-- ============================================================
-- 2. 角色表
-- ============================================================
CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(64) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- 3. 用户-角色关联表
-- ============================================================
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

-- ============================================================
-- 4. 权限表
-- ============================================================
CREATE TABLE permissions (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    module VARCHAR(64) NOT NULL,
    description TEXT
);

-- ============================================================
-- 5. 角色-权限关联表
-- ============================================================
CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

-- ============================================================
-- 6. 菜单项表
-- ============================================================
CREATE TABLE menu_items (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    title VARCHAR(64) NOT NULL,
    path VARCHAR(128) NOT NULL,
    icon VARCHAR(64),
    sort_order INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- 7. 角色-菜单关联表
-- ============================================================
CREATE TABLE role_menu_items (
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    menu_item_id BIGINT NOT NULL REFERENCES menu_items(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, menu_item_id)
);

-- ============================================================
-- 8. 客户表
-- ============================================================
CREATE TABLE customers (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    phone VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (phone)
);

-- ============================================================
-- 9. 客户地址表
-- ============================================================
CREATE TABLE customer_addresses (
    id BIGSERIAL PRIMARY KEY,
    customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    province VARCHAR(64),
    city VARCHAR(64),
    district VARCHAR(64),
    detail_address TEXT NOT NULL,
    contact_name VARCHAR(64),
    contact_phone VARCHAR(32),
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_customer_addresses_customer ON customer_addresses(customer_id);

-- ============================================================
-- 10. 销售工单主表
-- ============================================================
CREATE TABLE sales_orders (
    id BIGSERIAL PRIMARY KEY,
    order_no VARCHAR(64) NOT NULL UNIQUE,
    customer_id BIGINT REFERENCES customers(id),
    customer_name VARCHAR(64) NOT NULL,
    customer_phone VARCHAR(32) NOT NULL,
    customer_address TEXT NOT NULL,
    delivery_requirement TEXT,
    payment_method VARCHAR(32) NOT NULL DEFAULT 'cash',
    delivery_time VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'draft',
    total_amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
    created_by BIGINT NOT NULL REFERENCES users(id),
    cancelled_by BIGINT REFERENCES users(id),
    cancelled_reason TEXT,
    cancelled_at TIMESTAMPTZ,
    submitted_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_sales_orders_status ON sales_orders(status);
CREATE INDEX idx_sales_orders_created_by ON sales_orders(created_by);
CREATE INDEX idx_sales_orders_created_at ON sales_orders(created_at);
CREATE INDEX idx_sales_orders_customer_phone ON sales_orders(customer_phone);

-- 状态约束
ALTER TABLE sales_orders ADD CONSTRAINT ck_order_status
    CHECK (status IN ('draft', 'pending', 'dispatched', 'delivering', 'delivered', 'completed', 'cancelled', 'exception'));

-- ============================================================
-- 11. 工单商品明细表
-- ============================================================
CREATE TABLE sales_order_items (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES sales_orders(id) ON DELETE CASCADE,
    product_name VARCHAR(255) NOT NULL,
    sku VARCHAR(128),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    line_amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
    remark TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sales_order_items_order ON sales_order_items(order_id);

-- ============================================================
-- 12. 配送任务表
-- ============================================================
CREATE TABLE delivery_tasks (
    id BIGSERIAL PRIMARY KEY,
    delivery_no VARCHAR(64) NOT NULL UNIQUE,
    order_id BIGINT NOT NULL REFERENCES sales_orders(id),
    dispatcher_id BIGINT NOT NULL REFERENCES users(id),
    courier_id BIGINT NOT NULL REFERENCES users(id),
    clerk_id BIGINT REFERENCES users(id),
    status VARCHAR(32) NOT NULL DEFAULT 'assigned',
    notes TEXT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at TIMESTAMPTZ,
    picked_up_at TIMESTAMPTZ,
    in_transit_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    signed_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    failed_reason TEXT,
    cancelled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_delivery_tasks_order ON delivery_tasks(order_id);
CREATE INDEX idx_delivery_tasks_courier ON delivery_tasks(courier_id);
CREATE INDEX idx_delivery_tasks_dispatcher ON delivery_tasks(dispatcher_id);
CREATE INDEX idx_delivery_tasks_status ON delivery_tasks(status);

-- 一个工单只有一个活跃配送任务
CREATE UNIQUE INDEX uniq_active_delivery_per_order
    ON delivery_tasks(order_id)
    WHERE status IN ('assigned', 'accepted', 'picked_up', 'in_transit', 'delivered');

ALTER TABLE delivery_tasks ADD CONSTRAINT ck_delivery_status
    CHECK (status IN ('assigned', 'accepted', 'picked_up', 'in_transit', 'delivered', 'signed', 'failed', 'cancelled', 'reassigned'));

-- ============================================================
-- 13. 配送状态日志
-- ============================================================
CREATE TABLE delivery_status_logs (
    id BIGSERIAL PRIMARY KEY,
    delivery_task_id BIGINT NOT NULL REFERENCES delivery_tasks(id) ON DELETE CASCADE,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    operator_id BIGINT NOT NULL REFERENCES users(id),
    note TEXT,
    location_lng NUMERIC(10, 6),
    location_lat NUMERIC(10, 6),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_delivery_status_logs_task ON delivery_status_logs(delivery_task_id);

-- ============================================================
-- 14. 工单状态日志
-- ============================================================
CREATE TABLE order_status_logs (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES sales_orders(id) ON DELETE CASCADE,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    operator_id BIGINT NOT NULL REFERENCES users(id),
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_order_status_logs_order ON order_status_logs(order_id);

-- ============================================================
-- 15. 附件表
-- ============================================================
CREATE TABLE attachments (
    id BIGSERIAL PRIMARY KEY,
    owner_type VARCHAR(64) NOT NULL,
    owner_id BIGINT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_url TEXT NOT NULL,
    mime_type VARCHAR(128),
    file_size BIGINT,
    uploaded_by BIGINT NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_attachments_owner ON attachments(owner_type, owner_id);

-- ============================================================
-- 16. OCR 识别结果表
-- ============================================================
CREATE TABLE ocr_results (
    id BIGSERIAL PRIMARY KEY,
    attachment_id BIGINT NOT NULL REFERENCES attachments(id) ON DELETE CASCADE,
    raw_text TEXT,
    parsed_json JSONB,
    confidence NUMERIC(5, 4),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_by BIGINT NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ocr_results_attachment ON ocr_results(attachment_id);
CREATE INDEX idx_ocr_results_status ON ocr_results(status);

-- ============================================================
-- 17. 操作审计日志
-- ============================================================
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_id BIGINT REFERENCES users(id),
    action VARCHAR(128) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id BIGINT,
    before_data JSONB,
    after_data JSONB,
    ip_address VARCHAR(64),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_target ON audit_logs(target_type, target_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
