// ============================================================
// 密码哈希生成工具
// 运行: node seed-passwords.js
// 将更新 seed.sql 中的占位符为真实 bcrypt 哈希值
// ============================================================

const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const DEFAULT_PASSWORD = '123456';

const accounts = [
  { placeholder: '$2a$10$placeholder_admin_hash', username: 'admin' },
  { placeholder: '$2a$10$placeholder_manager_hash', username: 'manager1' },
  { placeholder: '$2a$10$placeholder_clerk_hash', username: 'clerk1' },
  { placeholder: '$2a$10$placeholder_clerk2_hash', username: 'clerk2' },
  { placeholder: '$2a$10$placeholder_dispatcher_hash', username: 'dispatcher1' },
  { placeholder: '$2a$10$placeholder_courier_hash', username: 'courier1' },
  { placeholder: '$2a$10$placeholder_courier2_hash', username: 'courier2' },
];

async function main() {
  const seedPath = path.join(__dirname, 'seed.sql');
  let content = fs.readFileSync(seedPath, 'utf8');

  for (const account of accounts) {
    const hash = await bcrypt.hash(DEFAULT_PASSWORD, 10);
    console.log(`${account.username}: ${hash}`);
    content = content.replace(account.placeholder, hash);
  }

  fs.writeFileSync(seedPath, content, 'utf8');
  console.log('\n✅ seed.sql 已更新，所有占位符已替换为真实 bcrypt 哈希值');
  console.log('   默认密码均为:', DEFAULT_PASSWORD);
}

main().catch(console.error);
