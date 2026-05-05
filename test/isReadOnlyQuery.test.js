const assert = require("node:assert/strict");
const test = require("node:test");

process.env.DATABASE_URL ||= "postgres://user:pass@localhost:5432/proxy_app_db";
process.env.PROXY_ADMIN_SECRET ||= "test-admin-secret";
process.env.PROXY_SIGNING_SECRET ||= "test-signing-secret";

const { isReadOnlyQuery } = require("../index");

test("allows normal select statements", () => {
  assert.equal(isReadOnlyQuery("select now() as now"), true);
  assert.equal(isReadOnlyQuery("  -- lead comment\nSELECT 1;"), true);
});

test("allows read-only CTEs", () => {
  assert.equal(
    isReadOnlyQuery(`
      with recent_orders as (
        select id, created_at from orders where created_at > now() - interval '1 day'
      )
      select count(*) from recent_orders
    `),
    true
  );
});

test("allows recursive read-only CTEs", () => {
  assert.equal(
    isReadOnlyQuery(`
      with recursive nums(n) as (
        select 1
        union all
        select n + 1 from nums where n < 3
      )
      select n from nums
    `),
    true
  );
});

test("rejects writable statements in CTE bodies", () => {
  assert.equal(
    isReadOnlyQuery(`
      with deleted_rows as (
        delete from orders where created_at < now() - interval '1 year' returning id
      )
      select count(*) from deleted_rows
    `),
    false
  );
});

test("rejects writable main statements after CTEs", () => {
  assert.equal(
    isReadOnlyQuery(`
      with recent_orders as (
        select id from orders
      )
      delete from orders where id in (select id from recent_orders)
    `),
    false
  );
});

test("rejects extra statements after a read-only statement", () => {
  assert.equal(isReadOnlyQuery("select 1; delete from orders;"), false);
});
