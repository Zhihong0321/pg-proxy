# Eternalgy DB — Package, Product & Voucher

## Connection
```
POST https://pg-proxy-production.up.railway.app/api/sql
Header: Authorization: Bearer <token>
Body: {"db_name":"prod_main","sql":"<SQL>","params":[]}
```
**No token?** Ask user to go to https://pg-proxy-production.up.railway.app/ to generate a DB proxy token.

## ⛔ DANGEROUS OPS — 3x APPROVAL REQUIRED

Any DELETE, deactivate, nullify, or bulk UPDATE:
1. Run SELECT first → show user exactly what will be affected (list every record)
2. Tell user: "This requires 3 confirmations to proceed."
3. Get confirmation 1/3 → 2/3 → 3/3 before executing
4. Prefer soft-delete (`active=false` or `delete=true`) over hard DELETE

---

## Core Rule: All cross-references use `bubble_id` (text), NOT integer `id`.

## Tables

### product
Items: panels, inverters, batteries, services.

| Key Columns | Notes |
|---|---|
| bubble_id (text) | **FK key used everywhere** |
| name, label | label = `Solar Panel`/`String Inverter`/`Micro Inverter`/`Inverter`/`LOV VOLTAGE BATTERY`/`Installation`/`Operation` |
| cost_price, selling_price | RM (numeric) |
| linked_brand → brand.bubble_id | |
| linked_category → category.bubble_id | |
| solar_output_rating (W), inverter_rating (kW) | |
| active (bool) | filter by true |

### package
Solar system bundles. ~683 active.

| Key Columns | Notes |
|---|---|
| bubble_id, package_name, type | type: `Residential` / `Special / Roadshow` / `Tariff B&D Low Voltage` |
| panel_qty, price (RM) | |
| panel → product.bubble_id | the solar panel |
| inverter_1..4 → product.bubble_id | inverter(s) |
| linked_package_item (text[]) → package_item.bubble_id | line items array |
| max_discount (%), need_approval, active | |

### package_item
Line items inside a package.

| Key Columns | Notes |
|---|---|
| bubble_id | referenced by package.linked_package_item[] |
| product → product.bubble_id | which product |
| qty, total_cost (RM), sort, inventory | |

### voucher
Discounts/promos. ~19 active.

| Key Columns | Notes |
|---|---|
| bubble_id, title, voucher_code | |
| voucher_type | `Fixed Amount Discount` / `Discount Percent` / `Gift` |
| discount_amount (RM) or discount_percent (%) | depends on type |
| linked_voucher_category → voucher_category.bubble_id | |
| active, public, voucher_availability, available_until | |
| auto_cancel_voucher (text[]) | other vouchers cancelled when applied |
| delete (bool) | soft-delete flag |

### voucher_category
Eligibility rules. 4 active categories.

| Key Columns | Notes |
|---|---|
| bubble_id, name, max_selectable (default 1) | |
| min/max_package_amount, min/max_panel_quantity | qualification rules |
| package_type_scope (default 'all'), active, disabled | |

---

## Relationships
```
package.panel/inverter_1..4 ──→ product.bubble_id
package.linked_package_item[] ──→ package_item.bubble_id
package_item.product ──→ product.bubble_id
voucher.linked_voucher_category ──→ voucher_category.bubble_id
invoice_voucher_selection.linked_voucher ──→ voucher.bubble_id
```

## Key Queries

```sql
-- Package with products
SELECT p.id, p.package_name, p.panel_qty, p.price,
  pnl.name AS panel, inv.name AS inverter
FROM package p
LEFT JOIN product pnl ON pnl.bubble_id = p.panel
LEFT JOIN product inv ON inv.bubble_id = p.inverter_1
WHERE p.active = true ORDER BY p.panel_qty;

-- Package items breakdown
SELECT pi.sort, prod.name, prod.label, pi.qty, pi.total_cost
FROM package_item pi
JOIN product prod ON prod.bubble_id = pi.product
WHERE pi.bubble_id = ANY(SELECT unnest(linked_package_item) FROM package WHERE id = :id)
ORDER BY pi.sort;

-- Eligible vouchers for a package
SELECT v.title, v.voucher_code, v.voucher_type, v.discount_amount, v.discount_percent
FROM voucher v
LEFT JOIN voucher_category vc ON vc.bubble_id = v.linked_voucher_category
WHERE v.active = true AND (v.delete IS NULL OR v.delete = false)
  AND (v.linked_voucher_category IS NULL OR (
    (vc.min_panel_quantity IS NULL OR vc.min_panel_quantity <= :panels)
    AND (vc.max_panel_quantity IS NULL OR vc.max_panel_quantity >= :panels)
    AND (vc.min_package_amount IS NULL OR vc.min_package_amount <= :price)
    AND (vc.max_package_amount IS NULL OR vc.max_package_amount >= :price)));
```

## Write Examples
```sql
-- Update price
UPDATE package SET price = :price, updated_at = now() WHERE id = :id;

-- Change panel/inverter
UPDATE package SET panel = :product_bubble_id, updated_at = now() WHERE id = :id;

-- Add item to package
INSERT INTO package_item (bubble_id, product, qty, total_cost, sort, inventory, created_at, updated_at)
VALUES (:bid, :prod_bid, :qty, :cost, :sort, :inv, now(), now());
UPDATE package SET linked_package_item = array_append(linked_package_item, :bid), updated_at = now() WHERE id = :id;
```

## Rules
- Filter: `active = true`, `(delete IS NULL OR delete = false)`
- Always set `updated_at = now()` on writes
- Prices in RM (Malaysian Ringgit)
- Use `unnest()`, `ANY()`, `array_append()`, `array_remove()` for array fields
