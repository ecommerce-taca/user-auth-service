-- Cross-service admin permissions documented in auth-user LLD §5.3 but not seeded by V012.
-- SEARCH_ADMIN is enforced by search-service (X-User-Permissions), VOUCHER_MANAGE by order-commerce.
INSERT INTO permissions
(
    id,
    permission_key,
    scope_type,
    description
)
VALUES
(
    UNHEX(REPLACE('019b0000-0000-7000-8000-000000001301', '-', '')),
    'SEARCH_ADMIN',
    'SYSTEM',
    'Search reindex, cancel and diagnostics (enforced by search-service).'
),
(
    UNHEX(REPLACE('019b0000-0000-7000-8000-000000001302', '-', '')),
    'VOUCHER_MANAGE',
    'SYSTEM',
    'Platform/freeship voucher CRUD (enforced by order-commerce).'
);

INSERT INTO role_permissions
(
    role_id,
    permission_id,
    granted_by
)
SELECT
    r.id,
    p.id,
    NULL
FROM
(
    SELECT 'SUPER_ADMIN' AS role_key, 'SEARCH_ADMIN' AS permission_key
    UNION ALL
    SELECT 'SUPER_ADMIN', 'VOUCHER_MANAGE'
) matrix
JOIN roles r
    ON r.role_key = matrix.role_key
JOIN permissions p
    ON p.permission_key = matrix.permission_key;
