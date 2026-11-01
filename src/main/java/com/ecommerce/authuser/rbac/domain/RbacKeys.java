package com.ecommerce.authuser.rbac.domain;

public final class RbacKeys {

    private RbacKeys() {
    }

    public static final class Roles {

        public static final String BUYER = "BUYER";

        public static final String SELLER = "SELLER";

        public static final String SELLER_STAFF = "SELLER_STAFF";

        public static final String SUPER_ADMIN = "SUPER_ADMIN";

        public static final String RISK_MANAGER = "RISK_MANAGER";

        public static final String CATALOG_ADMIN = "CATALOG_ADMIN";

        public static final String FINANCE_OPS = "FINANCE_OPS";

        public static final String SUPPORT_VIEWER = "SUPPORT_VIEWER";

        private Roles() {
        }
    }

    public static final class Permissions {

        public static final String KYC_READ = "KYC_READ";

        public static final String KYC_DECIDE = "KYC_DECIDE";

        public static final String KYC_REQUEST_INFO = "KYC_REQUEST_INFO";

        public static final String USER_READ = "USER_READ";

        public static final String USER_SUSPEND = "USER_SUSPEND";

        public static final String ROLE_READ = "ROLE_READ";

        public static final String ROLE_ASSIGN = "ROLE_ASSIGN";

        public static final String SHOP_READ = "SHOP_READ";

        public static final String SHOP_UPDATE = "SHOP_UPDATE";

        public static final String SELLER_STAFF_MANAGE = "SELLER_STAFF_MANAGE";

        /** Cross-service: enforced by search-service. */
        public static final String SEARCH_ADMIN = "SEARCH_ADMIN";

        /** Cross-service: enforced by order-commerce. */
        public static final String VOUCHER_MANAGE = "VOUCHER_MANAGE";

        private Permissions() {
        }
    }
}
