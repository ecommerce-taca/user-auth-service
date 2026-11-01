package com.ecommerce.authuser.integration.auth;

import com.ecommerce.authuser.rbac.domain.Permission;
import com.ecommerce.authuser.rbac.domain.Role;
import com.ecommerce.authuser.rbac.domain.RolePermission;
import com.ecommerce.authuser.rbac.domain.ScopeType;
import com.ecommerce.authuser.rbac.domain.UserRole;
import com.ecommerce.authuser.shop.repository.SellerOnboardingRepository;
import com.ecommerce.authuser.shop.repository.ShopRepository;
import com.ecommerce.authuser.shop.repository.ShopStaffRepository;
import com.ecommerce.authuser.support.base.BaseIntegrationTest;
import com.ecommerce.authuser.support.fixture.RbacFixture;
import com.ecommerce.authuser.support.fixture.ShopFixture;
import com.ecommerce.authuser.support.fixture.UserRoleFixture;
import com.ecommerce.authuser.support.testdata.RbacTestData;
import com.ecommerce.authuser.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RbacIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private RbacFixture rbacFixture;

    private UserRoleFixture userRoleFixture;

    @Autowired
    private ShopRepository shopRepository;

    @Autowired
    private SellerOnboardingRepository sellerOnboardingRepository;

    @Autowired
    private ShopStaffRepository shopStaffRepository;

    private ShopFixture shopFixture;

    @BeforeEach
    void setUp() {
        userRoleFixture = new UserRoleFixture(userRoleRepository);

        shopFixture = new ShopFixture(
                shopRepository,
                sellerOnboardingRepository,
                shopStaffRepository
        );
    }

    // =========================================================
    // ROLE CATALOG
    // =========================================================

    @Test
    @DisplayName("RBAC - seeded roles should exist with correct scope")
    void seededRolesShouldExistWithCorrectScope() {

        Role buyer = roleRepository
                .findByRoleKey("BUYER")
                .orElseThrow();

        Role seller = roleRepository
                .findByRoleKey("SELLER")
                .orElseThrow();

        Role sellerStaff = roleRepository
                .findByRoleKey("SELLER_STAFF")
                .orElseThrow();

        Role superAdmin = roleRepository
                .findByRoleKey("SUPER_ADMIN")
                .orElseThrow();

        Role riskManager = roleRepository
                .findByRoleKey("RISK_MANAGER")
                .orElseThrow();

        Role catalogAdmin = roleRepository
                .findByRoleKey("CATALOG_ADMIN")
                .orElseThrow();

        Role financeOps = roleRepository
                .findByRoleKey("FINANCE_OPS")
                .orElseThrow();

        Role supportViewer = roleRepository
                .findByRoleKey("SUPPORT_VIEWER")
                .orElseThrow();

        assertThat(buyer.getScopeType())
                .isEqualTo(ScopeType.USER);

        assertThat(seller.getScopeType())
                .isEqualTo(ScopeType.SHOP);

        assertThat(sellerStaff.getScopeType())
                .isEqualTo(ScopeType.SHOP);

        assertThat(superAdmin.getScopeType())
                .isEqualTo(ScopeType.SYSTEM);

        assertThat(riskManager.getScopeType())
                .isEqualTo(ScopeType.SYSTEM);

        assertThat(catalogAdmin.getScopeType())
                .isEqualTo(ScopeType.SYSTEM);

        assertThat(financeOps.getScopeType())
                .isEqualTo(ScopeType.SYSTEM);

        assertThat(supportViewer.getScopeType())
                .isEqualTo(ScopeType.SYSTEM);
    }

    // =========================================================
    // PERMISSION CATALOG
    // =========================================================

    @Test
    @DisplayName("RBAC - seeded permissions should exist with correct scope")
    void seededPermissionsShouldExistWithCorrectScope() {

        List<String> systemPermissions = List.of(
                "KYC_READ",
                "KYC_DECIDE",
                "KYC_REQUEST_INFO",
                "USER_READ",
                "USER_SUSPEND",
                "ROLE_READ",
                "ROLE_ASSIGN",
                "SEARCH_ADMIN",
                "VOUCHER_MANAGE"
        );

        List<String> shopPermissions = List.of(
                "SHOP_READ",
                "SHOP_UPDATE",
                "SELLER_STAFF_MANAGE"
        );

        for (String permissionKey : systemPermissions) {

            Permission permission = permissionRepository
                    .findByPermissionKey(permissionKey)
                    .orElseThrow();

            assertThat(permission.getScopeType())
                    .as("Permission %s", permissionKey)
                    .isEqualTo(ScopeType.SYSTEM);
        }

        for (String permissionKey : shopPermissions) {

            Permission permission = permissionRepository
                    .findByPermissionKey(permissionKey)
                    .orElseThrow();

            assertThat(permission.getScopeType())
                    .as("Permission %s", permissionKey)
                    .isEqualTo(ScopeType.SHOP);
        }
    }

    // =========================================================
    // ROLE -> PERMISSION MATRIX
    // =========================================================

    @Test
    @DisplayName("RBAC - SELLER should have expected permissions")
    void sellerShouldHaveExpectedPermissions() {

        assertRoleHasPermissions(
                "SELLER",
                "SHOP_READ",
                "SHOP_UPDATE",
                "SELLER_STAFF_MANAGE"
        );
    }

    @Test
    @DisplayName("RBAC - SELLER_STAFF should have SHOP_READ only")
    void sellerStaffShouldHaveExpectedPermissions() {

        assertRoleHasPermissions(
                "SELLER_STAFF",
                "SHOP_READ"
        );
    }

    @Test
    @DisplayName("RBAC - RISK_MANAGER should have expected permissions")
    void riskManagerShouldHaveExpectedPermissions() {

        assertRoleHasPermissions(
                "RISK_MANAGER",
                "KYC_READ",
                "KYC_DECIDE",
                "KYC_REQUEST_INFO"
        );
    }

    @Test
    @DisplayName("RBAC - SUPPORT_VIEWER should have expected permissions")
    void supportViewerShouldHaveExpectedPermissions() {

        assertRoleHasPermissions(
                "SUPPORT_VIEWER",
                "USER_READ",
                "ROLE_READ"
        );
    }

    @Test
    @DisplayName("RBAC - SUPER_ADMIN should have all baseline permissions")
    void superAdminShouldHaveAllBaselinePermissions() {

        assertRoleHasPermissions(
                "SUPER_ADMIN",
                "KYC_READ",
                "KYC_DECIDE",
                "KYC_REQUEST_INFO",
                "USER_READ",
                "USER_SUSPEND",
                "ROLE_READ",
                "ROLE_ASSIGN",
                "SHOP_READ",
                "SHOP_UPDATE",
                "SELLER_STAFF_MANAGE",
                "SEARCH_ADMIN",
                "VOUCHER_MANAGE"
        );
    }

    @Test
    @DisplayName("RBAC - BUYER should have no seeded permissions")
    void buyerShouldHaveNoSeededPermissions() {

        Role buyer = roleRepository
                .findByRoleKey("BUYER")
                .orElseThrow();

        List<RolePermission> mappings =
                rolePermissionRepository.findAllByRole_Id(
                        buyer.getId()
                );

        assertThat(mappings)
                .isEmpty();
    }

    @Test
    @DisplayName("RBAC - CATALOG_ADMIN should have no seeded permissions")
    void catalogAdminShouldHaveNoSeededPermissions() {

        assertRoleHasNoPermissions("CATALOG_ADMIN");
    }

    @Test
    @DisplayName("RBAC - FINANCE_OPS should have no seeded permissions")
    void financeOpsShouldHaveNoSeededPermissions() {

        assertRoleHasNoPermissions("FINANCE_OPS");
    }

    // =========================================================
    // USER ROLE ASSIGNMENT
    // =========================================================

    @Test
    @DisplayName("RBAC - USER scoped role should be assignable without shop")
    void userScopedRoleShouldBeAssignableWithoutShop() {

        var user = createUser();

        Role buyerRole = roleRepository
                .findByRoleKey("BUYER")
                .orElseThrow();

        UserRole assignment = userRoleFixture.assign(
                user,
                buyerRole
        );

        assertThat(assignment.getUser())
                .isEqualTo(user);

        assertThat(assignment.getRole())
                .isEqualTo(buyerRole);

        assertThat(assignment.getShop())
                .isNull();

        assertThat(assignment.isActive())
                .isTrue();
    }

    @Test
    @DisplayName("RBAC - SHOP scoped role should require shop")
    void shopScopedRoleShouldRequireShop() {

        var user = createUser();

        Role sellerRole = roleRepository
                .findByRoleKey("SELLER")
                .orElseThrow();

        assertThatThrownBy(() ->
                userRoleFixture.assign(
                        user,
                        sellerRole
                )
        )
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("SHOP scoped role requires shop");
    }

    @Test
    @DisplayName("RBAC - non-SHOP scoped role should reject shop")
    void nonShopScopedRoleShouldRejectShop() {

        var user = createUser();

        Role buyerRole = roleRepository
                .findByRoleKey("BUYER")
                .orElseThrow();

        var shop = createShop();

        assertThatThrownBy(() ->
                userRoleFixture.assignShopRole(
                        user,
                        buyerRole,
                        shop
                )
        )
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Non-SHOP role must not have shop");
    }

    // =========================================================
    // USER ROLE LIFECYCLE
    // =========================================================

    @Test
    @DisplayName("RBAC - active user role should become inactive after revoke")
    void activeUserRoleShouldBecomeInactiveAfterRevoke() {

        var user = createUser();

        Role buyerRole = roleRepository
                .findByRoleKey("BUYER")
                .orElseThrow();

        UserRole assignment = userRoleFixture.assign(
                user,
                buyerRole
        );

        assertThat(assignment.isActive())
                .isTrue();

        assignment.revoke(
                java.time.Instant.now()
        );

        assertThat(assignment.isActive())
                .isFalse();

        assertThat(assignment.getRevokedAt())
                .isNotNull();
    }

    @Test
    @DisplayName("RBAC - revoked user role should be reactivated")
    void revokedUserRoleShouldBeReactivated() {

        var user = createUser();

        Role buyerRole = roleRepository
                .findByRoleKey("BUYER")
                .orElseThrow();

        UserRole assignment = userRoleFixture.assign(
                user,
                buyerRole
        );

        assignment.revoke(
                java.time.Instant.now()
        );

        assertThat(assignment.isActive())
                .isFalse();

        UUID grantedBy = UUID.randomUUID();
        java.time.Instant reactivatedAt = java.time.Instant.now();

        assignment.reactivate(
                grantedBy,
                reactivatedAt
        );

        assertThat(assignment.isActive())
                .isTrue();

        assertThat(assignment.getRevokedAt())
                .isNull();

        assertThat(assignment.getGrantedBy())
                .isEqualTo(grantedBy);

        assertThat(assignment.getGrantedAt())
                .isEqualTo(reactivatedAt);
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private void assertRoleHasPermissions(
            String roleKey,
            String... expectedPermissionKeys
    ) {

        Role role = roleRepository
                .findByRoleKey(roleKey)
                .orElseThrow();

        List<RolePermission> mappings =
                rolePermissionRepository.findAllByRole_Id(
                        role.getId()
                );

        List<String> actualPermissionKeys = mappings
                .stream()
                .map(mapping -> mapping.getPermission().getPermissionKey())
                .toList();

        assertThat(actualPermissionKeys)
                .containsExactlyInAnyOrder(
                        expectedPermissionKeys
                );
    }

    private void assertRoleHasNoPermissions(String roleKey) {

        Role role = roleRepository
                .findByRoleKey(roleKey)
                .orElseThrow();

        List<RolePermission> mappings =
                rolePermissionRepository.findAllByRole_Id(
                        role.getId()
                );

        assertThat(mappings)
                .isEmpty();
    }

    private User createUser() {

        String email =
                "rbac-test-" + UUID.randomUUID() + "@example.com";

        User user = User.registerBuyer(
                email,
                email,
                "$2a$10$7EqJtq98hPqEX7fNZaFWoO6X6L5x5Q",
                "RBAC Test User",
                null,
                null
        );

        return userRepository.saveAndFlush(user);
    }

    private com.ecommerce.authuser.shop.domain.Shop createShop() {

        return shopFixture.create(
                createUser(),
                "RBAC Test Shop",
                "rbac-test-shop-" + UUID.randomUUID(),
                "RBAC Test Shop Business"
        );
    }
}

