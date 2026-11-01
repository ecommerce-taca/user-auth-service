package com.ecommerce.authuser.rbac.repository;

import com.ecommerce.authuser.rbac.domain.ScopeType;
import com.ecommerce.authuser.rbac.domain.UserRole;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    List<UserRole> findAllByUser_IdAndRevokedAtIsNull(UUID userId);

    List<UserRole> findAllByShop_IdAndRevokedAtIsNull(UUID shopId);

    Optional<UserRole> findByUser_IdAndRole_IdAndShop_Id(
            UUID userId,
            UUID roleId,
            UUID shopId
    );

    Optional<UserRole> findByUser_IdAndRole_IdAndShopIsNull(
            UUID userId,
            UUID roleId
    );

    boolean existsByUser_IdAndRole_RoleKeyAndRevokedAtIsNull(
            UUID userId,
            String roleKey
    );

    boolean existsByUser_IdAndRole_RoleKeyAndShop_IdAndRevokedAtIsNull(
            UUID userId,
            String roleKey,
            UUID shopId
    );

    @Query("""
        select (count(ur) > 0)
        from UserRole ur, RolePermission rp
        where ur.user.id = :userId
            and ur.revokedAt is null
            and ur.role.id = rp.role.id
            and ur.role.scopeType = :scopeType
            and rp.permission.permissionKey = :permissionKey
        """)
    boolean existsActivePermission(
            @Param("userId") UUID userId,
            @Param("permissionKey") String permissionKey,
            @Param("scopeType") ScopeType scopeType
    );

    @Query("""
        select count(ur)
            from UserRole ur
            where ur.user.id = :userId
                and ur.revokedAt is null
                and ur.shop is null
                and ur.role.scopeType = :scopeType
                and ur.role.roleKey in :roleKeys
        """)
    long countActiveRoles(
            @Param("userId") UUID userId,
            @Param("roleKeys") Collection<String> roleKeys,
            @Param("scopeType") ScopeType scopeType
    );

    @Query("""
        select ur
        from UserRole ur
        join fetch ur.role role
        left join fetch ur.shop shop
        where ur.user.id = :userId
            and ur.revokedAt is null
        order by ur.grantedAt asc, ur.id asc
        """)
    List<UserRole> findActiveAssignmentsWithRoleAndShop(
            @Param("userId") UUID userId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        select ur
        from UserRole ur
        join fetch ur.role role
        where ur.user.id = :userId
            and ur.role.id = :roleId
            and ur.shop.id = :shopId
        """)
    Optional<UserRole> findShopAssignmentForUpdate(
            @Param("userId") UUID userId,
            @Param("roleId") UUID roleId,
            @Param("shopId") UUID shopId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        select ur
        from UserRole ur
        join fetch ur.role role
        where ur.user.id = :userId
            and ur.role.id = :roleId
            and ur.shop is null
        """)
    Optional<UserRole> findUnscopedAssignmentForUpdate(
            @Param("userId") UUID userId,
            @Param("roleId") UUID roleId
    );

    @Query("""
        select distinct rp.permission.permissionKey
        from UserRole ur, RolePermission rp
        where ur.user.id = :userId
            and ur.revokedAt is null
            and ur.role.id = rp.role.id
            and (
                ur.role.scopeType =
                    com.ecommerce.authuser.rbac.domain.ScopeType.SYSTEM
                or (
                    ur.role.scopeType =
                        com.ecommerce.authuser.rbac.domain.ScopeType.SHOP
                    and ur.shop.id = :shopId
                )
            )
        """)
    List<String> findActivePermissionKeysForShop(
            @Param("userId") UUID userId,
            @Param("shopId") UUID shopId
    );

    @Query("""
        select distinct rp.permission.permissionKey
        from UserRole ur, RolePermission rp
        where ur.user.id = :userId
            and ur.revokedAt is null
            and ur.role.id = rp.role.id
            and ur.role.scopeType =
                com.ecommerce.authuser.rbac.domain.ScopeType.SYSTEM
        """)
    List<String> findActiveSystemPermissionKeys(
            @Param("userId") UUID userId
    );
}
