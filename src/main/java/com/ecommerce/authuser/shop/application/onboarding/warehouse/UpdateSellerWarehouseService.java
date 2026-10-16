package com.ecommerce.authuser.shop.application.onboarding.warehouse;

import com.ecommerce.authuser.auth.application.support.IdentityNormalizer;
import com.ecommerce.authuser.auth.exception.verification.phone.InvalidPhoneFormatException;

import com.ecommerce.authuser.rbac.domain.RbacKeys;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;

import com.ecommerce.authuser.shop.domain.SellerOnboarding;
import com.ecommerce.authuser.shop.domain.Shop;

import com.ecommerce.authuser.shop.exception.InvalidSellerWarehouseException;
import com.ecommerce.authuser.shop.exception.SellerPermissionDeniedException;
import com.ecommerce.authuser.shop.exception.ShopInvalidStateException;
import com.ecommerce.authuser.shop.exception.ShopNotFoundException;

import com.ecommerce.authuser.shop.repository.SellerOnboardingRepository;
import com.ecommerce.authuser.shop.repository.ShopRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UpdateSellerWarehouseService {

    private static final int MAX_CARRIERS = 10;

    private final ShopRepository shopRepository;

    private final SellerOnboardingRepository sellerOnboardingRepository;

    private final UserRoleRepository userRoleRepository;

    private final IdentityNormalizer identityNormalizer;

    @Transactional
    public UpdateSellerWarehouseResult update(UpdateSellerWarehouseCommand command) {

        if (command == null
                || command.userId() == null
                || command.address() == null) {

            throw new InvalidSellerWarehouseException();
        }

        Shop shop = shopRepository
                .findByOwnerIdForUpdate(command.userId())
                .orElseThrow(ShopNotFoundException::new);

        boolean sellerOwner = userRoleRepository
                .existsByUser_IdAndRole_RoleKeyAndShop_IdAndRevokedAtIsNull(
                        command.userId(),
                        RbacKeys.Roles.SELLER,
                        shop.getId()
                );

        if (!sellerOwner) {
            throw new SellerPermissionDeniedException();
        }

        if (!shop.canEditOnboarding()) {
            throw new ShopInvalidStateException();
        }

        SellerOnboarding onboarding = sellerOnboardingRepository
                .findByShopIdForUpdate(shop.getId())
                .orElseThrow(ShopNotFoundException::new);

        String warehouseName =
                requiredText(command.warehouseName(), 120);

        String contactName = requiredText(command.contactName(), 120);

        String contactPhone = normalizePhone(command.contactPhone());

        UpdateSellerWarehouseCommand.AddressCommand address = command.address();

        String line1 = requiredText(address.line1(), 255);

        String line2 = optionalText(address.line2(), 255);

        String ward = requiredText(address.ward(), 120);

        String district = optionalText(address.district(), 120);

        String province = requiredText(address.province(), 120);

        String postalCode = optionalText(address.postalCode(), 12);

        List<String> carrierPreferences =
                normalizeCarrierPreferences(command.carrierPreferences());

        boolean codEnabled = command.codEnabled() == null || command.codEnabled();

        Map<String, Object> addressSnapshot = new LinkedHashMap<>();

        addressSnapshot.put("line1", line1);
        addressSnapshot.put("line2", line2);
        addressSnapshot.put("ward", ward);
        addressSnapshot.put("district", district);
        addressSnapshot.put("province", province);
        addressSnapshot.put("postal_code", postalCode);

        Map<String, Object> warehouseSnapshot = new LinkedHashMap<>();

        warehouseSnapshot.put("warehouse_name", warehouseName);
        warehouseSnapshot.put("contact_name", contactName);
        warehouseSnapshot.put("contact_phone", contactPhone);
        warehouseSnapshot.put("address", addressSnapshot);
        warehouseSnapshot.put("carrier_preferences", carrierPreferences);
        warehouseSnapshot.put("cod_enabled", codEnabled);

        shop.updateWarehouseSnapshot(warehouseSnapshot);

        onboarding.completeWarehouseStep();

        shopRepository.saveAndFlush(shop);

        return new UpdateSellerWarehouseResult(
                shop.getId(),
                warehouseName,
                contactName,
                contactPhone,

                new UpdateSellerWarehouseResult.AddressResult(
                        line1,
                        line2,
                        ward,
                        district,
                        province,
                        postalCode
                ),

                carrierPreferences,
                codEnabled,
                onboarding.getCurrentStep(),
                onboarding.isWarehouseCompleted(),
                onboarding.getBlockers()
        );
    }

    private String normalizePhone(String value) {

        if (value == null || value.isBlank()) {
            throw new InvalidSellerWarehouseException();
        }

        try {
            return identityNormalizer.normalizePhone(value);

        } catch (InvalidPhoneFormatException ex) {
            throw new InvalidSellerWarehouseException();
        }
    }

    private List<String> normalizeCarrierPreferences(List<String> values) {

        if (values == null) {
            return List.of();
        }

        if (values.size() > MAX_CARRIERS) {
            throw new InvalidSellerWarehouseException();
        }

        LinkedHashSet<String> normalized = new LinkedHashSet<>();

        for (String value : values) {

            if (value == null) {
                throw new InvalidSellerWarehouseException();
            }

            String carrier = value.strip();

            int length = carrier.codePointCount(0, carrier.length());

            if (length < 1 || length > 32) {
                throw new InvalidSellerWarehouseException();
            }

            normalized.add(carrier);
        }

        return List.copyOf(new ArrayList<>(normalized));
    }

    private String requiredText(
            String value,
            int maxLength
    ) {

        if (value == null) {
            throw new InvalidSellerWarehouseException();
        }

        String normalized = value.strip();

        int length = normalized.codePointCount(0, normalized.length());

        if (length < 1 || length > maxLength) {
            throw new InvalidSellerWarehouseException();
        }

        return normalized;
    }

    private String optionalText(
            String value,
            int maxLength
    ) {

        if (value == null) {
            return null;
        }

        String normalized = value.strip();

        if (normalized.isEmpty()) {
            return null;
        }

        int length = normalized.codePointCount(0, normalized.length());

        if (length > maxLength) {
            throw new InvalidSellerWarehouseException();
        }

        return normalized;
    }
}
