package com.ecommerce.authuser.shop.application.pickupaddress;

import com.ecommerce.authuser.shop.domain.Shop;
import com.ecommerce.authuser.shop.domain.ShopStatus;

import com.ecommerce.authuser.shop.exception.InvalidPublicShopQueryException;
import com.ecommerce.authuser.shop.exception.ShopNotFoundException;
import com.ecommerce.authuser.shop.exception.ShopWarehouseMissingException;

import com.ecommerce.authuser.shop.repository.ShopRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

/**
 * Reads the pickup (warehouse) address a seller saved in onboarding step
 * "Kho & vận chuyển" ({@code shops.warehouse_snapshot}) for internal callers
 * (checkout-service quotes, order-service carrier quotes and shipments).
 *
 * <p>Suspended shops still return their address so already placed orders
 * can be shipped; only deleted shops are hidden.</p>
 */
@Service
@RequiredArgsConstructor
public class GetShopPickupAddressService {

    private final ShopRepository shopRepository;

    @Transactional(readOnly = true)
    public GetShopPickupAddressResult get(GetShopPickupAddressQuery query) {
        if (query == null || query.shopId() == null) {
            throw new InvalidPublicShopQueryException();
        }

        Shop shop = shopRepository
                .findByIdAndDeletedAtIsNull(query.shopId())
                .orElseThrow(ShopNotFoundException::new);

        if (shop.getStatus() == ShopStatus.DELETED) {
            throw new ShopNotFoundException();
        }

        Map<String, Object> warehouse = asMap(shop.getWarehouseSnapshot());
        Map<String, Object> address = asMap(warehouse.get("address"));

        String warehouseName = text(warehouse.get("warehouse_name"));
        String contactName = text(warehouse.get("contact_name"));
        String contactPhone = text(warehouse.get("contact_phone"));
        String line1 = text(address.get("line1"));
        String ward = text(address.get("ward"));
        String province = text(address.get("province"));

        if (isBlank(warehouseName)
                || isBlank(contactName)
                || isBlank(contactPhone)
                || isBlank(line1)
                || isBlank(ward)
                || isBlank(province)) {
            throw new ShopWarehouseMissingException();
        }

        Object codEnabled = warehouse.get("cod_enabled");

        return new GetShopPickupAddressResult(
                shop.getId(),
                warehouseName,
                contactName,
                contactPhone,
                new GetShopPickupAddressResult.Address(
                        line1,
                        text(address.get("line2")),
                        ward,
                        text(address.get("district")),
                        province,
                        text(address.get("postal_code"))
                ),
                !(codEnabled instanceof Boolean enabled) || enabled,
                shop.getUpdatedAt()
        );
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map<?, ?> map
                ? (Map<String, Object>) map
                : Map.of();
    }

    private static String text(Object value) {
        return value instanceof String string ? string : null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
