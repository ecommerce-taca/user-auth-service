package com.ecommerce.authuser.shop.application.pickupaddress;

import com.ecommerce.authuser.shop.domain.Shop;
import com.ecommerce.authuser.shop.domain.ShopStatus;
import com.ecommerce.authuser.shop.exception.ShopNotFoundException;
import com.ecommerce.authuser.shop.exception.ShopWarehouseMissingException;
import com.ecommerce.authuser.shop.repository.ShopRepository;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GetShopPickupAddressServiceTest {

    private final ShopRepository shopRepository = mock(ShopRepository.class);

    private final GetShopPickupAddressService service = new GetShopPickupAddressService(shopRepository);

    private final UUID shopId = UUID.fromString("01912f31-7a1b-7c12-9c55-8b1c34a6d921");

    @Test
    void get_shouldMapWarehouseSnapshot() {
        Instant updatedAt = Instant.parse("2026-10-20T08:00:00Z");
        Shop shop = shop(ShopStatus.ACTIVE, warehouse(true), updatedAt);

        GetShopPickupAddressResult result = service.get(new GetShopPickupAddressQuery(shopId));

        assertEquals(shopId, result.shopId());
        assertEquals("Kho HCM", result.warehouseName());
        assertEquals("Nguyễn Văn B", result.contactName());
        assertEquals("+84901234567", result.contactPhone());
        assertEquals("15 Lê Lợi", result.address().line1());
        assertNull(result.address().line2());
        assertEquals("Bến Thành", result.address().ward());
        assertEquals("Quận 1", result.address().district());
        assertEquals("TP.HCM", result.address().province());
        assertTrue(result.codEnabled());
        assertEquals(updatedAt, result.updatedAt());
    }

    @Test
    void get_shouldReturnAddressForSuspendedShopSoExistingOrdersCanShip() {
        shop(ShopStatus.SUSPENDED, warehouse(false), Instant.now());

        GetShopPickupAddressResult result = service.get(new GetShopPickupAddressQuery(shopId));

        assertFalse(result.codEnabled());
    }

    @Test
    void get_shouldRejectMissingWarehouse() {
        shop(ShopStatus.DRAFT, Map.of(), Instant.now());

        assertThrows(
                ShopWarehouseMissingException.class,
                () -> service.get(new GetShopPickupAddressQuery(shopId))
        );
    }

    @Test
    void get_shouldRejectUnknownOrDeletedShop() {
        when(shopRepository.findByIdAndDeletedAtIsNull(shopId)).thenReturn(Optional.empty());

        assertThrows(
                ShopNotFoundException.class,
                () -> service.get(new GetShopPickupAddressQuery(shopId))
        );

        shop(ShopStatus.DELETED, warehouse(true), Instant.now());

        assertThrows(
                ShopNotFoundException.class,
                () -> service.get(new GetShopPickupAddressQuery(shopId))
        );
    }

    private Shop shop(ShopStatus status, Map<String, Object> warehouse, Instant updatedAt) {
        Shop shop = mock(Shop.class);
        when(shop.getId()).thenReturn(shopId);
        when(shop.getStatus()).thenReturn(status);
        when(shop.getWarehouseSnapshot()).thenReturn(warehouse);
        when(shop.getUpdatedAt()).thenReturn(updatedAt);
        when(shopRepository.findByIdAndDeletedAtIsNull(shopId)).thenReturn(Optional.of(shop));
        return shop;
    }

    private static Map<String, Object> warehouse(boolean codEnabled) {
        Map<String, Object> address = new LinkedHashMap<>();
        address.put("line1", "15 Lê Lợi");
        address.put("line2", null);
        address.put("ward", "Bến Thành");
        address.put("district", "Quận 1");
        address.put("province", "TP.HCM");
        address.put("postal_code", null);

        Map<String, Object> warehouse = new LinkedHashMap<>();
        warehouse.put("warehouse_name", "Kho HCM");
        warehouse.put("contact_name", "Nguyễn Văn B");
        warehouse.put("contact_phone", "+84901234567");
        warehouse.put("address", address);
        warehouse.put("cod_enabled", codEnabled);
        return warehouse;
    }
}
