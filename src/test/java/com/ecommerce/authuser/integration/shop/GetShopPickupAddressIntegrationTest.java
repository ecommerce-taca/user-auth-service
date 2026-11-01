package com.ecommerce.authuser.integration.shop;

import com.ecommerce.authuser.shop.domain.Shop;
import com.ecommerce.authuser.shop.repository.ShopRepository;
import com.ecommerce.authuser.support.base.BaseIntegrationTest;
import com.ecommerce.authuser.support.builder.ShopTestBuilder;
import com.ecommerce.authuser.support.builder.UserTestBuilder;
import com.ecommerce.authuser.user.domain.User;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class GetShopPickupAddressIntegrationTest extends BaseIntegrationTest {

    private static final String TOKEN = "test-internal-token";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ShopRepository shopRepository;

    @Test
    void getPickupAddress_shouldReturnWarehouseForInternalCaller() throws Exception {
        Shop shop = createShop(true);

        mockMvc.perform(
                        get("/api/v1/internal/shops/{shopId}/pickup-address", shop.getId())
                                .header("X-Internal-Service-Token", TOKEN)
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.shop_id").value(shop.getId().toString()))
                .andExpect(jsonPath("$.data.warehouse_name").value("Kho HCM"))
                .andExpect(jsonPath("$.data.contact_name").value("Nguyễn Văn B"))
                .andExpect(jsonPath("$.data.contact_phone").value("+84901234567"))
                .andExpect(jsonPath("$.data.address.line1").value("15 Lê Lợi"))
                .andExpect(jsonPath("$.data.address.ward").value("Bến Thành"))
                .andExpect(jsonPath("$.data.address.province").value("TP.HCM"))
                .andExpect(jsonPath("$.data.cod_enabled").value(true))
                .andExpect(jsonPath("$.meta.request_id").exists());
    }

    @Test
    void getPickupAddress_shouldRejectMissingOrWrongToken() throws Exception {
        Shop shop = createShop(true);

        mockMvc.perform(get("/api/v1/internal/shops/{shopId}/pickup-address", shop.getId()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("AUTH_TOKEN_INVALID"));

        mockMvc.perform(
                        get("/api/v1/internal/shops/{shopId}/pickup-address", shop.getId())
                                .header("X-Internal-Service-Token", "wrong")
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("AUTH_TOKEN_INVALID"));
    }

    @Test
    void getPickupAddress_shouldReturnConflictWhenWarehouseMissing() throws Exception {
        Shop shop = createShop(false);

        mockMvc.perform(
                        get("/api/v1/internal/shops/{shopId}/pickup-address", shop.getId())
                                .header("X-Internal-Service-Token", TOKEN)
                )
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("SHOP_WAREHOUSE_MISSING"));
    }

    @Test
    void getPickupAddress_shouldReturnNotFoundForUnknownShop() throws Exception {
        mockMvc.perform(
                        get("/api/v1/internal/shops/{shopId}/pickup-address", UUID.randomUUID())
                                .header("X-Internal-Service-Token", TOKEN)
                )
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("SHOP_NOT_FOUND"));
    }

    private Shop createShop(boolean withWarehouse) {
        String unique = UUID.randomUUID().toString();

        User owner = userRepository.saveAndFlush(
                UserTestBuilder
                        .aUser()
                        .withEmail("pickup-" + unique + "@test.com")
                        .withFullName("Pickup Seller")
                        .build()
        );

        Shop shop = ShopTestBuilder
                .forOwner(owner)
                .withSlug("pickup-" + unique)
                .build();

        if (withWarehouse) {
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
            warehouse.put("carrier_preferences", java.util.List.of("GHN"));
            warehouse.put("cod_enabled", true);

            shop.updateWarehouseSnapshot(warehouse);
        }

        return shopRepository.saveAndFlush(shop);
    }
}
