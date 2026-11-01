package com.ecommerce.authuser.shop.web.internal;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.UUID;

public record GetShopPickupAddressResponse(
        Data data,
        Meta meta
) {

    public record Data(
            @JsonProperty("shop_id")
            UUID shopId,

            @JsonProperty("warehouse_name")
            String warehouseName,

            @JsonProperty("contact_name")
            String contactName,

            @JsonProperty("contact_phone")
            String contactPhone,

            Address address,

            @JsonProperty("cod_enabled")
            boolean codEnabled,

            @JsonProperty("updated_at")
            Instant updatedAt
    ) {
    }

    public record Address(
            String line1,
            String line2,
            String ward,
            String district,
            String province,

            @JsonProperty("postal_code")
            String postalCode
    ) {
    }

    public record Meta(
            @JsonProperty("request_id")
            String requestId
    ) {
    }
}
