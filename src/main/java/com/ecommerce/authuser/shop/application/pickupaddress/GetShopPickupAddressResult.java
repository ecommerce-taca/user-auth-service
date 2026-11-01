package com.ecommerce.authuser.shop.application.pickupaddress;

import java.time.Instant;
import java.util.UUID;

public record GetShopPickupAddressResult(
        UUID shopId,
        String warehouseName,
        String contactName,
        String contactPhone,
        Address address,
        boolean codEnabled,
        Instant updatedAt
) {

    public record Address(
            String line1,
            String line2,
            String ward,
            String district,
            String province,
            String postalCode
    ) {
    }
}
