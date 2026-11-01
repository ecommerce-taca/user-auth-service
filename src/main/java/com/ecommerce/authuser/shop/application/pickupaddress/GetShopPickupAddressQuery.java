package com.ecommerce.authuser.shop.application.pickupaddress;

import java.util.UUID;

public record GetShopPickupAddressQuery(
        UUID shopId
) {
}
