package com.ecommerce.authuser.shop.web.internal;

import com.ecommerce.authuser.common.id.CanonicalUuidParser;
import com.ecommerce.authuser.common.web.RequestIdResolver;

import com.ecommerce.authuser.internal.security.InternalServiceTokenVerifier;

import com.ecommerce.authuser.shop.application.pickupaddress.GetShopPickupAddressQuery;
import com.ecommerce.authuser.shop.application.pickupaddress.GetShopPickupAddressResult;
import com.ecommerce.authuser.shop.application.pickupaddress.GetShopPickupAddressService;

import com.ecommerce.authuser.shop.exception.InvalidPublicShopQueryException;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Internal endpoint for checkout-service and order-service. Not routed by
 * the API Gateway; callers authenticate with {@code X-Internal-Service-Token}.
 */
@RestController
@RequestMapping("/api/v1/internal/shops")
@RequiredArgsConstructor
public class GetShopPickupAddressController {

    private final InternalServiceTokenVerifier internalServiceTokenVerifier;

    private final GetShopPickupAddressService getShopPickupAddressService;

    @GetMapping("/{shopId}/pickup-address")
    public ResponseEntity<GetShopPickupAddressResponse> getPickupAddress(
            @PathVariable String shopId,
            @RequestHeader(name = "X-Internal-Service-Token", required = false) String internalToken,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {
        internalServiceTokenVerifier.verify(internalToken);

        UUID parsedShopId =
                CanonicalUuidParser.parse(
                        shopId,
                        InvalidPublicShopQueryException::new
                );

        GetShopPickupAddressResult result =
                getShopPickupAddressService.get(
                        new GetShopPickupAddressQuery(parsedShopId)
                );

        GetShopPickupAddressResult.Address address = result.address();

        GetShopPickupAddressResponse response =
                new GetShopPickupAddressResponse(
                        new GetShopPickupAddressResponse.Data(
                                result.shopId(),
                                result.warehouseName(),
                                result.contactName(),
                                result.contactPhone(),
                                new GetShopPickupAddressResponse.Address(
                                        address.line1(),
                                        address.line2(),
                                        address.ward(),
                                        address.district(),
                                        address.province(),
                                        address.postalCode()
                                ),
                                result.codEnabled(),
                                result.updatedAt()
                        ),
                        new GetShopPickupAddressResponse.Meta(
                                RequestIdResolver.resolve(requestId)
                        )
                );

        return ResponseEntity.ok(response);
    }
}
