package com.ecommerce.authuser.kyc.exception;

import com.ecommerce.authuser.shop.domain.KycStatus;

import lombok.Getter;

@Getter
public class KycDocumentDeleteNotAllowedException extends RuntimeException {

    private final KycStatus kycStatus;

    public KycDocumentDeleteNotAllowedException(KycStatus kycStatus) {
        this.kycStatus = kycStatus;
    }
}
