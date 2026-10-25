package com.ecommerce.authuser.kyc.exception;

public class InvalidKycDocumentException extends RuntimeException {

    private final Reason reason;

    public InvalidKycDocumentException() {
        this(Reason.REQUEST_INVALID);
    }

    public InvalidKycDocumentException(Reason reason) {
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }

    public enum Reason {
        REQUEST_INVALID,
        DOCUMENT_TYPE_UNSUPPORTED,
        FILE_NAME_INVALID,
        CONTENT_TYPE_UNSUPPORTED,
        SIZE_INVALID,
        CHECKSUM_INVALID,
        DUPLICATE,
        STATE_INVALID,
        VERIFICATION_FAILED,
        UPLOAD_INCOMPLETE,
        DOCUMENT_REQUIRED,
        PROFILE_INCOMPLETE
    }
}
