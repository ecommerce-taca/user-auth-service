package com.ecommerce.authuser.common.web;

import com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException.Reason.*;
import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerKycTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleInvalidKycDocument_shouldReturnSpecificErrorForEveryReason() {
        List<ExpectedError> expectedErrors = List.of(
                new ExpectedError(REQUEST_INVALID, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_REQUEST_INVALID"),
                new ExpectedError(DOCUMENT_TYPE_UNSUPPORTED, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_TYPE_UNSUPPORTED"),
                new ExpectedError(FILE_NAME_INVALID, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_FILENAME_INVALID"),
                new ExpectedError(CONTENT_TYPE_UNSUPPORTED, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_CONTENT_TYPE_UNSUPPORTED"),
                new ExpectedError(SIZE_INVALID, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_SIZE_INVALID"),
                new ExpectedError(CHECKSUM_INVALID, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_CHECKSUM_INVALID"),
                new ExpectedError(DUPLICATE, HttpStatus.CONFLICT, "KYC_DOCUMENT_DUPLICATE"),
                new ExpectedError(STATE_INVALID, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_STATE_INVALID"),
                new ExpectedError(VERIFICATION_FAILED, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_VERIFICATION_FAILED"),
                new ExpectedError(UPLOAD_INCOMPLETE, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_UPLOAD_INCOMPLETE"),
                new ExpectedError(DOCUMENT_REQUIRED, HttpStatus.BAD_REQUEST, "KYC_DOCUMENT_REQUIRED"),
                new ExpectedError(PROFILE_INCOMPLETE, HttpStatus.BAD_REQUEST, "SELLER_PROFILE_INCOMPLETE")
        );

        for (ExpectedError expected : expectedErrors) {
            ResponseEntity<ApiErrorResponse> response =
                    handler.handleInvalidKycDocument(
                            new InvalidKycDocumentException(expected.reason())
                    );

            assertThat(response.getStatusCode())
                    .isEqualTo(expected.status());

            assertThat(response.getBody())
                    .isNotNull();

            assertThat(response.getBody().error().code())
                    .isEqualTo(expected.code());

            assertThat(response.getBody().error().message())
                    .isNotBlank();

            assertThat(response.getBody().error().traceId())
                    .isNotBlank();
        }
    }

    private record ExpectedError(
            InvalidKycDocumentException.Reason reason,
            HttpStatus status,
            String code
    ) {
    }
}
