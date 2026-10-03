package com.ecommerce.authuser.common.web;

import com.ecommerce.authuser.address.exception.*;
import com.ecommerce.authuser.audit.exception.InvalidAdminAuditQueryException;
import com.ecommerce.authuser.auth.exception.mfa.*;
import com.ecommerce.authuser.auth.exception.password.InvalidCurrentPasswordException;
import com.ecommerce.authuser.auth.exception.password.InvalidPasswordInputException;
import com.ecommerce.authuser.auth.exception.password.InvalidPasswordRecoveryInputException;
import com.ecommerce.authuser.auth.exception.password.InvalidPasswordResetTokenException;
import com.ecommerce.authuser.auth.exception.password.PasswordReuseException;
import com.ecommerce.authuser.auth.exception.session.ExpiredRefreshTokenException;
import com.ecommerce.authuser.auth.exception.session.InvalidRefreshTokenException;
import com.ecommerce.authuser.auth.exception.session.ReusedRefreshTokenException;
import com.ecommerce.authuser.auth.exception.signin.AccountLockedException;
import com.ecommerce.authuser.auth.exception.signin.AccountSuspendedException;
import com.ecommerce.authuser.auth.exception.signin.AdminMfaRequiredException;
import com.ecommerce.authuser.auth.exception.signin.InvalidCredentialsException;
import com.ecommerce.authuser.auth.exception.signup.EmailAlreadyExistsException;
import com.ecommerce.authuser.auth.exception.signup.PhoneAlreadyExistsException;
import com.ecommerce.authuser.auth.exception.verification.email.InvalidVerificationTokenException;
import com.ecommerce.authuser.auth.exception.verification.email.ResendLimitExceededException;
import com.ecommerce.authuser.auth.exception.verification.email.VerificationAlreadyCompleteException;
import com.ecommerce.authuser.auth.exception.verification.phone.InvalidOtpException;
import com.ecommerce.authuser.auth.exception.verification.phone.InvalidPhoneFormatException;
import com.ecommerce.authuser.auth.exception.verification.phone.OtpAttemptsExceededException;
import com.ecommerce.authuser.auth.exception.verification.phone.OtpRateLimitedException;
import com.ecommerce.authuser.common.id.UuidV7Generator;

import com.ecommerce.authuser.favorite.exception.FavoriteLimitReachedException;
import com.ecommerce.authuser.favorite.exception.InvalidFavoriteInputException;
import com.ecommerce.authuser.favorite.exception.InvalidFavoriteQueryException;
import com.ecommerce.authuser.kyc.exception.*;
import com.ecommerce.authuser.location.exception.InvalidAdministrativeLocationException;
import com.ecommerce.authuser.location.exception.ProvinceNotFoundException;
import com.ecommerce.authuser.rbac.exception.AdminRbacPermissionDeniedException;
import com.ecommerce.authuser.rbac.exception.InvalidRoleAssignmentException;
import com.ecommerce.authuser.rbac.exception.RoleAssignmentExistsException;
import com.ecommerce.authuser.rbac.exception.RoleAssignmentNotFoundException;
import com.ecommerce.authuser.shop.exception.*;
import com.ecommerce.authuser.shopfollow.exception.InvalidShopFollowInputException;
import com.ecommerce.authuser.shopfollow.exception.InvalidShopFollowQueryException;
import com.ecommerce.authuser.shopfollow.exception.ShopFollowLimitReachedException;
import com.ecommerce.authuser.user.exception.admin.AdminUserStatusConflictException;
import com.ecommerce.authuser.user.exception.admin.InvalidAdminUserStatusRequestException;
import com.ecommerce.authuser.user.exception.profile.ProfileInvalidException;
import com.ecommerce.authuser.user.exception.profile.ProfilePhoneAlreadyExistsException;
import com.ecommerce.authuser.user.exception.profile.UserNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleEmailExists(EmailAlreadyExistsException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "AUTH_EMAIL_EXISTS",
                "Email đã được sử dụng."
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        Object details =
                ex.getBindingResult()
                        .getFieldErrors()
                        .stream()
                        .map(error ->
                                new ValidationDetail(
                                        error.getField(),
                                        error.getDefaultMessage()
                                )
                        )
                        .toList();

        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Dữ liệu đầu vào không hợp lệ.",
                details
        );
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCredentials(InvalidCredentialsException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_INVALID_CREDENTIALS",
                "Email/số điện thoại hoặc mật khẩu không đúng."
        );
    }

    @ExceptionHandler(AccountSuspendedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccountSuspended(AccountSuspendedException ex) {
        return buildError(
                HttpStatus.FORBIDDEN,
                "AUTH_ACCOUNT_SUSPENDED",
                "Tài khoản hiện không thể sử dụng."
        );
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccountLocked(AccountLockedException ex) {
        return buildError(
                HttpStatus.LOCKED,
                "AUTH_ACCOUNT_LOCKED",
                "Tài khoản đang tạm khóa. Vui lòng thử lại sau."
        );
    }

    @ExceptionHandler(AdminMfaRequiredException.class)
    public ResponseEntity<ApiErrorResponse> handleAdminMfaRequired(AdminMfaRequiredException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_MFA_REQUIRED",
                "Vui lòng xác thực 2FA.",
                java.util.Map.of(
                        "challenge_id",
                        ex.getChallengeId(),
                        "expires_at",
                        ex.getExpiresAt(),
                        "methods",
                        ex.getMethods()
                )
        );
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidRefreshToken(InvalidRefreshTokenException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_TOKEN_INVALID",
                "Refresh token không hợp lệ."
        );
    }

    @ExceptionHandler(ExpiredRefreshTokenException.class)
    public ResponseEntity<ApiErrorResponse> handleExpiredRefreshToken(ExpiredRefreshTokenException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_TOKEN_EXPIRED",
                "Refresh token đã hết hạn."
        );
    }

    @ExceptionHandler(ReusedRefreshTokenException.class)
    public ResponseEntity<ApiErrorResponse> handleReusedRefreshToken(ReusedRefreshTokenException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_REFRESH_REUSED",
                "Refresh token đã được sử dụng trước đó."
        );
    }

    @ExceptionHandler(MfaStepUpRequiredException.class)
    public ResponseEntity<ApiErrorResponse> handleMfaStepUpRequired(MfaStepUpRequiredException ex) {
        Object details =
                ex.getChallengeId() == null
                        ? null
                        : java.util.Map.of(
                        "challenge_id",
                        ex.getChallengeId(),
                        "expires_at",
                        ex.getExpiresAt(),
                        "methods",
                        ex.getMethods()
                );

        return buildError(
                HttpStatus.PRECONDITION_REQUIRED,
                "RBAC_MFA_REQUIRED",
                "Vui lòng xác thực lại trước khi tiếp tục.",
                details
        );
    }

    @ExceptionHandler(InvalidVerificationTokenException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidVerificationToken(InvalidVerificationTokenException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_VERIFICATION_INVALID",
                "Token xác thực không hợp lệ hoặc đã hết hạn."
        );
    }

    @ExceptionHandler(VerificationAlreadyCompleteException.class)
    public ResponseEntity<ApiErrorResponse> handleVerificationAlreadyComplete(VerificationAlreadyCompleteException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "AUTH_VERIFICATION_ALREADY_COMPLETE",
                "Thông tin này đã được xác thực."
        );
    }

    @ExceptionHandler(ResendLimitExceededException.class)
    public ResponseEntity<ApiErrorResponse> handleResendLimitExceeded(ResendLimitExceededException ex) {
        return buildError(
                HttpStatus.TOO_MANY_REQUESTS,
                "AUTH_RESEND_LIMIT_EXCEEDED",
                "Đã vượt quá số lần gửi lại email xác thực cho phép."
        );
    }

    @ExceptionHandler(InvalidPhoneFormatException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidPhoneFormat(InvalidPhoneFormatException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Số điện thoại không đúng định dạng."
        );
    }

    @ExceptionHandler(OtpRateLimitedException.class)
    public ResponseEntity<ApiErrorResponse> handleOtpRateLimited(OtpRateLimitedException ex) {
        return buildError(
                HttpStatus.TOO_MANY_REQUESTS,
                "AUTH_OTP_RATE_LIMITED",
                "Vui lòng thử lại sau."
        );
    }

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidOtp(InvalidOtpException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_VERIFICATION_INVALID",
                "Mã xác thực không hợp lệ hoặc đã hết hạn."
        );
    }

    @ExceptionHandler(OtpAttemptsExceededException.class)
    public ResponseEntity<ApiErrorResponse> handleOtpAttemptsExceeded(OtpAttemptsExceededException ex) {
        return buildError(
                HttpStatus.TOO_MANY_REQUESTS,
                "AUTH_OTP_ATTEMPTS_EXCEEDED",
                "Bạn đã thử quá số lần cho phép."
        );
    }

    @ExceptionHandler(InvalidPasswordRecoveryInputException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidPasswordRecoveryInput(InvalidPasswordRecoveryInputException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Thông tin chưa đúng."
        );
    }

    @ExceptionHandler(InvalidPasswordResetTokenException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidPasswordResetToken(InvalidPasswordResetTokenException ex) {

        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_RESET_INVALID",
                "Liên kết đặt lại mật khẩu không hợp lệ."
        );
    }

    @ExceptionHandler(InvalidPasswordInputException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidPasswordInput(InvalidPasswordInputException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Mật khẩu mới chưa đáp ứng yêu cầu."
        );
    }

    @ExceptionHandler(InvalidCurrentPasswordException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCurrentPassword(InvalidCurrentPasswordException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_CURRENT_PASSWORD_INVALID",
                "Mật khẩu hiện tại không đúng."
        );
    }

    @ExceptionHandler(PasswordReuseException.class)
    public ResponseEntity<ApiErrorResponse> handlePasswordReuse(PasswordReuseException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_PASSWORD_REUSE",
                "Mật khẩu mới phải khác mật khẩu hiện tại."
        );
    }

    @ExceptionHandler(MfaAlreadyEnabledException.class)
    public ResponseEntity<ApiErrorResponse> handleMfaAlreadyEnabled(MfaAlreadyEnabledException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "AUTH_MFA_ALREADY_ENABLED",
                "2FA đã được bật."
        );
    }

    @ExceptionHandler(InvalidMfaCodeException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidMfaCode(InvalidMfaCodeException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_MFA_INVALID",
                "Mã 2FA không đúng."
        );
    }

    @ExceptionHandler(MfaChallengeExpiredException.class)
    public ResponseEntity<ApiErrorResponse> handleMfaChallengeExpired(MfaChallengeExpiredException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_MFA_CHALLENGE_EXPIRED",
                "Phiên xác thực 2FA đã hết hạn."
        );
    }

    @ExceptionHandler(MfaAttemptsExceededException.class)
    public ResponseEntity<ApiErrorResponse> handleMfaAttemptsExceeded(MfaAttemptsExceededException ex) {
        return buildError(
                HttpStatus.TOO_MANY_REQUESTS,
                "AUTH_MFA_ATTEMPTS_EXCEEDED",
                "Bạn đã thử quá số lần cho phép."
        );
    }

    @ExceptionHandler(MfaAuthenticationRequiredException.class)
    public ResponseEntity<ApiErrorResponse> handleMfaAuthenticationRequired(MfaAuthenticationRequiredException ex) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "AUTH_TOKEN_INVALID",
                "Phiên đăng nhập không hợp lệ."
        );
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleUserNotFound(UserNotFoundException ex) {
        return buildError(
                HttpStatus.NOT_FOUND,
                "AUTH_USER_NOT_FOUND",
                "Không tìm thấy tài khoản."
        );
    }

    @ExceptionHandler(AddressLimitReachedException.class)
    public ResponseEntity<ApiErrorResponse> handleAddressLimitReached(AddressLimitReachedException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "ADDRESS_LIMIT_REACHED",
                "Bạn đã đạt giới hạn số địa chỉ."
        );
    }

    @ExceptionHandler(AddressNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleAddressNotFound(AddressNotFoundException ex) {
        return buildError(
                HttpStatus.NOT_FOUND,
                "ADDRESS_NOT_FOUND",
                "Không tìm thấy địa chỉ."
        );
    }

    @ExceptionHandler(AddressDefaultRequiredException.class)
    public ResponseEntity<ApiErrorResponse> handleAddressDefaultRequired(AddressDefaultRequiredException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "ADDRESS_DEFAULT_REQUIRED",
                "Cần có một địa chỉ mặc định."
        );
    }

    @ExceptionHandler(ProvinceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleProvinceNotFound(ProvinceNotFoundException ex) {
        return buildError(
                HttpStatus.NOT_FOUND,
                "LOCATION_PROVINCE_NOT_FOUND",
                "Khong tim thay Tinh/Thanh pho."
        );
    }

    @ExceptionHandler(InvalidAdministrativeLocationException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidAdministrativeLocation(
            InvalidAdministrativeLocationException ex
    ) {
        return buildError(
                HttpStatus.UNPROCESSABLE_ENTITY,
                "ADDRESS_LOCATION_INVALID",
                "Tinh/Thanh pho va Xa/Phuong khong hop le."
        );
    }

    @ExceptionHandler(SellerEmailNotVerifiedException.class)
    public ResponseEntity<ApiErrorResponse> handleSellerEmailNotVerified(SellerEmailNotVerifiedException ex) {
        return buildError(
                HttpStatus.FORBIDDEN,
                "AUTH_EMAIL_NOT_VERIFIED",
                "Vui lòng xác thực email trước."
        );
    }

    @ExceptionHandler(ShopAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleShopAlreadyExists(ShopAlreadyExistsException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "SHOP_ALREADY_EXISTS",
                "Tài khoản đã có hồ sơ người bán."
        );
    }

    @ExceptionHandler(TaxCodeAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleTaxCodeAlreadyExists(TaxCodeAlreadyExistsException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "AUTH_TAX_CODE_EXISTS",
                "Mã số thuế đã được sử dụng."
        );
    }

    @ExceptionHandler(ShopSlugAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleShopSlugAlreadyExists(ShopSlugAlreadyExistsException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "SHOP_SLUG_EXISTS",
                "Đường dẫn gian hàng đã tồn tại."
        );
    }

    @ExceptionHandler(ShopNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleShopNotFound(
            ShopNotFoundException ex
    ) {
        return buildError(
                HttpStatus.NOT_FOUND,
                "SHOP_NOT_FOUND",
                "Không tìm thấy gian hàng."
        );
    }

    @ExceptionHandler(ShopInvalidStateException.class)
    public ResponseEntity<ApiErrorResponse> handleShopInvalidState(ShopInvalidStateException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "SHOP_INVALID_STATE",
                "Trạng thái gian hàng không cho phép thao tác."
        );
    }

    @ExceptionHandler(InvalidKycDocumentException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidKycDocument(InvalidKycDocumentException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "KYC_DOCUMENT_INVALID",
                "Tài liệu không hợp lệ."
        );
    }

    @ExceptionHandler(KycDocumentTooLargeException.class)
    public ResponseEntity<ApiErrorResponse> handleKycDocumentTooLarge(KycDocumentTooLargeException ex) {
        return buildError(
                HttpStatus.PAYLOAD_TOO_LARGE,
                "KYC_DOCUMENT_TOO_LARGE",
                "Tài liệu vượt quá dung lượng cho phép."
        );
    }

    @ExceptionHandler(KycDocumentLimitReachedException.class)
    public ResponseEntity<ApiErrorResponse> handleKycDocumentLimitReached(KycDocumentLimitReachedException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "KYC_DOCUMENT_LIMIT_REACHED",
                "Hồ sơ đã đạt giới hạn số tài liệu."
        );
    }

    @ExceptionHandler(KycAlreadyPendingException.class)
    public ResponseEntity<ApiErrorResponse> handleKycAlreadyPending(KycAlreadyPendingException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "KYC_ALREADY_PENDING",
                "Hồ sơ đang được xét duyệt."
        );
    }

    @ExceptionHandler(KycDocumentNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleKycDocumentNotFound(KycDocumentNotFoundException ex) {
        return buildError(
                HttpStatus.NOT_FOUND,
                "KYC_DOCUMENT_NOT_FOUND",
                "Không tìm thấy tài liệu."
        );
    }

    @ExceptionHandler(KycDocumentAlreadyCompletedException.class)
    public ResponseEntity<ApiErrorResponse> handleKycDocumentAlreadyCompleted(KycDocumentAlreadyCompletedException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "KYC_DOCUMENT_ALREADY_COMPLETED",
                "Tài liệu đã được hoàn tất."
        );
    }

    @ExceptionHandler(BankAccountInvalidException.class)
    public ResponseEntity<ApiErrorResponse> handleBankAccountInvalid(BankAccountInvalidException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "BANK_ACCOUNT_INVALID",
                "Thông tin tài khoản ngân hàng chưa hợp lệ."
        );
    }

    @ExceptionHandler(KycCaseNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleKycCaseNotFound(KycCaseNotFoundException ex) {
        return buildError(
                HttpStatus.NOT_FOUND,
                "KYC_CASE_NOT_FOUND",
                "Không tìm thấy hồ sơ KYC."
        );
    }

    @ExceptionHandler(InvalidKycReviewRequestException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidKycReviewRequest(InvalidKycReviewRequestException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "KYC_DECISION_INVALID",
                "Quyết định KYC chưa hợp lệ."
        );
    }

    @ExceptionHandler(KycDecisionConflictException.class)
    public ResponseEntity<ApiErrorResponse> handleKycDecisionConflict(KycDecisionConflictException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "KYC_DECISION_INVALID",
                "Quyết định KYC chưa hợp lệ."
        );
    }

    @ExceptionHandler(InvalidRoleAssignmentException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidRoleAssignment(InvalidRoleAssignmentException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "RBAC_INVALID_ROLE",
                "Vai trò hoặc phạm vi không hợp lệ."
        );
    }

    @ExceptionHandler(RoleAssignmentExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleRoleAssignmentExists(RoleAssignmentExistsException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "RBAC_ASSIGNMENT_EXISTS",
                "Quyền này đã được cấp."
        );
    }

    @ExceptionHandler(RoleAssignmentNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleRoleAssignmentNotFound(RoleAssignmentNotFoundException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "RBAC_ASSIGNMENT_NOT_FOUND",
                "Không tìm thấy quyền cần thu hồi."
        );
    }

    @ExceptionHandler(AdminUserStatusConflictException.class)
    public ResponseEntity<ApiErrorResponse> handleAdminUserStatusConflict(AdminUserStatusConflictException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "AUTH_ACCOUNT_SUSPENDED",
                "Trạng thái tài khoản hiện tại không cho phép thao tác."
        );
    }

    @ExceptionHandler(InvalidAdminAuditQueryException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidAdminAuditQuery(InvalidAdminAuditQueryException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Dữ liệu truy vấn không hợp lệ."
        );
    }

    @ExceptionHandler(FavoriteLimitReachedException.class)
    public ResponseEntity<ApiErrorResponse> handleFavoriteLimitReached(FavoriteLimitReachedException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "FAVORITE_LIMIT_REACHED",
                "Bạn đã đạt giới hạn số sản phẩm yêu thích."
        );
    }

    @ExceptionHandler(ShopFollowLimitReachedException.class)
    public ResponseEntity<ApiErrorResponse> handleShopFollowLimitReached(ShopFollowLimitReachedException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "SHOP_FOLLOW_LIMIT_REACHED",
                "Bạn đã đạt giới hạn số shop có thể theo dõi."
        );
    }

    @ExceptionHandler(InvalidShopFollowQueryException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidShopFollowQuery(InvalidShopFollowQueryException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Thông tin truy vấn chưa đúng."
        );
    }

    @ExceptionHandler(InvalidPublicShopQueryException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidPublicShopQuery(InvalidPublicShopQueryException ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Thông tin shop chưa đúng."
        );
    }

    @ExceptionHandler({
            PhoneAlreadyExistsException.class,
            ProfilePhoneAlreadyExistsException.class
    })
    public ResponseEntity<ApiErrorResponse> handlePhoneAlreadyExists(RuntimeException ex) {
        return buildError(
                HttpStatus.CONFLICT,
                "AUTH_PHONE_EXISTS",
                "Số điện thoại đã được sử dụng."
        );
    }

    @ExceptionHandler({
            MfaSetupForbiddenException.class,
            SellerPermissionDeniedException.class,
            AdminKycPermissionDeniedException.class,
            AdminRbacPermissionDeniedException.class
    })
    public ResponseEntity<ApiErrorResponse> handlePermissionDenied(RuntimeException ex) {
        return buildError(
                HttpStatus.FORBIDDEN,
                "RBAC_PERMISSION_DENIED",
                "Bạn không có quyền thực hiện thao tác này."
        );
    }

    @ExceptionHandler({
            ProfileInvalidException.class,
            InvalidAddressInputException.class,
            InvalidSellerRegistrationException.class,
            InvalidSellerProfileException.class,
            InvalidSellerWarehouseException.class,
            InvalidSellerBankException.class,
            InvalidSellerShopProfileException.class
    })
    public ResponseEntity<ApiErrorResponse> handleProfileInvalid(Exception ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "PROFILE_INVALID",
                "Thông tin hồ sơ chưa đúng."
        );
    }

    @ExceptionHandler({
            InvalidMfaVerifyRequestException.class,
            HttpMessageNotReadableException.class,
            InvalidAdminKycQueueQueryException.class,
            InvalidAdminUserStatusRequestException.class
    })
    public ResponseEntity<ApiErrorResponse> handleInvalidRequest(Exception ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Dữ liệu đầu vào không hợp lệ."
        );
    }

    @ExceptionHandler({
            InvalidAddressQueryException.class,
            InvalidFavoriteQueryException.class,
            InvalidFavoriteInputException.class,
            InvalidShopFollowInputException.class
    })
    public ResponseEntity<ApiErrorResponse> handleInvalidInput(Exception ex) {
        return buildError(
                HttpStatus.BAD_REQUEST,
                "AUTH_INVALID_INPUT",
                "Thông tin gửi lên chưa đúng."
        );
    }

    private ResponseEntity<ApiErrorResponse> buildError(
            HttpStatus status,
            String code,
            String message
    ) {
        return buildError(
                status,
                code,
                message,
                null
        );
    }

    private ResponseEntity<ApiErrorResponse> buildError(
            HttpStatus status,
            String code,
            String message,
            Object details
    ) {
        String traceId = UuidV7Generator.generate().toString();

        ApiErrorResponse body =
                new ApiErrorResponse(
                        new ApiErrorResponse.ErrorData(
                                code,
                                message,
                                details,
                                traceId
                        )
                );

        return ResponseEntity
                .status(status)
                .body(body);
    }

    private record ValidationDetail(
            String field,
            String message
    ) {
    }
}
