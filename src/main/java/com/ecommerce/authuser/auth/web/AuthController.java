package com.ecommerce.authuser.auth.web;

import com.ecommerce.authuser.auth.application.mfa.*;
import com.ecommerce.authuser.auth.application.password.*;
import com.ecommerce.authuser.auth.application.session.*;
import com.ecommerce.authuser.auth.application.signin.SigninCommand;
import com.ecommerce.authuser.auth.application.signin.SigninResult;
import com.ecommerce.authuser.auth.application.signin.SigninService;
import com.ecommerce.authuser.auth.application.signout.SignoutCommand;
import com.ecommerce.authuser.auth.web.common.AuthTokenData;
import com.ecommerce.authuser.auth.web.session.SignoutRequest;
import com.ecommerce.authuser.auth.application.signout.SignoutService;
import com.ecommerce.authuser.auth.application.signup.SignupCommand;
import com.ecommerce.authuser.auth.application.signup.SignupResult;
import com.ecommerce.authuser.auth.application.signup.SignupService;
import com.ecommerce.authuser.auth.application.verification.email.*;
import com.ecommerce.authuser.auth.application.verification.phone.*;
import com.ecommerce.authuser.auth.exception.mfa.InvalidMfaVerifyRequestException;
import com.ecommerce.authuser.auth.exception.mfa.MfaAuthenticationRequiredException;
import com.ecommerce.authuser.auth.web.mfa.*;
import com.ecommerce.authuser.auth.web.password.PasswordChangeRequest;
import com.ecommerce.authuser.auth.web.password.PasswordChangeResponse;
import com.ecommerce.authuser.auth.web.password.PasswordForgotRequest;
import com.ecommerce.authuser.auth.web.password.PasswordForgotResponse;
import com.ecommerce.authuser.auth.web.password.PasswordResetRequest;
import com.ecommerce.authuser.auth.web.password.PasswordResetResponse;
import com.ecommerce.authuser.auth.web.session.RefreshRequest;
import com.ecommerce.authuser.auth.web.session.RefreshResponse;
import com.ecommerce.authuser.auth.web.signin.SigninRequest;
import com.ecommerce.authuser.auth.web.signin.SigninResponse;
import com.ecommerce.authuser.auth.web.signup.SignupRequest;
import com.ecommerce.authuser.auth.web.signup.SignupResponse;
import com.ecommerce.authuser.auth.web.verification.email.EmailResendRequest;
import com.ecommerce.authuser.auth.web.verification.email.EmailResendResponse;
import com.ecommerce.authuser.auth.web.verification.email.EmailVerificationRequest;
import com.ecommerce.authuser.auth.web.verification.email.EmailVerificationResponse;
import com.ecommerce.authuser.auth.web.verification.phone.PhoneOtpRequest;
import com.ecommerce.authuser.auth.web.verification.phone.PhoneOtpRequestResponse;
import com.ecommerce.authuser.auth.web.verification.phone.PhoneOtpVerifyRequest;
import com.ecommerce.authuser.auth.web.verification.phone.PhoneOtpVerifyResponse;
import com.ecommerce.authuser.common.id.UuidV7Generator;

import com.ecommerce.authuser.common.web.RequestIdResolver;
import com.ecommerce.authuser.common.web.RequestMeta;
import com.ecommerce.authuser.mfa.domain.MfaMethod;
import com.ecommerce.authuser.mfa.domain.MfaPurpose;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final SignupService signupService;

    private final SigninService signinService;

    private final RefreshService refreshService;

    private final SignoutService signoutService;

    private final EmailVerificationService emailVerificationService;

    private final EmailVerificationResendService emailVerificationResendService;

    private final PhoneOtpRequestService phoneOtpRequestService;

    private final PhoneOtpVerifyService phoneOtpVerifyService;

    private final PasswordForgotService passwordForgotService;

    private final PasswordResetService passwordResetService;

    private final PasswordChangeService passwordChangeService;

    private final MfaSetupService mfaSetupService;

    private final MfaEnrollVerifyService mfaEnrollVerifyService;

    private final MfaLoginVerifyService mfaLoginVerifyService;

    private final MfaStepUpVerifyService mfaStepUpVerifyService;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(
            @Valid @RequestBody SignupRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {

        SignupResult result = signupService.signup(
                new SignupCommand(
                        request.fullName(),
                        request.email(),
                        request.password(),
                        request.phone()
                )
        );

        String resolvedRequestId = RequestIdResolver.resolve(requestId);

        SignupResponse response = new SignupResponse(
                new SignupResponse.Data(
                        new SignupResponse.UserData(
                                result.userId(),
                                result.fullName(),
                                result.email(),
                                false,
                                result.phone(),
                                false,
                                List.of("BUYER"),
                                "ACTIVE"
                        ),

                        new AuthTokenData(
                                "Bearer",
                                result.accessToken(),
                                result.accessExpiresIn(),
                                result.refreshToken(),
                                result.refreshExpiresIn()
                        ),

                        new SignupResponse.VerificationData(
                                true,
                                result.verificationExpiresAt()
                        )
                ),

                new RequestMeta(resolvedRequestId)
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @PostMapping("/signin")
    public ResponseEntity<SigninResponse> signin(
            @Valid @RequestBody SigninRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId,
            HttpServletRequest httpRequest
    ) {

        SigninResult result = signinService.signin(
                new SigninCommand(
                        request.identifier(),
                        request.password(),
                        request.resolvedRememberMe(),
                        httpRequest.getRemoteAddr(),
                        httpRequest.getHeader("User-Agent")
                )
        );

        String resolvedRequestId = RequestIdResolver.resolve(requestId);

        SigninResponse response = new SigninResponse(
                new SigninResponse.Data(
                        new SigninResponse.UserData(
                                result.userId(),
                                result.fullName(),
                                result.email(),
                                result.emailVerified(),
                                result.phone(),
                                result.phoneVerified(),
                                result.roles(),
                                result.status()
                        ),

                        new AuthTokenData(
                                "Bearer",
                                result.accessToken(),
                                result.accessExpiresIn(),
                                result.refreshToken(),
                                result.refreshExpiresIn()
                        )
                ),

                new RequestMeta(resolvedRequestId)
        );

        return ResponseEntity.ok(
                response
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(
            @Valid @RequestBody RefreshRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId,
            HttpServletRequest httpRequest
    ) {
        RefreshResult result = refreshService.refresh(
                new RefreshCommand(
                        request.refreshToken(),
                        httpRequest.getRemoteAddr()
                )
        );

        RefreshResponse response = new RefreshResponse(
                new RefreshResponse.Data(
                        new AuthTokenData(
                            "Bearer",
                            result.accessToken(),
                            result.accessExpiresIn(),
                            result.refreshToken(),
                            result.refreshExpiresIn()
                        )
                ),

                new RequestMeta(RequestIdResolver.resolve(requestId)));

        return ResponseEntity.ok(response);
    }

    @PostMapping("/signout")
    public ResponseEntity<Void> signout(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody(required = false) SignoutRequest request,
            @RequestHeader(name = "X-MFA-Step-Up", required = false)String stepUpToken,
            HttpServletRequest httpRequest
    ) {

        UUID userId = UUID.fromString(jwt.getSubject());

        UUID sessionId = UUID.fromString(jwt.getClaimAsString("session_id"));

        String refreshToken =
                request == null
                        ? null
                        : request.refreshToken();

        boolean allSessions = request != null && request.resolvedAllSessions();

        signoutService.signout(
                new SignoutCommand(
                        userId,
                        sessionId,
                        refreshToken,
                        allSessions,
                        stepUpToken,
                        httpRequest.getRemoteAddr()
                )
        );

        return ResponseEntity
                .noContent()
                .build();
    }

    @PostMapping("/email/verify")
    public ResponseEntity<EmailVerificationResponse> verifyEmail(
            @Valid @RequestBody EmailVerificationRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {

        EmailVerificationResult result = emailVerificationService.verify(
                new EmailVerificationCommand(request.token())
        );

        EmailVerificationResponse response =
                new EmailVerificationResponse(
                        new EmailVerificationResponse.Data(
                                result.userId(),
                                true,
                                result.verifiedAt()
                        ),

                        new RequestMeta(RequestIdResolver.resolve(requestId))
                );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/email/resend")
    public ResponseEntity<EmailResendResponse>
    resendVerificationEmail(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody(required = false) EmailResendRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId,
            HttpServletRequest httpRequest
    ) {

        UUID userId = UUID.fromString(jwt.getSubject());

        EmailResendResult result = emailVerificationResendService.resend(
                new EmailResendCommand(
                        userId,
                        httpRequest.getRemoteAddr()
                )
        );

        EmailResendResponse response = new EmailResendResponse(
                new EmailResendResponse.Data(true, result.expiresAt()),
                new RequestMeta(RequestIdResolver.resolve(requestId)));

        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(response);
    }

    @PostMapping("/phone/request-otp")
    public ResponseEntity<PhoneOtpRequestResponse> requestPhoneOtp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PhoneOtpRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {

        UUID userId = UUID.fromString(jwt.getSubject());

        PhoneOtpRequestResult result = phoneOtpRequestService.request(
                new PhoneOtpRequestCommand(
                        userId,
                        request.phone()
                )
        );

        PhoneOtpRequestResponse response = new PhoneOtpRequestResponse(
                new PhoneOtpRequestResponse.Data(
                        result.challengeId(),
                        result.maskedPhone(),
                        result.expiresAt(),
                        result.maxAttempts()
                ),

                new RequestMeta(RequestIdResolver.resolve(requestId))
        );

        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(response);
    }

    @PostMapping("/phone/verify-otp")
    public ResponseEntity<PhoneOtpVerifyResponse> verifyPhoneOtp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PhoneOtpVerifyRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {
        UUID userId = UUID.fromString(jwt.getSubject());

        PhoneOtpVerifyResult result = phoneOtpVerifyService.verify(
                new PhoneOtpVerifyCommand(
                        userId,
                        request.challengeId(),
                        request.otp()
                )
        );

        PhoneOtpVerifyResponse response = new PhoneOtpVerifyResponse(
                new PhoneOtpVerifyResponse.Data(
                        true,
                        result.verifiedAt()
                ),

                new RequestMeta(RequestIdResolver.resolve(requestId))
        );

        return ResponseEntity.ok(
                response
        );
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<PasswordForgotResponse> forgotPassword(
            @Valid @RequestBody PasswordForgotRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {
        PasswordForgotResult result =
                passwordForgotService.forgot(
                        new PasswordForgotCommand(request.identifier())
                );

        PasswordForgotResponse response = new PasswordForgotResponse(
                new PasswordForgotResponse.Data(
                        result.accepted(),
                        "Nếu tài khoản tồn tại, hướng dẫn đặt lại mật khẩu sẽ được gửi."
                ),

                new RequestMeta(
                        RequestIdResolver.resolve(requestId))
                );

        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(response);
    }

    @PostMapping("/password/reset")
    public ResponseEntity<PasswordResetResponse> resetPassword(
            @Valid @RequestBody PasswordResetRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {
        PasswordResetResult result = passwordResetService.reset(
                new PasswordResetCommand(
                        request.token(),
                        request.newPassword()
                )
        );

        PasswordResetResponse response = new PasswordResetResponse(
                new PasswordResetResponse.Data(
                        new AuthTokenData(
                                "Bearer",
                                result.accessToken(),
                                result.accessExpiresIn(),
                                result.refreshToken(),
                                result.refreshExpiresIn()
                        )
                ),
                new RequestMeta(RequestIdResolver.resolve(requestId))
        );

        return ResponseEntity
                .ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(response);
    }

    @PostMapping("/password/change")
    public ResponseEntity<PasswordChangeResponse> changePassword(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PasswordChangeRequest request,
            @RequestHeader(name = "X-MFA-Step-Up", required = false) String stepUpToken,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId,
            HttpServletRequest httpRequest
    ) {
        UUID userId = UUID.fromString(jwt.getSubject());
        UUID sessionId = UUID.fromString(jwt.getClaimAsString("session_id"));
        PasswordChangeResult result = passwordChangeService.change(
                new PasswordChangeCommand(
                        userId,
                        sessionId,
                        request.currentPassword(),
                        request.newPassword(),
                        request.resolvedAllSessions(),
                        stepUpToken,
                        httpRequest.getRemoteAddr()
                )
        );

        AuthTokenData tokens = result.sessionTokens() == null
                ? null
                : new AuthTokenData(
                        "Bearer",
                        result.sessionTokens().accessToken(),
                        result.sessionTokens().accessExpiresIn(),
                        result.sessionTokens().refreshToken(),
                        result.sessionTokens().refreshExpiresIn()
                );

        PasswordChangeResponse response = new PasswordChangeResponse(
                new PasswordChangeResponse.Data(
                        result.allSessions(),
                        result.revokedSessionCount(),
                        tokens
                ),
                new RequestMeta(RequestIdResolver.resolve(requestId))
        );

        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(response);
    }

    @PostMapping("/2fa/setup")
    public ResponseEntity<MfaSetupResponse> setupMfa(
            @AuthenticationPrincipal Jwt jwt,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {
        UUID userId = UUID.fromString(jwt.getSubject());

        MfaSetupResult result = mfaSetupService.setup(new MfaSetupCommand(userId));

        MfaSetupResponse response =
                new MfaSetupResponse(
                        new MfaSetupResponse.Data(
                                result.setupId(),
                                result.issuer(),
                                result.account(),
                                result.otpauthUri(),
                                result.expiresAt()
                        ),

                        new RequestMeta(
                                RequestIdResolver.resolve(requestId)
                        )
                );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(response);
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<?> verifyMfa(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody MfaVerifyRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {
        String resolvedRequestId = RequestIdResolver.resolve(requestId);

        if (request.purpose() == MfaPurpose.ENROLL) {
            return verifyMfaEnrollment(
                    jwt,
                    request,
                    resolvedRequestId
            );
        }

        if (request.purpose() == MfaPurpose.LOGIN) {
            return verifyMfaLogin(
                    request,
                    resolvedRequestId
            );
        }

        if (request.purpose() == MfaPurpose.STEP_UP) {
            return verifyMfaStepUp(
                    jwt,
                    request,
                    resolvedRequestId
            );
        }

        throw new InvalidMfaVerifyRequestException();
    }

    private ResponseEntity<MfaEnrollVerifyResponse> verifyMfaEnrollment(
            Jwt jwt,
            MfaVerifyRequest request,
            String requestId
    ) {
        if (jwt == null) {
            throw new MfaAuthenticationRequiredException();
        }

        if (request.method() != MfaMethod.TOTP
                || request.setupId() == null
                || request.challengeId() != null) {
            throw new InvalidMfaVerifyRequestException();
        }

        UUID userId = UUID.fromString(jwt.getSubject());

        MfaEnrollVerifyResult result = mfaEnrollVerifyService.verify(
                new MfaEnrollVerifyCommand(
                        userId,
                        request.setupId(),
                        request.code()
                )
        );

        MfaEnrollVerifyResponse response = new MfaEnrollVerifyResponse(
                new MfaEnrollVerifyResponse.Data(
                        result.status(),
                        result.enabledAt(),
                        result.recoveryCodes()
                ),

                new RequestMeta(requestId)
        );

        return ResponseEntity
                .ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(response);
    }

    private ResponseEntity<MfaLoginVerifyResponse> verifyMfaLogin(
            MfaVerifyRequest request,
            String requestId
    ) {

        if (request.challengeId() == null || request.setupId() != null) {
            throw new InvalidMfaVerifyRequestException();
        }

        MfaLoginVerifyResult result = mfaLoginVerifyService.verify(
                new MfaLoginVerifyCommand(
                        request.challengeId(),
                        request.method(),
                        request.code()
                )
        );

        MfaLoginVerifyResponse response = new MfaLoginVerifyResponse(
                new MfaLoginVerifyResponse.Data(
                        new AuthTokenData(
                            "Bearer",
                            result.accessToken(),
                            result.accessExpiresIn(),
                            result.refreshToken(),
                            result.refreshExpiresIn()
                        )
                ),
                new RequestMeta(requestId)
        );

        return ResponseEntity
                .ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(response);
    }

    private ResponseEntity<MfaStepUpVerifyResponse> verifyMfaStepUp(
            Jwt jwt,
            MfaVerifyRequest request,
            String requestId
    ) {
        if (jwt == null) {
            throw new MfaAuthenticationRequiredException();
        }

        if (request.challengeId() == null
                || request.setupId() != null) {
            throw new InvalidMfaVerifyRequestException();
        }

        UUID userId;

        UUID sessionId;

        try {

            userId = UUID.fromString(jwt.getSubject());

            sessionId = UUID.fromString(
                    jwt.getClaimAsString("session_id")
            );

        } catch (RuntimeException ex) {

            throw new MfaAuthenticationRequiredException();
        }

        MfaStepUpVerifyResult result =
                mfaStepUpVerifyService.verify(

                        new MfaStepUpVerifyCommand(
                                userId,
                                sessionId,
                                request.challengeId(),
                                request.method(),
                                request.code()
                        )
                );

        MfaStepUpVerifyResponse response = new MfaStepUpVerifyResponse(
                new MfaStepUpVerifyResponse.Data(
                        result.stepUpToken(),
                        result.expiresAt()
                ),

                new RequestMeta(requestId)
                );

        return ResponseEntity
                .ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(response);
    }
}
