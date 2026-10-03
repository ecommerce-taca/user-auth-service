ALTER TABLE refresh_tokens
    DROP CHECK ck_refresh_revoke_reason,
    ADD CONSTRAINT ck_refresh_revoke_reason
        CHECK (
            revoke_reason IS NULL
            OR revoke_reason IN (
                'ROTATED',
                'SIGNOUT',
                'RESET',
                'PASSWORD_CHANGE',
                'REUSE',
                'SUSPEND',
                'EXPIRED'
            )
        );
