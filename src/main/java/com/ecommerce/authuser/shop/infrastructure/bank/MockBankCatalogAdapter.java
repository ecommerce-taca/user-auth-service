package com.ecommerce.authuser.shop.infrastructure.bank;

import com.ecommerce.authuser.shop.port.BankCatalogPort;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

@Component
@Profile("!prod")
public class MockBankCatalogAdapter implements BankCatalogPort {

    private static final Map<String, BankInfo>
            BANKS =
            Map.of(
                    "MOCK_BANK",
                    new BankInfo(
                            "MOCK_BANK",
                            "Mock Bank"
                    ),
                    "NCB",
                    new BankInfo(
                            "NCB",
                            "Ngân hàng Quốc Dân (NCB - VNPAY Sandbox)"
                    )
            );

    @Override
    public Optional<BankInfo> findByCode(String bankCode) {
        if (bankCode == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(
                BANKS.get(
                        bankCode
                )
        );
    }
}
