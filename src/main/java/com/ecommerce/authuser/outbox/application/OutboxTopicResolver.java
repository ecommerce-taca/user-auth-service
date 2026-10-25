package com.ecommerce.authuser.outbox.application;

import com.ecommerce.authuser.outbox.domain.OutboxEvent;
import com.ecommerce.authuser.outbox.infrastructure.kafka.KafkaTopicProperties;

import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class OutboxTopicResolver {

    public static final Set<String> NOTIFICATION_COMMAND_TYPES = Set.of(
            "AUTH_VERIFICATION_REQUESTED",
            "PASSWORD_RESET_REQUESTED",
            "PHONE_OTP_REQUESTED"
    );

    public static final Set<String> USER_EVENT_TYPES = Set.of(
            "user.created",
            "user.email_verified",
            "user.password_changed",
            "user.role_changed",
            "user.status_changed",
            "user.updated"
    );

    public static final Set<String> SHOP_EVENT_TYPES = Set.of(
            "shop.created",
            "shop.updated",
            "shop.status_changed",
            "shop.kyc.submitted",
            "shop.kyc.approved",
            "shop.kyc.rejected",
            "shop.kyc.needs_info",
            "shop.kyc.expired"
    );

    public static final Set<String> KYC_EVENT_TYPES = Set.of(
            "kyc.document.delete_requested"
    );

    private final KafkaTopicProperties topics;

    public OutboxTopicResolver(KafkaTopicProperties topics) {
        this.topics = topics;
    }

    public String resolveTopic(OutboxEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("outbox event must not be null");
        }

        return resolveTopic(event.getEventType());
    }

    public String resolveTopic(String eventType) {
        if (eventType == null || eventType.isBlank()) {
            throw new IllegalArgumentException("event type must not be blank");
        }

        if (NOTIFICATION_COMMAND_TYPES.contains(eventType)) {
            return topics.getNotificationCommands();
        }

        if (USER_EVENT_TYPES.contains(eventType)) {
            return topics.getUserEvents();
        }

        if (SHOP_EVENT_TYPES.contains(eventType)) {
            return topics.getShopEvents();
        }

        if (KYC_EVENT_TYPES.contains(eventType)) {
            return topics.getShopEvents();
        }

        throw new IllegalArgumentException(
                "Unsupported outbox event type: " + eventType
        );
    }

    public String resolveDlqTopic() {
        return topics.getDlq();
    }

    public boolean isNotificationCommand(String eventType) {
        return NOTIFICATION_COMMAND_TYPES.contains(eventType);
    }
}
