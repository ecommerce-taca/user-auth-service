package com.ecommerce.authuser.auth.google;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(GoogleIdTokenProperties.class)
public class GoogleIdTokenConfiguration {
}
