package com.github.base.security.keycloak;

import com.github.base.security.keycloak.config.KeycloakAdviser;
import com.github.base.security.keycloak.login.LoginController;
import com.github.base.security.keycloak.servlet.AuditorProvider;
import com.github.base.security.keycloak.servlet.SecurityConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Import({
    SecurityConfiguration.class,
    AuditorProvider.class,
    LoginController.class,
    KeycloakAdviser.class
})
@Configuration
public class SecureServletConfiguration {

}
