package com.bosch.inst.base.security.keycloak;

import com.bosch.inst.base.security.keycloak.login.LoginController;
import com.bosch.inst.base.security.keycloak.service.impl.KeycloakService;
import com.bosch.inst.base.security.keycloak.servlet.AuditorProvider;
import com.bosch.inst.base.security.keycloak.servlet.SecurityConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Import({
    SecurityConfiguration.class,
    AuditorProvider.class,
    KeycloakService.class,
    LoginController.class
})
@Configuration
public class SecureServletConfiguration {

}
