package com.bosch.inst.base.security.keycloak;

import com.bosch.inst.base.security.keycloak.service.impl.KeycloakService;
import com.bosch.inst.base.security.keycloak.servlet.SecurityConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Import({
    SecurityConfiguration.class,
    KeycloakService.class,
    TestController.class
})
@Configuration
public class SecureServletConfiguration {

}
