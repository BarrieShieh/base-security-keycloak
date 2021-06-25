package com.github.base.security.keycloak.auth;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Component
@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class CredentialsProperties {

  private String header = "X-Access-Token";

  private String secret = "MyJwtSecret";

  private int expire = 7200000;
}
