package com.bosch.inst.base.security.keycloak.auth;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "http")
public class HttpProperties {

  private boolean enable = true;
  private HttpCookie cookie = new HttpCookie();
  private List<String> whitelist = new ArrayList<>();
}
