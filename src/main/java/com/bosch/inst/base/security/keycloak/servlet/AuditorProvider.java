package com.bosch.inst.base.security.keycloak.servlet;

import com.bosch.inst.base.domain.IAuditorProvider;
import java.util.Optional;
import org.keycloak.KeycloakPrincipal;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;

@Configuration
public class AuditorProvider implements IAuditorProvider {

  @Override
  public Optional getAuditorPrincipal(Object principal) {
    if (principal.getClass().isAssignableFrom(User.class)) {
      return Optional.ofNullable(((User) principal).getUsername());
    } else if (principal.getClass().isAssignableFrom(String.class)) {
      return Optional.ofNullable((String) principal);
    } else if (principal.getClass().isAssignableFrom(KeycloakPrincipal.class)) {
      return Optional.ofNullable(((KeycloakPrincipal) principal).getName());
    } else {
      return null;
    }
  }
}
