package com.github.base.security.keycloak.auth;

import lombok.Data;
import lombok.NonNull;

@Data
public class Credentials {
  @NonNull
  private String username;
  @NonNull
  private String password;
}
