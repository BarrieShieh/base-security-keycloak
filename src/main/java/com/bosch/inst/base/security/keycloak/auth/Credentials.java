package com.bosch.inst.base.security.keycloak.auth;

import lombok.Data;
import lombok.NonNull;

@Data
public class Credentials {

  private String tenant;
  @NonNull
  private String username;
  @NonNull
  private String password;
}
