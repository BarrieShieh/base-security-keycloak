package com.bosch.inst.base.security.keycloak.auth;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class HttpCookie {

  private String name = "TOKEN";

  private boolean setRootDomain = true;

  private boolean httpOnly = true;

  private boolean secure = true;

  private String path = "/";

  private int maxAge = 3600;


}
