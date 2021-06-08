package com.bosch.inst.base.security.keycloak.login;

import com.bosch.inst.base.security.keycloak.auth.Credentials;
import org.keycloak.representations.AccessTokenResponse;

public interface LoginAdapter {

  void before(String tenant, Credentials credentials, AccessTokenResponse tokenResponse);

  void after(String tenant, Credentials credentials, AccessTokenResponse tokenResponse);
}
