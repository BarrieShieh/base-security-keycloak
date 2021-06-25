package com.github.base.security.keycloak.login;

import com.github.base.security.keycloak.auth.Credentials;
import org.keycloak.representations.AccessTokenResponse;

public interface LoginAdapter {

  void before(String tenant, Credentials credentials, AccessTokenResponse tokenResponse);

  void after(String tenant, Credentials credentials, AccessTokenResponse tokenResponse);
}
