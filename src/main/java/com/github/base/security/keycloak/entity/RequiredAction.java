package com.github.base.security.keycloak.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RequiredAction {
  CONFIGURE_TOTP("CONFIGURE_TOTP"),
  VERIFY_EMAIL("VERIFY_EMAIL"),
  UPDATE_PASSWORD("UPDATE_PASSWORD"),
  UPDATE_PROFILE("UPDATE_PROFILE"),
  UPDATE_USER_LOCALE("update_user_locale");

  private final String action;
}
