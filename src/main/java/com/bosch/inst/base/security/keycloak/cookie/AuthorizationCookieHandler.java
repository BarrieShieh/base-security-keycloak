package com.bosch.inst.base.security.keycloak.cookie;


import static com.bosch.inst.base.security.keycloak.service.impl.KeycloakService.TENANT_COOKIE_NAME;

import com.bosch.inst.base.security.keycloak.auth.CredentialsProperties;
import com.bosch.inst.base.security.keycloak.auth.HttpProperties;
import java.util.Arrays;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;

/**
 * Handler for working with the authorization cookie.<br> The authorization cookie is used to login
 * the user 'into' PLCS. It is initially provided by the {@link LoginController} at the {@code
 * /login} endpoint where the user logs in with its credentials. <br> It is renewed on each
 * successful request by the {@link RefreshLoginCookieFilter}.
 * <ul>
 * <li>The name of the token is defined by {@link AuthProperties.Cookie}</li>
 * <li>The value is the JWT received by IoT Permissions and stored in the Spring SecurityContext</li>
 * </ul>
 *
 * @see LoginController
 * @see RefreshLoginCookieFilter
 * @see SecurityConfiguration
 */
@Slf4j
@Configuration
@EnableConfigurationProperties({
    HttpProperties.class,
    CredentialsProperties.class,
})
public class AuthorizationCookieHandler {

  @Autowired
  private HttpProperties httpProperties;

  @Autowired
  private CredentialsProperties credentialsProperties;

  /**
   * Enriches the response with the authentication cookie that contains the JWT contained in the
   * given authentication.<br>
   *
   * @param response       The response to enrich with the authentication cookie
   * @param authentication The authentication that contains the JWT which should be set as cookie
   */
  public void setAuthenticationCookie(HttpServletRequest request,
      HttpServletResponse response, Authentication authentication) {
    log.debug("CookieHandler.setAuthenticationCookie");
    // For swagger-ui static files, when open the index page with TOKEN provided, the authentication will be null. to prevent error, check if authentication is null
    String pathInfo = request.getServletPath();
    if (null == authentication && httpProperties.getWhitelist().contains(pathInfo)) {
      return;
    }
    log.debug("Adding cookie with authorization token for user: {}", authentication.getPrincipal());
    KeycloakAuthenticationToken authenticationToken = (KeycloakAuthenticationToken) request
        .getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) authenticationToken.getPrincipal();

    String token = principal.getKeycloakSecurityContext().getIdTokenString();
    String domain = getCookieDomain(request.getServerName());
    response.addCookie(createLoginCookie(httpProperties.getCookie().getName(), token, domain));
    response.addHeader(credentialsProperties.getHeader(), token);
  }

  public void setTenantCookie(HttpServletRequest httpServletRequest, HttpServletResponse response,
      String tenant) {
    String domain = getCookieDomain(httpServletRequest.getServerName());
    response.addCookie(this.createLoginCookie(TENANT_COOKIE_NAME, tenant, domain));
  }

  public void deleteAuthenticationCookie(HttpServletRequest httpServletRequest,
      HttpServletResponse response) {
    String domain = getCookieDomain(httpServletRequest.getServerName());
    response.addCookie(deleteLoginCookie(httpProperties.getCookie().getName(), "value", domain));
  }

  public void deleteTenantCookie(HttpServletRequest httpServletRequest,
      HttpServletResponse response) {
    String domain = getCookieDomain(httpServletRequest.getServerName());
    response.addCookie(this.deleteLoginCookie(TENANT_COOKIE_NAME, "tenant", domain));
  }


  private Cookie deleteLoginCookie(String cookieKey, String cookieValue, String domain) {
    Cookie cookie = new Cookie(cookieKey, cookieValue);
    cookie.setHttpOnly(httpProperties.getCookie().isHttpOnly());
    cookie.setSecure(httpProperties.getCookie().isSecure());
    cookie.setPath(httpProperties.getCookie().getPath());
    cookie.setMaxAge(0);
    if (null != domain) {
      cookie.setDomain(domain);
    }
    return cookie;
  }

  private Cookie createLoginCookie(String cookieKey, String cookieValue, String domain) {
    Cookie cookie = new Cookie(cookieKey, cookieValue);
    cookie.setHttpOnly(httpProperties.getCookie().isHttpOnly());
    cookie.setSecure(httpProperties.getCookie().isSecure());
    cookie.setPath(httpProperties.getCookie().getPath());
    cookie.setMaxAge(httpProperties.getCookie().getMaxAge());
    if (null != domain) {
      cookie.setDomain(domain);
    }
//        log.info("New cookie: " + new Gson().toJson(cookie));
    return cookie;
  }

  /**
   * Returns the authentication cookie or null is none is contained in the given request.
   *
   * @param request The request to extract the authentication cookie from
   * @return The authentication cookie or null if none is found in the given request
   */
  public Cookie getAuthorizationCookie(HttpServletRequest request) {
    return this.getCookie(request, httpProperties.getCookie().getName());
  }

  public Cookie getTenantCookie(HttpServletRequest request) {
    return this.getCookie(request, TENANT_COOKIE_NAME);
  }

  private Cookie getCookie(HttpServletRequest request, String cookieName) {
    Cookie cookie = null;
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      cookie = Arrays.stream(cookies)
          .filter(c -> c.getName().equals(cookieName))
          .findFirst()
          .orElse(null);
    }
    return cookie;
  }

  public String getCookieDomain(String serverName) {
    log.debug("Server name: " + serverName);
    if (serverName != null && !serverName.isEmpty()) {
      String[] paths = serverName.split("\\.");
      if (httpProperties.getCookie().isSetRootDomain() && !ipCheck(serverName)
          && paths.length >= 2) {
        return paths[paths.length - 2] + "." + paths[paths.length - 1];
      }
    }
    return null;
  }

  public boolean ipCheck(String text) {
    if (text != null && !text.isEmpty()) {
      String regex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."
          + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
          + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
          + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
      return text.matches(regex);
    }
    return false;
  }
}
