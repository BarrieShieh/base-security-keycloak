package com.bosch.inst.base.security.keycloak.login;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

import com.bosch.inst.base.security.keycloak.adapter.BaseAdapter;
import com.bosch.inst.base.security.keycloak.adapter.UserAdapter;
import com.bosch.inst.base.security.keycloak.auth.Credentials;
import com.bosch.inst.base.security.keycloak.cookie.AuthorizationCookieHandler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Upon a login request via BasicAuth the servlet filters in im-spring-security will authenticate
 * the user, retrieve the AuthorizationToken and set this token in the Spring SecurityContext.<br>
 * This controller adds the AuthorizationToken as Cookie for the client.<br> There's no logout
 * endpoint since this is provided and handled by Spring Security.
 */
@Slf4j
@RestController
@Tag(description = "Manage authentication", name = "Login")
@Import({
    AuthorizationCookieHandler.class
})
public class LoginController {

  @Autowired
  private HttpServletRequest request;

  @Autowired
  private HttpServletResponse response;


  @Autowired
  private AuthorizationCookieHandler authorizationCookieHandler;

  @Autowired
  private LoginAdapter loginAdapter;

  @Value("${identity-provider.config.path}")
  private String configPath;

  public static final String LOGIN_PATH = "/login";

//  @Operation(description = "Refresh credentials in cookies")
//  @RequestMapping(value = LOGIN_PATH, method = GET)
//  public void getLogin(HttpServletRequest request, HttpServletResponse response) {
//    // If we've come so far, the user already has been authenticated via BasicAuth and retrieved an AuthToken
//    // which is available via the Spring SecurityContext
//    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//    authorizationCookieHandler.setAuthenticationCookie(request, response, authentication);
//  }

  @SneakyThrows
  @RequestMapping(value = LOGIN_PATH, method = POST)
  @Operation(description = "Login the system, and put credentials into cookies")
  public ResponseEntity login(
      @Parameter(description = "Realm")
      @RequestHeader(value = BaseAdapter.REALM_HEADER_NAME) String realm,
      @Valid
      @Parameter(description = "User provided credentials")
      @RequestBody Credentials credentials) {
    UserAdapter userAdapter = new UserAdapter(realm, configPath);
    AccessTokenResponse tokenResponse = userAdapter.getAccessToken(credentials);

    loginAdapter.before(realm, credentials, tokenResponse);
    authorizationCookieHandler.setAuthenticationCookie(tokenResponse);
    authorizationCookieHandler.setRealmCookie(realm);
    loginAdapter.after(realm, credentials, tokenResponse);
    return new ResponseEntity<>(tokenResponse, HttpStatus.OK);
//    TenantUserPasswordToken token = new TenantUserPasswordToken(credentials.getUsername(),
//        credentials.getPassword(), credentials.getTenant());
//    Authentication authentication = tokenSessionManager
//        .getTenantUserPasswordTokenAuthorization(token);
////        Authentication authentication = authenticationProviderService.authenticate(token);
//
//    authorizationCookieHandler.setAuthenticationCookie(request, response, authentication);
//
//    if (StringUtils.hasText(credentials.getTenant())) {
//      authorizationCookieHandler.setTenantCookie(request, response, credentials.getTenant());
//    } else {
//      authorizationCookieHandler.setTenantCookie(request, response, imConfig.getTenantId());
//    }
  }
}
