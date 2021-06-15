package com.bosch.inst.base.security.keycloak.adapter;

import static graphql.Assert.assertTrue;
import static org.springframework.test.util.AssertionErrors.assertEquals;

import com.bosch.inst.base.ExcludeLogging;
import com.bosch.inst.base.security.keycloak.auth.Credentials;
import com.bosch.inst.base.security.keycloak.exception.FailedRequestKeycloakException;
import com.bosch.inst.base.security.keycloak.exception.InvalidKeycloakResponseException;
import com.bosch.inst.base.security.keycloak.exception.InvalidTenantException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Getter
public abstract class BaseAdapter {

  public static final String REALM_HEADER_NAME = "x-realm";
  public static final String REALM_COOKIE_NAME = "TENANT";
  public static final String ACCESS_TOKEN_COOKIE_NAME = "TOKEN";
  public static final String REFRESH_TOKEN_COOKIE_NAME = "REFRESH_TOKEN";
  public static final String ROOT_REALM_NAME = "master";

  protected String realm;

  public BaseAdapter(String realm) {
    this.realm = realm;
  }

  /*
    Using a confidential service account
    * Create new client under your desired realm -> keycloak-admin
    * Select confidential client with only service account enabled
    * Select tab service account roles
      * type realm-management into client roles
      * add available roles that you need
     */
  public Keycloak getKeycloakInstance() {
    KeycloakDeployment deployment = getRealmInfo();
    String authServerUrl = deployment.getAuthServerBaseUrl();
    String clientId = deployment.getResourceName();
    String clientSecret = deployment.getResourceCredentials().get("secret").toString();

    Keycloak keycloak = KeycloakBuilder.builder()
        .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
        .serverUrl(authServerUrl)
        .realm(realm)
        .clientId(clientId)
        .clientSecret(clientSecret)
        .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(20).build())
        .build();
    return keycloak;
  }

  public Keycloak getKeycloakInstance(String accessToken) {
    KeycloakDeployment deployment = getRealmInfo();
    String authServerUrl = deployment.getAuthServerBaseUrl();

    Keycloak keycloak = KeycloakBuilder.builder()
        .serverUrl(authServerUrl)
        .realm(realm)
        .authorization(accessToken)
        .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(20).build())
        .build();
    return keycloak;
  }

  /*
  Create new client under your desired realm -> keycloak-admin

  * Select public client with only direct access grant enabled
  * Create new role, enable composite roles
  * type realm-managment into client roles under composite roles
      * add available roles that you need
      * Select a user and open role mappings tab
  * type keycloak-admin in client roles and add needed roles
   */
  public Keycloak getKeycloakInstance(String username,
      @ExcludeLogging String password) {
    KeycloakDeployment deployment = getRealmInfo();
    String authServerUrl = deployment.getAuthServerBaseUrl();

    Keycloak keycloak = KeycloakBuilder.builder()
        .grantType(OAuth2Constants.PASSWORD)
        .serverUrl(authServerUrl)
        .realm(realm)
        .username(username)
        .password(password)
        .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(20).build())
        .build();
    return keycloak;
  }

  public String getAccessToken(HttpServletRequest request) {
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
    KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
    return session.getTokenString();
  }

  public AccessTokenResponse getAccessToken(Credentials credentials) {
    KeycloakDeployment deployment = getRealmInfo();
    String authServerUrl = deployment.getAuthServerBaseUrl();

    // data for token request
    List<NameValuePair> params = new ArrayList<NameValuePair>();

    params.add(new BasicNameValuePair("grant_type", "password"));
//    params.add("client_id", deployment.getResourceName());
    params.add(new BasicNameValuePair("username", credentials.getUsername()));
    params.add(new BasicNameValuePair("password", credentials.getPassword()));

    CloseableHttpClient httpClient = HttpClients.custom().useSystemProperties()
        .build();

    try {
      HttpPost httpPost = new HttpPost(
          new URI(authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token"));

      httpPost.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
      httpPost.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
      httpPost
          .setHeader(HttpHeaders.AUTHORIZATION, httpBasicAuthorization(deployment.getResourceName(),
              deployment.getResourceCredentials().get("secret").toString()));

      httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
      HttpResponse response = httpClient.execute(httpPost);

      if (!HttpStatus.valueOf(response.getStatusLine().getStatusCode()).is2xxSuccessful()) {
        throw new InvalidKeycloakResponseException(EntityUtils.toString(response.getEntity()));
      }
      String responseStr = EntityUtils.toString(response.getEntity());

      ObjectMapper objectMapper = new ObjectMapper();

      AccessTokenResponse tokenResponse = objectMapper
          .readValue(responseStr, AccessTokenResponse.class);
      return tokenResponse;

    } catch (Exception e) {
      throw new InvalidKeycloakResponseException("Invalid Keycloak response!", e);
    } finally {
      if (null != httpClient) {
        try {
          httpClient.close();
        } catch (IOException e) {
          throw new InvalidKeycloakResponseException("Invalid Keycloak response!", e);
        }
      }
    }

//    // construct token request (including authorization for client(
//    RequestEntity<MultiValueMap<String, String>> authRequest = null;
//    try {
//      authRequest = RequestEntity
//          .post(new URI(authServerUrl +
//              "/realms/" + realm + "/protocol/openid-connect/token"))
//          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
//          .accept(MediaType.APPLICATION_JSON)
//          .header("Authorization",
//              httpBasicAuthorization(deployment.getResourceName(),
//                  deployment.getResourceCredentials().get("secret").toString()))
//          .body(params);
//    } catch (URISyntaxException e) {
//      throw new FailedRequestKeycloakException("Request keycloak failed", e);
//    }
//
//    // execute request and test for success
//    RestTemplate restTemplate = new RestTemplate();
//    ResponseEntity<String> response = restTemplate.exchange(authRequest, String.class);
//    assertEquals("", HttpStatus.OK, response.getStatusCode());
//    assertTrue(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON));

//    // extract access token (JWT) from response

//    ObjectMapper objectMapper = new ObjectMapper();
//
//    AccessTokenResponse tokenResponse = null;
//    try {
//      tokenResponse = objectMapper.readValue(responseStr, AccessTokenResponse.class);
//    } catch (JsonProcessingException e) {
//      throw new InvalidKeycloakResponseException("Invalid Keycloak response!", e);
//    }
//
//    return tokenResponse;
  }

  public static String getRefreshAccessToken(HttpServletRequest request) {
    return getCookie(request, REFRESH_TOKEN_COOKIE_NAME);
  }

  public AccessTokenResponse refreshAccessToken(String refreshToken) {
    KeycloakDeployment deployment = getRealmInfo();
    String authServerUrl = deployment.getAuthServerBaseUrl();

    // data for token request
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    params.add("grant_type", "refresh_token");
//    params.add("client_id", deployment.getResourceName());

    params.add("refresh_token", refreshToken);
    // construct token request (including authorization for client(
    RequestEntity<MultiValueMap<String, String>> authRequest = null;
    try {
      authRequest = RequestEntity
          .post(new URI(authServerUrl +
              "/realms/" + realm + "/protocol/openid-connect/token"))
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .accept(MediaType.APPLICATION_JSON)
          .header("Authorization",
              httpBasicAuthorization(deployment.getResourceName(),
                  deployment.getResourceCredentials().get("secret").toString()))
          .body(params);
    } catch (URISyntaxException e) {
      throw new FailedRequestKeycloakException("Request keycloak failed", e);
    }

    // execute request and test for success
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<String> response = restTemplate.exchange(authRequest, String.class);
    assertEquals("", HttpStatus.OK, response.getStatusCode());
    assertTrue(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON));

    // extract access token (JWT) from response

    ObjectMapper objectMapper = new ObjectMapper();

    AccessTokenResponse tokenResponse = null;
    try {
      tokenResponse = objectMapper
          .readValue(response.getBody(), AccessTokenResponse.class);
    } catch (JsonProcessingException e) {
      throw new InvalidKeycloakResponseException("Invalid Keycloak response!", e);
    }

    return tokenResponse;
  }

  public KeycloakDeployment getRealmInfo() {
    if (null == realm) {
      throw new InvalidTenantException("Realm is null!");
    }
    KeycloakDeployment keycloakDeployment;

    String path = "/keycloak/" + realm + ".json";
    InputStream configInputStream = getClass().getResourceAsStream(path);

    if (configInputStream == null) {
      throw new InvalidTenantException("Could not load Keycloak deployment info: " + path);
    } else {
      keycloakDeployment = KeycloakDeploymentBuilder.build(configInputStream);
    }

    return keycloakDeployment;
  }

  public RealmResource getRealmResource() {
    return getKeycloakInstance().realm(realm);
  }

  public static String getRealm(HttpServletRequest request) {
    String realm = null;
    if (null != getCookie(request, REALM_COOKIE_NAME)) {
      realm = getCookie(request, REALM_COOKIE_NAME);
    }
    if (null != request.getHeader(REALM_HEADER_NAME)) {
      realm = request.getHeader(REALM_HEADER_NAME);
    }
    return realm;
  }

  public static String getRealm(OIDCHttpFacade.Request request) {
    String tenant = null;
    if (null != request.getCookie(REALM_COOKIE_NAME)) {
      tenant = request.getCookie(REALM_COOKIE_NAME).getValue();
    }
    if (null != request.getHeader(REALM_HEADER_NAME)) {
      tenant = request.getHeader(REALM_HEADER_NAME);
    }
    return tenant;
  }

  public static String getCookie(HttpServletRequest request, String key) {
    Cookie[] cookies = request.getCookies();

    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(key)) {
          //do something
          //value can be retrieved using #cookie.getValue()
          return cookie.getValue();
        }
      }
    }

    return null;
  }

  private String httpBasicAuthorization(String username, String password) {
    return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
  }
}
