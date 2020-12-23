package com.bosch.inst.base.security.keycloak.service.impl;

import com.bosch.inst.base.security.keycloak.service.IKeycloakService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class KeycloakService implements IKeycloakService {

  @Autowired
  private HttpServletRequest request;

  @Value("${keycloak.realm}")
  private String keycloakRealm;

  @Value("${keycloak.auth-server-url}")
  private String keycloakAuthServerUrl;

  @Value("${keycloak.resource}")
  private String keycloakResource;

  @Value("${keycloak.credentials.secret}")
  private String keycloakCredentialsSecret;

  @Override
  public Keycloak getKeycloakInstance() {
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
    KeycloakSecurityContext session = principal.getKeycloakSecurityContext();

    Keycloak keycloak = KeycloakBuilder.builder()
        .serverUrl(keycloakAuthServerUrl)
        .realm(keycloakRealm)
        .authorization(session.getTokenString())
        .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(20).build())
        .build();
    return keycloak;
  }

  @Override
  public UserRepresentation selfRegistration(String realm, String username, String firstName,
      String lastName,
      String email,
      String password, List<String> roles, List<String> groupIds) {

    Keycloak keycloakInstance = getKeycloakInstance();
    UserRepresentation u = new UserRepresentation();
    u.setEmail(email);
    u.setUsername(username);
    u.setFirstName(firstName);
    u.setLastName(lastName);
    u.setEnabled(true);

    CredentialRepresentation credential = new CredentialRepresentation();
    credential.setType(CredentialRepresentation.PASSWORD);
    credential.setValue(password);

    u.setCredentials(Arrays.asList(credential));
    Response response = keycloakInstance.realm(realm).users().create(u);
    log.info("Response |  Status: {} | Status Info: {}", response.getStatus(),
        response.getStatusInfo());
    String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
    List<RoleRepresentation> roleRepresentations = new ArrayList<>();

    for (String role : roles) {
      roleRepresentations.add(keycloakInstance.realm(realm).roles().get(role).toRepresentation());
    }

    setRoles(realm, userId, roleRepresentations);
    setGroups(realm, userId, groupIds);
    sendVerifyEmail(realm, userId);

    return keycloakInstance.realm(realm).users().get(userId).toRepresentation();
  }

  @Override
  public void sendVerifyEmail(String realm, String userId) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);

    userResource.sendVerifyEmail();
  }

  @Override
  public void resetPasswordEmail(String realm, String userId) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);

    userResource.executeActionsEmail(Arrays.asList("UPDATE_PASSWORD"));
  }

  @Override
  public void setRoles(String realm, String userId, List<RoleRepresentation> roles) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);
    // Assign realm-role role1 to user
    userResource.roles().realmLevel().add(roles);
  }

  @Override
  public void setGroups(String realm, String userId, List<String> groupIds) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);

    for (String groupId : groupIds) {
      userResource.joinGroup(groupId);
    }
  }

  @Override
  public UserRepresentation getUserById(String realm, String userId) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).toRepresentation();
  }

  @Override
  public List<UserRepresentation> getUserByUsername(String realm, String username) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().search(username);
  }

  @Override
  public List<UserRepresentation> getUsers(String realm) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().list();
  }

  @Override
  public GroupRepresentation getGroupById(String realm, String groupId) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.groups().group(groupId).toRepresentation();
  }

  @Override
  public List<GroupRepresentation> getGroups(String realm) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.groups().groups();
  }

  @Override
  public List<UserRepresentation> getGroupMembers(String realm, String groupId) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    return realmResource.groups().group(groupId).members();
  }

  @Override
  public RoleRepresentation getRoleByName(String realm, String roleName) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.roles().get(roleName).toRepresentation();
  }

  @Override
  public List<RoleRepresentation> getRoles(String realm) {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.roles().list();
  }
}
