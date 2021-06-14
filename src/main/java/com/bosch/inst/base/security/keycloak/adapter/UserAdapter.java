package com.bosch.inst.base.security.keycloak.adapter;

import com.bosch.inst.base.security.keycloak.entity.RequiredAction;
import com.bosch.inst.base.security.keycloak.exception.InvalidKeycloakResponseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.HttpStatus;

@Slf4j
@Getter
public class UserAdapter extends BaseAdapter {

  private RealmResource realmResource;

  public UserAdapter(String realm) {
    super(realm);
    this.realmResource = super.getRealmResource();
  }

  public UserRepresentation getLoginUser(HttpServletRequest request) {

    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
    String userId = principal.getName();
    UserRepresentation user = realmResource.users().get(userId).toRepresentation();
    List<String> realmRoles = getRealmLevelRolesByUserId(userId).stream()
        .map(r -> r.getName()).collect(
            Collectors.toList());
    user.setRealmRoles(realmRoles);

    Map<String, List<RoleRepresentation>> roles = this
        .getClientLevelRolesByUserId(userId);

    Map<String, List<String>> clientsRoles = new HashMap<>();
    for (Map.Entry<String, List<RoleRepresentation>> entry : roles.entrySet()) {
      String mapKey = entry.getKey();
      List<String> mapValue = entry.getValue().stream().map(r -> r.getName())
          .collect(Collectors.toList());
      clientsRoles.put(mapKey, mapValue);
    }

    user.setClientRoles(clientsRoles);
    return user;
  }

  public List<String> getLoginUserRoles(HttpServletRequest request) {
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
    KeycloakDeployment deployment = getRealmInfo();
    String clientId = deployment.getResourceName();
    AccessToken.Access resourceAccess = principal.getKeycloakSecurityContext().getToken()
        .getResourceAccess(clientId);
    Set<String> set = resourceAccess == null ? new HashSet<>() : resourceAccess.getRoles();
    return new ArrayList<>(set);
  }

  public UserRepresentation selfRegistration(UserRepresentation user) {
    user.setEnabled(true);

    Response response = realmResource.users().create(user);
    log.info("Response |  Status: {} | Status Info: {}", response.getStatus(),
        response.getStatusInfo());
    if (!HttpStatus.valueOf(response.getStatus()).is2xxSuccessful()) {
      throw new InvalidKeycloakResponseException(response.getStatusInfo().toString());
    }

    String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
    setRealmLevelRoles(userId, user.getRealmRoles());
    setClientLevelRoles(userId, user.getClientRoles());
    setGroups(userId, user.getGroups());
    if (user.getRequiredActions().contains(RequiredAction.VERIFY_EMAIL.toString())) {
      sendVerifyEmail(userId);
    }

    return realmResource.users().get(userId).toRepresentation();
  }


  public void sendVerifyEmail(String userId) {
    UserResource userResource = realmResource.users().get(userId);
    userResource.sendVerifyEmail();
  }


  public void resetPasswordEmail(String username) {
    List<UserRepresentation> users = realmResource.users().search(username);
    if (users.size() == 1) {
      realmResource.users().get(users.get(0).getId())
          .executeActionsEmail(Arrays.asList("UPDATE_PASSWORD"));
    }
  }


  public void setRealmLevelRoles(String userId,
      List<String> realmRoles) {
    if (null == userId || null == realmRoles || realmRoles.size() == 0) {
      return;
    }
    List<RoleRepresentation> roleRepresentations = new ArrayList<>();
    for (String role : realmRoles) {
      roleRepresentations.add(realmResource.roles().get(role).toRepresentation());
    }

    UserResource userResource = realmResource.users().get(userId);
    // Assign realm-role role1 to user
    userResource.roles().realmLevel().add(roleRepresentations);
  }


  public void setClientLevelRoles(String userId,
      Map<String, List<String>> clientRoles) {
    if (null == userId || null == clientRoles || clientRoles.size() == 0) {
      return;
    }
    UserResource userResource = realmResource.users().get(userId);
    // Assign client-role role1 to user

    for (Map.Entry<String, List<String>> entry : clientRoles.entrySet()) {
      String clientId = entry.getKey();
      List<ClientRepresentation> clients = realmResource.clients()
          .findByClientId(entry.getKey());
      if (clients.size() != 1) {
        throw new InvalidKeycloakResponseException("Client ID '" + clientId + "' not found");
      }
      String clientUUID = clients.stream().findFirst().get().getId();
      List<String> roles = entry.getValue();
      if (null == clientId || null == roles || roles.size() == 0) {
        continue;
      }

      userResource.roles().clientLevel(clientUUID).add(
          roles.stream().map(
              r -> realmResource.clients().get(clientUUID).roles().get(r)
                  .toRepresentation())
              .collect(
                  Collectors.toList()));
    }
  }

  public List<RoleRepresentation> getRealmLevelRolesByUserId(
      String userId) {
    return realmResource.users().get(userId).roles().realmLevel().listAll();
  }

  public Map<String, List<RoleRepresentation>> getClientLevelRolesByUserId(
      String userId) {
    List<ClientRepresentation> clients = realmResource.clients().findAll();

    Map<String, List<RoleRepresentation>> map = new HashMap<>();

    for (ClientRepresentation client : clients) {
      List<RoleRepresentation> roles = realmResource.users().get(userId).roles()
          .clientLevel(client.getId()).listAll();
      map.put(client.getClientId(), roles);
    }

    return map;
  }


  public void setGroups(String userId, List<String> groupIds) {
    if (null == userId || null == groupIds) {
      return;
    }
    UserResource userResource = realmResource.users().get(userId);
    for (String groupId : groupIds) {
      userResource.joinGroup(groupId);
    }
  }


  public List<UserRepresentation> searchForUserByAttribute(
      String attributeName,
      String attributeValue
  ) {

    return realmResource.users().list().stream()
        .filter(r -> null != r.getAttributes() && r.getAttributes().containsKey(attributeName) && r
            .getAttributes().get(attributeName)
            .contains(attributeValue)).collect(
            Collectors.toList());
  }
}
