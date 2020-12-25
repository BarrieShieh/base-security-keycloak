package com.bosch.inst.base.security.keycloak;

import com.bosch.inst.base.security.keycloak.service.IKeycloakService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("/test")
public class TestController {

  @Autowired
  private IKeycloakService keycloakService;

  @Value("${keycloak.realm}")
  private String keycloakRealm;

  @RequestMapping(value = "/anonymous", method = RequestMethod.GET)
  public ResponseEntity<String> getAnonymous() {
    return ResponseEntity.ok("Hello Anonymous");
  }

  @RolesAllowed("user")
  @RequestMapping(value = "/user", method = {RequestMethod.GET, RequestMethod.POST})
  public ResponseEntity getUser(@RequestHeader String Authorization) {

    Keycloak keycloak = keycloakService.getKeycloakInstance();

    RealmResource r = keycloak.realm(keycloakRealm);
    Object t = r.roles().list().toString();

    UserRepresentation u = new UserRepresentation();
    u.setEmail("Barrie.XIE@cn.bosch.com");
    u.setUsername(UUID.randomUUID().toString());
    u.setEnabled(true);

    CredentialRepresentation credential = new CredentialRepresentation();
    credential.setType(CredentialRepresentation.PASSWORD);
    credential.setValue("test123");

    List<String> roles = new ArrayList<>();
    roles.add("app-admin");
    roles.add("app-user");
    roles.add("user");
    u.setCredentials(Arrays.asList(credential));
    Response response = r.users().create(u);

    log.info("Response |  Status: {} | Status Info: {}", response.getStatus(),
        response.getStatusInfo());
    String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

    UsersResource usersResource = r.users();
    UserResource userResource = usersResource.get(userId);
    RoleRepresentation demoRealmRole = r.roles()
        .get("app-admin").toRepresentation();
    // Assign realm-role role1 to user
    userResource.roles().realmLevel().add(Arrays.asList(demoRealmRole));

    userResource.sendVerifyEmail();

    System.err.println(response.getLocation().getPath());

    Object o = r.groups().groups();

    userResource.executeActionsEmail(Arrays.asList("UPDATE_PASSWORD"));

//    System.err.println(keycloak.tokenManager().getAccessTokenString());

    List<org.keycloak.representations.idm.UserRepresentation> list = keycloak
        .realm("spring-boot-quickstart").users().list();

    return ResponseEntity.ok(o);
  }

  @RolesAllowed("admin")
  @RequestMapping(value = "/admin", method = RequestMethod.GET)
  public ResponseEntity<String> getAdmin(@RequestHeader String Authorization) {
    return ResponseEntity.ok("Hello Admin");
  }

  @RolesAllowed({"admin", "user"})
  @RequestMapping(value = "/all-user", method = RequestMethod.GET)
  public ResponseEntity<String> getAllUser(@RequestHeader String Authorization) {
    return ResponseEntity.ok("Hello All User");
  }

}
