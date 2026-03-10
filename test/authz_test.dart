import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';

  test('creates authorization instance', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init();

    final authz = KeycloakAuthorization(keycloak);
    expect(authz, isNotNull);
    expect(authz.rpt, isNull);
  });

  test('authorize throws when not authenticated', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init();

    final authz = KeycloakAuthorization(keycloak);

    expect(
      () => authz.authorize(AuthorizationRequest(ticket: 'test-ticket')),
      throwsException,
    );
  });

  test('entitlement throws when not authenticated', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init();

    final authz = KeycloakAuthorization(keycloak);

    expect(
      () => authz.entitlement('resource-server'),
      throwsException,
    );
  });

  test('creates authorization request with permissions', () {
    final request = AuthorizationRequest(
      permissions: [
        ResourcePermission(id: 'resource-1', scopes: ['view', 'edit']),
        ResourcePermission(id: 'resource-2'),
      ],
      ticket: 'test-ticket',
      incrementalAuthorization: true,
      metadata: AuthorizationRequestMetadata(
        responseIncludeResourceName: true,
        responsePermissionsLimit: 10,
      ),
    );

    expect(request.permissions, hasLength(2));
    expect(request.permissions![0].id, 'resource-1');
    expect(request.permissions![0].scopes, ['view', 'edit']);
    expect(request.permissions![1].id, 'resource-2');
    expect(request.permissions![1].scopes, isNull);
    expect(request.ticket, 'test-ticket');
    expect(request.incrementalAuthorization, isTrue);
    expect(request.metadata!.responseIncludeResourceName, isTrue);
    expect(request.metadata!.responsePermissionsLimit, 10);
  });
}
