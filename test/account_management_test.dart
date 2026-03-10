import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';

  test('accountManagement throws when not initialized', () {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);

    expect(
      () => keycloak.accountManagement(),
      throwsA(isA<StateError>()),
    );
  });

  test('accountManagement succeeds after initialization', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await keycloak.init();

    // Should not throw (default adapter is a no-op)
    await keycloak.accountManagement();
  });
}
