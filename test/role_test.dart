import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

import 'token_test.dart' show createTestToken;

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  late Keycloak keycloak;

  setUp(() async {
    keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 300,
      'iat': now,
      'realm_access': {
        'roles': ['user', 'admin'],
      },
      'resource_access': {
        clientId: {
          'roles': ['view', 'edit'],
        },
        'other-client': {
          'roles': ['manage'],
        },
      },
    });
    final refreshTokenStr = createTestToken({
      'exp': now + 1800,
      'iat': now,
    });
    keycloak.setToken(
      token,
      refreshTokenStr,
      null,
      DateTime.now().millisecondsSinceEpoch,
    );
  });

  test('hasRealmRole returns true for existing realm role', () {
    expect(keycloak.hasRealmRole('user'), isTrue);
    expect(keycloak.hasRealmRole('admin'), isTrue);
  });

  test('hasRealmRole returns false for non-existing realm role', () {
    expect(keycloak.hasRealmRole('superadmin'), isFalse);
  });

  test('hasResourceRole returns true for existing resource role', () {
    expect(keycloak.hasResourceRole('view'), isTrue);
    expect(keycloak.hasResourceRole('edit'), isTrue);
  });

  test('hasResourceRole returns false for non-existing resource role', () {
    expect(keycloak.hasResourceRole('delete'), isFalse);
  });

  test('hasResourceRole checks specific resource', () {
    expect(keycloak.hasResourceRole('manage', 'other-client'), isTrue);
    expect(keycloak.hasResourceRole('manage', clientId), isFalse);
  });

  test('hasRealmRole returns false when not authenticated', () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await kc.init();
    expect(kc.hasRealmRole('user'), isFalse);
  });

  test('hasResourceRole returns false when not authenticated', () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await kc.init();
    expect(kc.hasResourceRole('view'), isFalse);
  });
}
