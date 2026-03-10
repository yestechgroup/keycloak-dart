import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

import 'token_test.dart' show createTestToken;

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';

  test('initializes with pre-set token and refresh token', () async {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final tokenStr = createTestToken({
      'sub': 'init-user',
      'exp': now + 300,
      'iat': now,
    });
    final refreshTokenStr = createTestToken({
      'exp': now + 1800,
      'iat': now,
    });

    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);

    final authenticated = await keycloak.init(KeycloakInitOptions(
      token: tokenStr,
      refreshToken: refreshTokenStr,
    ),);

    expect(authenticated, isTrue);
    expect(keycloak.authenticated, isTrue);
    expect(keycloak.subject, 'init-user');
    expect(keycloak.token, tokenStr);
    expect(keycloak.refreshToken, refreshTokenStr);
  });

  test('initializes with pre-set token, refresh token, and ID token',
      () async {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final tokenStr = createTestToken({
      'sub': 'init-user',
      'exp': now + 300,
      'iat': now,
    });
    final refreshTokenStr = createTestToken({
      'exp': now + 1800,
      'iat': now,
    });
    final idTokenStr = createTestToken({
      'sub': 'init-user',
      'exp': now + 300,
      'iat': now,
      'nonce': 'init-nonce',
    });

    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);

    await keycloak.init(KeycloakInitOptions(
      token: tokenStr,
      refreshToken: refreshTokenStr,
      idToken: idTokenStr,
    ),);

    expect(keycloak.idToken, isNotNull);
    expect(keycloak.idTokenParsed, isNotNull);
    expect(keycloak.idTokenParsed!.nonce, 'init-nonce');
  });

  test('initializes with timeSkew option', () async {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final tokenStr = createTestToken({
      'sub': 'init-user',
      'exp': now + 300,
      'iat': now,
    });
    final refreshTokenStr = createTestToken({
      'exp': now + 1800,
      'iat': now,
    });

    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);

    await keycloak.init(KeycloakInitOptions(
      token: tokenStr,
      refreshToken: refreshTokenStr,
      timeSkew: 10,
    ),);

    expect(keycloak.authenticated, isTrue);
    expect(keycloak.timeSkew, isNotNull);
  });

  test('does not authenticate without initial tokens', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);

    final authenticated = await keycloak.init();

    expect(authenticated, isFalse);
    expect(keycloak.authenticated, isFalse);
  });
}
