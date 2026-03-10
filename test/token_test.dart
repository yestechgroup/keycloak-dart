import 'dart:convert';

import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

/// Helper to create a JWT token string from claims.
String createTestToken(Map<String, dynamic> claims) {
  final header = base64Url.encode(utf8.encode('{"alg":"RS256","typ":"JWT"}'));
  final payload = base64Url.encode(utf8.encode(jsonEncode(claims)));
  final signature = base64Url.encode(utf8.encode('test-signature'));
  // Remove padding
  return '${header.replaceAll('=', '')}.${payload.replaceAll('=', '')}.${signature.replaceAll('=', '')}';
}

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  test('decodes a valid JWT token', () {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'iss': '$authServerUrl/realms/$realm',
      'aud': clientId,
      'exp': now + 300,
      'iat': now,
      'nonce': 'test-nonce',
      'realm_access': {
        'roles': ['user', 'admin'],
      },
      'resource_access': {
        clientId: {
          'roles': ['view', 'edit'],
        },
      },
    });

    final parsed = decodeToken(token);
    expect(parsed.sub, 'user-123');
    expect(parsed.iss, '$authServerUrl/realms/$realm');
    expect(parsed.exp, now + 300);
    expect(parsed.iat, now);
    expect(parsed.nonce, 'test-nonce');
    expect(parsed.realmAccess?.roles, ['user', 'admin']);
    expect(parsed.resourceAccess?[clientId]?.roles, ['view', 'edit']);
  });

  test('throws on invalid token', () {
    expect(() => decodeToken('invalid'), throwsException);
  });

  test('refreshes a token fails when no refresh token available', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    expect(
      () => keycloak.updateToken(9999),
      throwsA(isA<StateError>().having(
        (e) => e.message,
        'message',
        contains('no refresh token available'),
      ),),
    );
  });

  test('isTokenExpired returns true when token is expired', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 35,
      'iat': now,
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

    // Token expires in 35s, asking for 30s validity -> not expired
    expect(keycloak.isTokenExpired(30), isFalse);

    // Simulate time skew (as if 5 seconds have passed)
    keycloak.timeSkew = keycloak.timeSkew! - 5;

    // Now token expires in ~30s, asking for 30s validity -> expired
    expect(keycloak.isTokenExpired(30), isTrue);
  });

  test('isTokenExpired throws when not authenticated', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    expect(() => keycloak.isTokenExpired(), throwsA(isA<StateError>()));
  });
}
