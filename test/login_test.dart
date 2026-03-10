import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

import 'token_test.dart' show createTestToken;

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  test('initializes with default configuration', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    final authenticated = await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
    ));

    expect(authenticated, isFalse);
    expect(keycloak.authenticated, isFalse);
  });

  test('sets authenticated state when token is provided', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 300,
      'iat': now,
      'sid': 'session-123',
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

    expect(keycloak.authenticated, isTrue);
    expect(keycloak.subject, 'user-123');
    expect(keycloak.sessionId, 'session-123');
  });

  test('clears token and sets unauthenticated state', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 300,
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

    expect(keycloak.authenticated, isTrue);

    keycloak.clearToken();

    expect(keycloak.authenticated, isFalse);
    expect(keycloak.token, isNull);
    expect(keycloak.refreshToken, isNull);
    expect(keycloak.subject, isNull);
  });

  test('calls onAuthLogout when clearing token', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 300,
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

    var logoutCalled = false;
    keycloak.onAuthLogout = () {
      logoutCalled = true;
    };

    keycloak.clearToken();
    expect(logoutCalled, isTrue);
  });

  test('does not call onAuthLogout when already cleared', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    var logoutCallCount = 0;
    keycloak.onAuthLogout = () {
      logoutCallCount++;
    };

    // No token set, clearToken should be a no-op
    keycloak.clearToken();
    expect(logoutCallCount, 0);
  });

  test('initializes without PKCE', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      enablePkce: false,
    ));

    final loginUrlString = await keycloak.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(loginUrl.queryParameters.containsKey('code_challenge'), isFalse);
    expect(
      loginUrl.queryParameters.containsKey('code_challenge_method'),
      isFalse,
    );
  });

  test('initializes with POST logout method', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      logoutMethod: 'POST',
    ));

    expect(keycloak.logoutMethod, 'POST');
  });

  test('configures with generic OpenID provider metadata', () async {
    final keycloak = Keycloak(GenericOidcConfig(
      clientId: clientId,
      oidcProvider: OpenIdProviderMetadata(
        authorizationEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/auth',
        tokenEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/token',
        endSessionEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/logout',
        userinfoEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/userinfo',
      ),
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    expect(keycloak.clientId, clientId);
    expect(keycloak.authenticated, isFalse);
    expect(keycloak.endpoints, isNotNull);
  });

  test('sets login-required flag', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      onLoad: KeycloakOnLoad.loginRequired,
    ));

    expect(keycloak.loginRequired, isTrue);
  });

  test('sets ID token when provided', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 300,
      'iat': now,
    });
    final refreshTokenStr = createTestToken({
      'exp': now + 1800,
      'iat': now,
    });
    final idTokenStr = createTestToken({
      'sub': 'user-123',
      'exp': now + 300,
      'iat': now,
      'nonce': 'test-nonce',
    });

    keycloak.setToken(
      token,
      refreshTokenStr,
      idTokenStr,
      DateTime.now().millisecondsSinceEpoch,
    );

    expect(keycloak.idToken, isNotNull);
    expect(keycloak.idTokenParsed, isNotNull);
    expect(keycloak.idTokenParsed!.nonce, 'test-nonce');
  });
}
