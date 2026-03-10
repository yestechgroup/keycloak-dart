import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

import 'token_test.dart' show createTestToken;

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  group('parseCallbackParams', () {
    test('extracts OAuth params from query string', () {
      final result = Keycloak.parseCallbackParams(
        'code=abc123&state=xyz789&session_state=sess1',
        ['code', 'state', 'session_state'],
      );

      expect(result.oauthParams['code'], 'abc123');
      expect(result.oauthParams['state'], 'xyz789');
      expect(result.oauthParams['session_state'], 'sess1');
      expect(result.paramsString, isEmpty);
    });

    test('preserves non-OAuth params', () {
      final result = Keycloak.parseCallbackParams(
        'code=abc123&state=xyz789&custom=value&other=data',
        ['code', 'state'],
      );

      expect(result.oauthParams['code'], 'abc123');
      expect(result.oauthParams['state'], 'xyz789');
      expect(result.paramsString, contains('custom=value'));
      expect(result.paramsString, contains('other=data'));
    });

    test('handles empty params string', () {
      final result = Keycloak.parseCallbackParams('', ['code', 'state']);

      expect(result.oauthParams, isEmpty);
    });

    test('extracts error params', () {
      final result = Keycloak.parseCallbackParams(
        'error=access_denied&error_description=User+denied&state=xyz',
        ['error', 'error_description', 'state'],
      );

      expect(result.oauthParams['error'], 'access_denied');
      expect(result.oauthParams['error_description'], 'User denied');
      expect(result.oauthParams['state'], 'xyz');
    });
  });

  group('parseCallbackUrl', () {
    test('parses standard flow callback with fragment response mode',
        () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      final result = keycloak.parseCallbackUrl(
        '$appUrl#code=auth_code&state=abc123&session_state=sess1',
      );

      expect(result, isNotNull);
      expect(result!.code, 'auth_code');
      expect(result.state, 'abc123');
      expect(result.sessionState, 'sess1');
    });

    test('parses standard flow callback with query response mode', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
        responseMode: KeycloakResponseMode.query,
      ),);

      final result = keycloak.parseCallbackUrl(
        '$appUrl?code=auth_code&state=abc123&session_state=sess1',
      );

      expect(result, isNotNull);
      expect(result!.code, 'auth_code');
      expect(result.state, 'abc123');
    });

    test('parses implicit flow callback', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
        flow: KeycloakFlow.implicit,
      ),);

      final result = keycloak.parseCallbackUrl(
        '$appUrl#access_token=token123&state=abc123&token_type=Bearer&expires_in=300',
      );

      expect(result, isNotNull);
      expect(result!.accessToken, 'token123');
      expect(result.state, 'abc123');
      expect(result.tokenType, 'Bearer');
    });

    test('parses error callback', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      final result = keycloak.parseCallbackUrl(
        '$appUrl#error=access_denied&error_description=Denied&state=abc123',
      );

      expect(result, isNotNull);
      expect(result!.error, 'access_denied');
      expect(result.errorDescription, 'Denied');
    });

    test('returns null when no valid OAuth params present', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      final result = keycloak.parseCallbackUrl(appUrl);
      expect(result, isNull);
    });

    test('returns null when state is missing', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      final result = keycloak.parseCallbackUrl(
        '$appUrl#code=auth_code',
      );
      expect(result, isNull);
    });

    test('parses kc_action_status', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      final result = keycloak.parseCallbackUrl(
        '$appUrl#code=auth_code&state=abc123&kc_action_status=success&kc_action=UPDATE_PASSWORD',
      );

      expect(result, isNotNull);
      expect(result!.kcActionStatus, 'success');
      expect(result.kcAction, 'UPDATE_PASSWORD');
    });
  });

  group('parseCallback', () {
    test('validates callback against stored state', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
        enablePkce: false,
      ),);

      // Create a login URL to store state
      final loginUrl = await keycloak.createLoginUrl();
      final loginUri = Uri.parse(loginUrl);
      final state = loginUri.queryParameters['state']!;

      // Simulate callback with that state
      final result = keycloak.parseCallback(
        '$appUrl#code=auth_code&state=$state&session_state=sess1',
      );

      expect(result, isNotNull);
      expect(result!.valid, isTrue);
      expect(result.redirectUri, appUrl);
    });

    test('returns invalid callback for unknown state', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      final result = keycloak.parseCallback(
        '$appUrl#code=auth_code&state=unknown_state&session_state=sess1',
      );

      expect(result, isNotNull);
      expect(result!.valid, isFalse);
    });
  });

  group('processCallback', () {
    test('fires onActionUpdate for kc_action_status', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
        flow: KeycloakFlow.implicit,
      ),);

      String? actionStatus;
      String? actionName;
      keycloak.onActionUpdate = (status, action) {
        actionStatus = status;
        actionName = action;
      };

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final tokenStr = createTestToken({
        'sub': 'user-123',
        'exp': now + 300,
        'iat': now,
      });

      final oauth = OAuthCallbackParams(
        accessToken: tokenStr,
        state: 'test-state',
        kcActionStatus: 'success',
        kcAction: 'UPDATE_PASSWORD',
        valid: true,
      );

      await keycloak.processCallback(oauth);
      expect(actionStatus, 'success');
      expect(actionName, 'UPDATE_PASSWORD');
    });

    test('throws on error callback (not prompt=none)', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      var authErrorCalled = false;
      keycloak.onAuthError = (error) {
        authErrorCalled = true;
      };

      const oauth = OAuthCallbackParams(
        error: 'access_denied',
        errorDescription: 'User denied access',
        state: 'test-state',
        valid: true,
      );

      await expectLater(
        keycloak.processCallback(oauth),
        throwsA(isA<KeycloakError>()),
      );
      expect(authErrorCalled, isTrue);
    });

    test('silently handles error with prompt=none', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
      ),);

      const oauth = OAuthCallbackParams(
        error: 'login_required',
        errorDescription: 'Login required',
        state: 'test-state',
        prompt: 'none',
        valid: true,
      );

      // Should not throw
      await keycloak.processCallback(oauth);
      expect(keycloak.authenticated, isFalse);
    });

    test('processes implicit flow token', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(
        redirectUri: appUrl,
        flow: KeycloakFlow.implicit,
        useNonce: false,
      ),);

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final tokenStr = createTestToken({
        'sub': 'user-123',
        'exp': now + 300,
        'iat': now,
      });

      var authSuccessCalled = false;
      keycloak.onAuthSuccess = () {
        authSuccessCalled = true;
      };

      final oauth = OAuthCallbackParams(
        accessToken: tokenStr,
        state: 'test-state',
        valid: true,
      );

      await keycloak.processCallback(oauth);

      expect(keycloak.authenticated, isTrue);
      expect(keycloak.subject, 'user-123');
      expect(authSuccessCalled, isTrue);
    });
  });

  group('buildAuthorizationHeader', () {
    test('returns null when no token is set', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init();

      expect(keycloak.buildAuthorizationHeader(), isNull);
    });

    test('returns Bearer token when authenticated', () async {
      final keycloak = Keycloak(KeycloakServerConfig(
        url: authServerUrl,
        realm: realm,
        clientId: clientId,
      ),);
      await keycloak.init(KeycloakInitOptions(redirectUri: appUrl),);

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final tokenStr = createTestToken({
        'sub': 'user-123',
        'exp': now + 300,
        'iat': now,
      });
      final refreshTokenStr = createTestToken({
        'exp': now + 1800,
        'iat': now,
      });
      keycloak.setToken(
        tokenStr,
        refreshTokenStr,
        null,
        DateTime.now().millisecondsSinceEpoch,
      );

      expect(
        keycloak.buildAuthorizationHeader(),
        startsWith('Bearer '),
      );
    });
  });
}
