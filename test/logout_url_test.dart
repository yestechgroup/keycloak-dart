import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

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
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
    ));
  });

  test('creates a logout URL with all options', () {
    final redirectUri = 'http://localhost:3000/foo/bar';
    final logoutUrlString = keycloak.createLogoutUrl(KeycloakLogoutOptions(
      logoutMethod: 'GET',
      redirectUri: redirectUri,
    ));
    final logoutUrl = Uri.parse(logoutUrlString);

    expect(
      logoutUrl.path,
      '/realms/$realm/protocol/openid-connect/logout',
    );
    expect(logoutUrl.queryParameters['client_id'], clientId);
    expect(
      logoutUrl.queryParameters['post_logout_redirect_uri'],
      redirectUri,
    );
    expect(logoutUrl.queryParameters.containsKey('id_token_hint'), isFalse);
  });

  test('creates a logout URL with default options', () {
    final logoutUrlString = keycloak.createLogoutUrl();
    final logoutUrl = Uri.parse(logoutUrlString);

    expect(
      logoutUrl.path,
      '/realms/$realm/protocol/openid-connect/logout',
    );
    expect(logoutUrl.queryParameters['client_id'], clientId);
    expect(logoutUrl.queryParameters['post_logout_redirect_uri'], appUrl);
    expect(logoutUrl.queryParameters.containsKey('id_token_hint'), isFalse);
  });

  test("creates a logout URL with 'POST' method", () {
    final logoutUrlString = keycloak.createLogoutUrl(KeycloakLogoutOptions(
      logoutMethod: 'POST',
      redirectUri: 'http://localhost:3000/foo/bar',
    ));
    final logoutUrl = Uri.parse(logoutUrlString);

    expect(
      logoutUrl.path,
      '/realms/$realm/protocol/openid-connect/logout',
    );
    expect(logoutUrl.queryParameters.containsKey('client_id'), isFalse);
    expect(
      logoutUrl.queryParameters.containsKey('post_logout_redirect_uri'),
      isFalse,
    );
    expect(logoutUrl.queryParameters.containsKey('id_token_hint'), isFalse);
  });

  test('creates a logout URL using the redirect URL passed during initialization',
      () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    final redirectUri = 'http://localhost:3000/foo/bar';
    await kc.init(KeycloakInitOptions(redirectUri: redirectUri));
    final logoutUrlString = kc.createLogoutUrl();
    final logoutUrl = Uri.parse(logoutUrlString);

    expect(logoutUrl.queryParameters['post_logout_redirect_uri'], redirectUri);
  });

  test('creates a logout URL with the ID token hint when authenticated', () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await kc.init(KeycloakInitOptions(redirectUri: appUrl));

    // Simulate authentication by setting the idToken
    kc.idToken = 'test-id-token';
    final logoutUrlString = kc.createLogoutUrl();
    final logoutUrl = Uri.parse(logoutUrlString);

    expect(logoutUrl.queryParameters['id_token_hint'], 'test-id-token');
  });
}
