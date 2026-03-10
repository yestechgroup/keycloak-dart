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
    ),);
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
    ),);
  });

  test('creates an account URL with all options', () {
    final redirectUri = 'http://localhost:3000/foo/bar';
    final accountUrlString = keycloak.createAccountUrl(
      KeycloakAccountOptions(redirectUri: redirectUri),
    );
    final accountUrl = Uri.parse(accountUrlString);

    expect(accountUrl.path, '/realms/$realm/account');
    expect(accountUrl.queryParameters['referrer'], clientId);
    expect(accountUrl.queryParameters['referrer_uri'], redirectUri);
  });

  test('creates an account URL with default options', () {
    final accountUrlString = keycloak.createAccountUrl();
    final accountUrl = Uri.parse(accountUrlString);

    expect(accountUrl.path, '/realms/$realm/account');
    expect(accountUrl.queryParameters['referrer'], clientId);
    expect(accountUrl.queryParameters['referrer_uri'], appUrl);
  });

  test('throws creating an account URL using a generic OpenID provider',
      () async {
    final kc = Keycloak(GenericOidcConfig(
      clientId: clientId,
      oidcProvider: OpenIdProviderMetadata(
        authorizationEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/auth',
        tokenEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/token',
        endSessionEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/logout',
      ),
    ),);
    await kc.init();

    expect(
      () => kc.createAccountUrl(),
      throwsA(isA<StateError>().having(
        (e) => e.message,
        'message',
        contains('generic OIDC provider'),
      ),),
    );
  });
}
