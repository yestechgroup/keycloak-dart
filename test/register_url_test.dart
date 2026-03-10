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

  test('creates a registration URL with all options', () async {
    final redirectUri = 'http://localhost:3000/foo/bar';
    final registerUrlString =
        await keycloak.createRegisterUrl(KeycloakRegisterOptions(
      scope: 'openid profile email',
      redirectUri: redirectUri,
      prompt: 'none',
      maxAge: 3600,
      loginHint: 'test-user@localhost',
      idpHint: 'facebook',
      locale: 'nl-NL nl',
      acr: Acr(values: ['foo', 'bar'], essential: false),
      acrValues: '2fa',
    ),);

    final registerUrl = Uri.parse(registerUrlString);
    expect(
      registerUrl.path,
      '/realms/$realm/protocol/openid-connect/registrations',
    );
    expect(registerUrl.queryParameters['client_id'], clientId);
    expect(registerUrl.queryParameters['redirect_uri'], redirectUri);
    expect(registerUrl.queryParameters['state'], isNotNull);
    expect(registerUrl.queryParameters['response_mode'], 'fragment');
    expect(registerUrl.queryParameters['response_type'], 'code');
    expect(registerUrl.queryParameters['scope'], 'openid profile email');
    expect(registerUrl.queryParameters['nonce'], isNotNull);
    expect(registerUrl.queryParameters['prompt'], 'none');
    expect(registerUrl.queryParameters['max_age'], '3600');
    expect(registerUrl.queryParameters['login_hint'], 'test-user@localhost');
    expect(registerUrl.queryParameters['kc_idp_hint'], 'facebook');
    expect(registerUrl.queryParameters.containsKey('kc_action'), isFalse);
    expect(registerUrl.queryParameters['ui_locales'], 'nl-NL nl');
    expect(
      registerUrl.queryParameters['claims'],
      '{"id_token":{"acr":{"values":["foo","bar"],"essential":false}}}',
    );
    expect(registerUrl.queryParameters['acr_values'], '2fa');
    expect(registerUrl.queryParameters['code_challenge'], isNotNull);
    expect(registerUrl.queryParameters['code_challenge_method'], 'S256');
  });

  test('creates a registration URL with default options', () async {
    final registerUrlString = await keycloak.createRegisterUrl();
    final registerUrl = Uri.parse(registerUrlString);

    expect(
      registerUrl.path,
      '/realms/$realm/protocol/openid-connect/registrations',
    );
    expect(registerUrl.queryParameters['client_id'], clientId);
    expect(registerUrl.queryParameters['redirect_uri'], appUrl);
    expect(registerUrl.queryParameters['state'], isNotNull);
    expect(registerUrl.queryParameters['response_mode'], 'fragment');
    expect(registerUrl.queryParameters['response_type'], 'code');
    expect(registerUrl.queryParameters['scope'], 'openid');
    expect(registerUrl.queryParameters['nonce'], isNotNull);
    expect(registerUrl.queryParameters.containsKey('prompt'), isFalse);
    expect(registerUrl.queryParameters.containsKey('max_age'), isFalse);
    expect(registerUrl.queryParameters.containsKey('login_hint'), isFalse);
    expect(registerUrl.queryParameters.containsKey('kc_idp_hint'), isFalse);
    expect(registerUrl.queryParameters.containsKey('kc_action'), isFalse);
    expect(registerUrl.queryParameters.containsKey('ui_locales'), isFalse);
    expect(registerUrl.queryParameters.containsKey('claims'), isFalse);
    expect(registerUrl.queryParameters.containsKey('acr_values'), isFalse);
    expect(registerUrl.queryParameters['code_challenge'], isNotNull);
    expect(registerUrl.queryParameters['code_challenge_method'], 'S256');
  });
}
