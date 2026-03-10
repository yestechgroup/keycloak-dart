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

  test('creates a login URL with all options', () async {
    final redirectUri = 'http://localhost:3000/foo/bar';
    final loginUrlString = await keycloak.createLoginUrl(KeycloakLoginOptions(
      scope: 'openid profile email',
      redirectUri: redirectUri,
      prompt: 'none',
      maxAge: 3600,
      loginHint: 'test-user@localhost',
      idpHint: 'facebook',
      action: 'UPDATE_PASSWORD',
      locale: 'nl-NL nl',
      acr: Acr(values: ['foo', 'bar'], essential: false),
      acrValues: '2fa',
    ),);

    final loginUrl = Uri.parse(loginUrlString);
    expect(
      loginUrl.path,
      '/realms/$realm/protocol/openid-connect/auth',
    );
    expect(loginUrl.queryParameters['client_id'], clientId);
    expect(loginUrl.queryParameters['redirect_uri'], redirectUri);
    expect(loginUrl.queryParameters['state'], isNotNull);
    expect(loginUrl.queryParameters['response_mode'], 'fragment');
    expect(loginUrl.queryParameters['response_type'], 'code');
    expect(loginUrl.queryParameters['scope'], 'openid profile email');
    expect(loginUrl.queryParameters['nonce'], isNotNull);
    expect(loginUrl.queryParameters['prompt'], 'none');
    expect(loginUrl.queryParameters['max_age'], '3600');
    expect(loginUrl.queryParameters['login_hint'], 'test-user@localhost');
    expect(loginUrl.queryParameters['kc_idp_hint'], 'facebook');
    expect(loginUrl.queryParameters['kc_action'], 'UPDATE_PASSWORD');
    expect(loginUrl.queryParameters['ui_locales'], 'nl-NL nl');
    expect(
      loginUrl.queryParameters['claims'],
      '{"id_token":{"acr":{"values":["foo","bar"],"essential":false}}}',
    );
    expect(loginUrl.queryParameters['acr_values'], '2fa');
    expect(loginUrl.queryParameters['code_challenge'], isNotNull);
    expect(loginUrl.queryParameters['code_challenge_method'], 'S256');
  });

  test('creates a login URL with default options', () async {
    final loginUrlString = await keycloak.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(
      loginUrl.path,
      '/realms/$realm/protocol/openid-connect/auth',
    );
    expect(loginUrl.queryParameters['client_id'], clientId);
    expect(loginUrl.queryParameters['redirect_uri'], appUrl);
    expect(loginUrl.queryParameters['state'], isNotNull);
    expect(loginUrl.queryParameters['response_mode'], 'fragment');
    expect(loginUrl.queryParameters['response_type'], 'code');
    expect(loginUrl.queryParameters['scope'], 'openid');
    expect(loginUrl.queryParameters['nonce'], isNotNull);
    expect(loginUrl.queryParameters.containsKey('prompt'), isFalse);
    expect(loginUrl.queryParameters.containsKey('max_age'), isFalse);
    expect(loginUrl.queryParameters.containsKey('login_hint'), isFalse);
    expect(loginUrl.queryParameters.containsKey('kc_idp_hint'), isFalse);
    expect(loginUrl.queryParameters.containsKey('kc_action'), isFalse);
    expect(loginUrl.queryParameters.containsKey('ui_locales'), isFalse);
    expect(loginUrl.queryParameters.containsKey('claims'), isFalse);
    expect(loginUrl.queryParameters.containsKey('acr_values'), isFalse);
    expect(loginUrl.queryParameters['code_challenge'], isNotNull);
    expect(loginUrl.queryParameters['code_challenge_method'], 'S256');
  });

  test('creates a login URL to the registration page', () async {
    final loginUrlString = await keycloak.createLoginUrl(
      KeycloakLoginOptions(action: 'register'),
    );
    final loginUrl = Uri.parse(loginUrlString);

    expect(
      loginUrl.path,
      '/realms/$realm/protocol/openid-connect/registrations',
    );
    expect(loginUrl.queryParameters.containsKey('kc_action'), isFalse);
  });

  test('creates a login URL using the redirect URL passed during initialization',
      () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    final redirectUri = 'http://localhost:3000/foo/bar';
    await kc.init(KeycloakInitOptions(redirectUri: redirectUri));
    final loginUrlString = await kc.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(loginUrl.queryParameters['redirect_uri'], redirectUri);
  });

  test('creates a login URL using the scope passed during initialization',
      () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await kc.init(KeycloakInitOptions(
      scope: 'openid profile email',
    ),);
    final loginUrlString = await kc.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(loginUrl.queryParameters['scope'], 'openid profile email');
  });

  test("creates a login URL with the 'openid' scope appended if omitted",
      () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await kc.init(KeycloakInitOptions(
      scope: 'profile email openidlike',
    ),);
    final loginUrlString = await kc.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(
      loginUrl.queryParameters['scope'],
      'openid profile email openidlike',
    );
  });

  test(
      'creates a login URL using the response mode passed during initialization',
      () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await kc.init(KeycloakInitOptions(
      responseMode: KeycloakResponseMode.query,
    ),);
    final loginUrlString = await kc.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(loginUrl.queryParameters['response_mode'], 'query');
  });

  test('creates a login URL based on the flow passed during initialization',
      () async {
    final kc = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await kc.init(KeycloakInitOptions(
      flow: KeycloakFlow.implicit,
    ),);
    final loginUrlString = await kc.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(loginUrl.queryParameters['response_type'], 'id_token token');
  });

  test('creates a login URL with a max age of 0', () async {
    final loginUrlString = await keycloak.createLoginUrl(
      KeycloakLoginOptions(maxAge: 0),
    );
    final loginUrl = Uri.parse(loginUrlString);

    expect(loginUrl.queryParameters['max_age'], '0');
  });
}
