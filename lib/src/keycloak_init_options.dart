import 'keycloak_adapter.dart';

/// Specifies an action to do on load.
enum KeycloakOnLoad { loginRequired, checkSso }

/// OpenID Connect response mode.
enum KeycloakResponseMode { query, fragment }

/// OpenID Connect response type.
enum KeycloakResponseType { code, idTokenToken, codeIdTokenToken }

/// OpenID Connect flow.
enum KeycloakFlow { standard, implicit, hybrid }

/// PKCE method.
enum KeycloakPkceMethod { s256 }

extension KeycloakResponseModeExtension on KeycloakResponseMode {
  String get value {
    switch (this) {
      case KeycloakResponseMode.query:
        return 'query';
      case KeycloakResponseMode.fragment:
        return 'fragment';
    }
  }
}

extension KeycloakResponseTypeExtension on KeycloakResponseType {
  String get value {
    switch (this) {
      case KeycloakResponseType.code:
        return 'code';
      case KeycloakResponseType.idTokenToken:
        return 'id_token token';
      case KeycloakResponseType.codeIdTokenToken:
        return 'code id_token token';
    }
  }
}

extension KeycloakFlowExtension on KeycloakFlow {
  String get value {
    switch (this) {
      case KeycloakFlow.standard:
        return 'standard';
      case KeycloakFlow.implicit:
        return 'implicit';
      case KeycloakFlow.hybrid:
        return 'hybrid';
    }
  }
}

extension KeycloakPkceMethodExtension on KeycloakPkceMethod {
  String get value {
    switch (this) {
      case KeycloakPkceMethod.s256:
        return 'S256';
    }
  }
}

/// Options for initializing the Keycloak adapter.
class KeycloakInitOptions {
  /// Adds a cryptographic nonce to verify that the authentication
  /// response matches the request. Defaults to true.
  final bool useNonce;

  /// Allow usage of different types of adapters or a custom adapter.
  final KeycloakAdapter? adapter;

  /// Specifies an action to do on load.
  final KeycloakOnLoad? onLoad;

  /// Set an initial value for the token.
  final String? token;

  /// Set an initial value for the refresh token.
  final String? refreshToken;

  /// Set an initial value for the id token.
  final String? idToken;

  /// Set an initial value for skew between local time and Keycloak server
  /// in seconds.
  final int? timeSkew;

  /// Set to enable/disable monitoring login state. Defaults to true.
  final bool checkLoginIframe;

  /// Set the interval to check login state (in seconds). Defaults to 5.
  final int checkLoginIframeInterval;

  /// Set the OpenID Connect response mode. Defaults to fragment.
  final KeycloakResponseMode? responseMode;

  /// Specifies a default uri to redirect to after login or logout.
  final String? redirectUri;

  /// Specifies an uri to redirect to after silent check-sso.
  final String? silentCheckSsoRedirectUri;

  /// Specifies whether the silent check-sso should fallback to
  /// "non-silent" check-sso when 3rd party cookies are blocked.
  /// Defaults to true.
  final bool silentCheckSsoFallback;

  /// Set the OpenID Connect flow. Defaults to standard.
  final KeycloakFlow? flow;

  /// Configures the PKCE method to use. Defaults to S256.
  /// Set to null to disable PKCE.
  final KeycloakPkceMethod? pkceMethod;

  /// Whether PKCE is enabled. Defaults to true.
  final bool enablePkce;

  /// Enables logging messages from Keycloak to the console.
  /// Defaults to false.
  final bool enableLogging;

  /// Set the default scope parameter to the login endpoint.
  final String? scope;

  /// Configures how long will Keycloak adapter wait for receiving
  /// messages from server in ms. Defaults to 10000.
  final int messageReceiveTimeout;

  /// When onLoad is 'login-required', sets the 'ui_locales' query param.
  final String? locale;

  /// HTTP method for calling the end_session endpoint.
  /// Defaults to 'GET'.
  final String logoutMethod;

  const KeycloakInitOptions({
    this.useNonce = true,
    this.adapter,
    this.onLoad,
    this.token,
    this.refreshToken,
    this.idToken,
    this.timeSkew,
    this.checkLoginIframe = true,
    this.checkLoginIframeInterval = 5,
    this.responseMode,
    this.redirectUri,
    this.silentCheckSsoRedirectUri,
    this.silentCheckSsoFallback = true,
    this.flow,
    this.pkceMethod = KeycloakPkceMethod.s256,
    this.enablePkce = true,
    this.enableLogging = false,
    this.scope,
    this.messageReceiveTimeout = 10000,
    this.locale,
    this.logoutMethod = 'GET',
  });
}
