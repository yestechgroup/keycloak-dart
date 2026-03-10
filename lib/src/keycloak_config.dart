/// Configuration for connecting to a Keycloak server.
class KeycloakServerConfig {
  /// URL to the Keycloak server, for example: http://keycloak-server/auth
  final String url;

  /// Name of the realm, for example: 'myrealm'
  final String realm;

  /// Client identifier, example: 'myapp'
  final String clientId;

  const KeycloakServerConfig({
    required this.url,
    required this.realm,
    required this.clientId,
  });
}

/// Configuration for a generic OpenID Connect provider.
class GenericOidcConfig {
  /// Client identifier, example: 'myapp'
  final String clientId;

  /// Generic OpenID Connect configuration.
  /// Can be a URL string to the discovery metadata endpoint,
  /// or an [OpenIdProviderMetadata] instance.
  final Object oidcProvider;

  const GenericOidcConfig({
    required this.clientId,
    required this.oidcProvider,
  });
}

/// OpenID Connect Discovery metadata.
class OpenIdProviderMetadata {
  /// URL of the OP's OAuth 2.0 Authorization Endpoint.
  final String authorizationEndpoint;

  /// URL of the OP's OAuth 2.0 Token Endpoint.
  final String tokenEndpoint;

  /// URL of the OP's UserInfo Endpoint.
  final String? userinfoEndpoint;

  /// URL of an OP iframe that supports cross-origin communications
  /// for session state information.
  final String? checkSessionIframe;

  /// URL at the OP to which an RP can perform a redirect to request
  /// that the End-User be logged out at the OP.
  final String? endSessionEndpoint;

  const OpenIdProviderMetadata({
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    this.userinfoEndpoint,
    this.checkSessionIframe,
    this.endSessionEndpoint,
  });

  factory OpenIdProviderMetadata.fromJson(Map<String, dynamic> json) {
    return OpenIdProviderMetadata(
      authorizationEndpoint: json['authorization_endpoint'] as String,
      tokenEndpoint: json['token_endpoint'] as String,
      userinfoEndpoint: json['userinfo_endpoint'] as String?,
      checkSessionIframe: json['check_session_iframe'] as String?,
      endSessionEndpoint: json['end_session_endpoint'] as String?,
    );
  }
}

/// Union type for Keycloak configuration.
/// Use either [KeycloakServerConfig] or [GenericOidcConfig].
typedef KeycloakConfig = Object;
