/// ACR (Authentication Context Class Reference) configuration.
class Acr {
  /// Array of values for the acr claim.
  final List<String> values;

  /// Whether the ACR claim is essential.
  final bool essential;

  const Acr({
    required this.values,
    required this.essential,
  });

  Map<String, dynamic> toJson() => {
        'values': values,
        'essential': essential,
      };
}

/// Options for the login redirect.
class KeycloakLoginOptions {
  /// Specifies the scope parameter for the login url.
  final String? scope;

  /// Specifies the uri to redirect to after login.
  final String? redirectUri;

  /// Controls the login screen display behavior.
  /// Can be 'none', 'login', or 'consent'.
  final String? prompt;

  /// If value is 'register' then user is redirected to registration page.
  final String? action;

  /// Maximum time since the authentication of user happened.
  final int? maxAge;

  /// Used to pre-fill the username/email field on the login form.
  final String? loginHint;

  /// Sets the acr claim of the ID token.
  final Acr? acr;

  /// Configures the 'acr_values' query param.
  final String? acrValues;

  /// Used to tell Keycloak which IDP the user wants to authenticate with.
  final String? idpHint;

  /// Sets the 'ui_locales' query param.
  final String? locale;

  const KeycloakLoginOptions({
    this.scope,
    this.redirectUri,
    this.prompt,
    this.action,
    this.maxAge,
    this.loginHint,
    this.acr,
    this.acrValues,
    this.idpHint,
    this.locale,
  });
}

/// Options for specifying a redirect URI.
class KeycloakRedirectUriOptions {
  /// Specifies the uri to redirect to after login.
  final String? redirectUri;

  const KeycloakRedirectUriOptions({
    this.redirectUri,
  });
}

/// Options for the logout redirect.
class KeycloakLogoutOptions {
  /// Specifies the uri to redirect to after logout.
  final String? redirectUri;

  /// HTTP method for calling the end_session endpoint.
  /// Defaults to 'GET'.
  final String? logoutMethod;

  const KeycloakLogoutOptions({
    this.redirectUri,
    this.logoutMethod,
  });
}

/// Options for the registration redirect.
/// Same as [KeycloakLoginOptions] but without the action field.
class KeycloakRegisterOptions {
  final String? scope;
  final String? redirectUri;
  final String? prompt;
  final int? maxAge;
  final String? loginHint;
  final Acr? acr;
  final String? acrValues;
  final String? idpHint;
  final String? locale;

  const KeycloakRegisterOptions({
    this.scope,
    this.redirectUri,
    this.prompt,
    this.maxAge,
    this.loginHint,
    this.acr,
    this.acrValues,
    this.idpHint,
    this.locale,
  });

  KeycloakLoginOptions toLoginOptions() {
    return KeycloakLoginOptions(
      scope: scope,
      redirectUri: redirectUri,
      prompt: prompt,
      action: 'register',
      maxAge: maxAge,
      loginHint: loginHint,
      acr: acr,
      acrValues: acrValues,
      idpHint: idpHint,
      locale: locale,
    );
  }
}

/// Options for the account management URL.
class KeycloakAccountOptions {
  /// Specifies the uri to redirect to when redirecting back.
  final String? redirectUri;

  const KeycloakAccountOptions({
    this.redirectUri,
  });
}
