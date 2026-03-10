import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart' as crypto_lib;
import 'package:http/http.dart' as http;

import 'keycloak_adapter.dart';
import 'keycloak_config.dart';
import 'keycloak_error.dart';
import 'keycloak_init_options.dart';
import 'keycloak_login_options.dart';
import 'keycloak_network_error.dart';
import 'keycloak_profile.dart';
import 'keycloak_token.dart';
import 'keycloak_user_info.dart';

/// Callback storage for managing OAuth state between redirects.
class CallbackState {
  final String state;
  final String nonce;
  final String redirectUri;
  final KeycloakLoginOptions? loginOptions;
  final String? prompt;
  final String? pkceCodeVerifier;

  const CallbackState({
    required this.state,
    required this.nonce,
    required this.redirectUri,
    this.loginOptions,
    this.prompt,
    this.pkceCodeVerifier,
  });
}

/// In-memory callback storage.
class CallbackStorage {
  final Map<String, CallbackState> _storage = {};

  void add(CallbackState state) {
    _storage[state.state] = state;
  }

  CallbackState? get(String? state) {
    if (state == null) return null;
    return _storage.remove(state);
  }
}

/// Result of parsing an OAuth callback URL.
class OAuthCallbackParams {
  final String? code;
  final String? error;
  final String? errorDescription;
  final String? errorUri;
  final String? state;
  final String? sessionState;
  final String? accessToken;
  final String? tokenType;
  final String? idToken;
  final String? expiresIn;
  final String? kcActionStatus;
  final String? kcAction;
  final String? iss;
  final String? newUrl;
  final String? redirectUri;
  final String? storedNonce;
  final String? prompt;
  final String? pkceCodeVerifier;
  final KeycloakLoginOptions? loginOptions;
  final bool valid;

  const OAuthCallbackParams({
    this.code,
    this.error,
    this.errorDescription,
    this.errorUri,
    this.state,
    this.sessionState,
    this.accessToken,
    this.tokenType,
    this.idToken,
    this.expiresIn,
    this.kcActionStatus,
    this.kcAction,
    this.iss,
    this.newUrl,
    this.redirectUri,
    this.storedNonce,
    this.prompt,
    this.pkceCodeVerifier,
    this.loginOptions,
    this.valid = false,
  });

  OAuthCallbackParams copyWith({
    String? redirectUri,
    String? storedNonce,
    String? prompt,
    String? pkceCodeVerifier,
    String? newUrl,
    KeycloakLoginOptions? loginOptions,
    bool? valid,
  }) {
    return OAuthCallbackParams(
      code: code,
      error: error,
      errorDescription: errorDescription,
      errorUri: errorUri,
      state: state,
      sessionState: sessionState,
      accessToken: accessToken,
      tokenType: tokenType,
      idToken: idToken,
      expiresIn: expiresIn,
      kcActionStatus: kcActionStatus,
      kcAction: kcAction,
      iss: iss,
      newUrl: newUrl ?? this.newUrl,
      redirectUri: redirectUri ?? this.redirectUri,
      storedNonce: storedNonce ?? this.storedNonce,
      prompt: prompt ?? this.prompt,
      pkceCodeVerifier: pkceCodeVerifier ?? this.pkceCodeVerifier,
      loginOptions: loginOptions ?? this.loginOptions,
      valid: valid ?? this.valid,
    );
  }
}

/// Result of parsing callback params from a URL fragment or query string.
class ParsedCallbackParams {
  final String paramsString;
  final Map<String, String> oauthParams;

  const ParsedCallbackParams({
    required this.paramsString,
    required this.oauthParams,
  });
}

/// Endpoints for the Keycloak server.
class Endpoints {
  final String Function() authorize;
  final String Function() token;
  final String Function() logout;
  final String Function() checkSessionIframe;
  final String Function() register;
  final String Function() userinfo;

  const Endpoints({
    required this.authorize,
    required this.token,
    required this.logout,
    required this.checkSessionIframe,
    required this.register,
    required this.userinfo,
  });
}

/// A client for the Keycloak authentication server.
class Keycloak {
  final Object _config;
  final http.Client _httpClient;

  KeycloakAdapter? _adapter;
  bool _useNonce = true;
  CallbackStorage _callbackStorage = CallbackStorage();
  final List<Completer<bool>> _refreshQueue = [];

  bool didInitialize = false;
  bool authenticated = false;
  bool loginRequired = false;

  KeycloakResponseMode responseMode = KeycloakResponseMode.fragment;
  KeycloakResponseType responseType = KeycloakResponseType.code;
  KeycloakFlow flow = KeycloakFlow.standard;

  int? timeSkew;
  String? redirectUri;
  String? silentCheckSsoRedirectUri;
  bool silentCheckSsoFallback = true;
  KeycloakPkceMethod? pkceMethod = KeycloakPkceMethod.s256;
  bool enablePkce = true;
  bool enableLogging = false;
  String logoutMethod = 'GET';
  String? scope;
  int messageReceiveTimeout = 10000;

  String? idToken;
  KeycloakTokenParsed? idTokenParsed;
  String? token;
  KeycloakTokenParsed? tokenParsed;
  String? refreshToken;
  KeycloakTokenParsed? refreshTokenParsed;

  String? clientId;
  String? sessionId;
  String? subject;
  String? authServerUrl;
  String? realm;

  KeycloakRolesData? realmAccess;
  Map<String, KeycloakRolesData>? resourceAccess;

  KeycloakProfile? profile;
  KeycloakUserInfo? userInfo;

  Endpoints? endpoints;

  // Callbacks
  void Function(bool authenticated)? onReady;
  void Function()? onAuthSuccess;
  void Function(KeycloakError? errorData)? onAuthError;
  void Function()? onAuthRefreshSuccess;
  void Function()? onAuthRefreshError;
  void Function()? onTokenExpired;
  void Function()? onAuthLogout;
  void Function(String status, String? action)? onActionUpdate;

  /// Creates a new Keycloak client instance.
  ///
  /// [config] must be a [KeycloakServerConfig], [GenericOidcConfig],
  /// or a [String] URL to a JSON configuration file.
  Keycloak(
    Object config, {
    http.Client? httpClient,
  })  : _config = config,
        _httpClient = httpClient ?? http.Client() {
    if (config is String) {
      // URL to JSON config - valid
    } else if (config is KeycloakServerConfig) {
      // Valid
    } else if (config is GenericOidcConfig) {
      // Valid
    } else {
      throw ArgumentError(
        "The 'Keycloak' constructor must be provided with a "
        'KeycloakServerConfig, GenericOidcConfig, or a URL string '
        'to a JSON configuration file.',
      );
    }
  }

  /// Initialize the Keycloak adapter.
  Future<bool> init([KeycloakInitOptions? initOptions]) async {
    final options = initOptions ?? const KeycloakInitOptions();

    if (didInitialize) {
      throw StateError(
        "A 'Keycloak' instance can only be initialized once.",
      );
    }

    didInitialize = true;
    _callbackStorage = CallbackStorage();

    if (options.adapter != null) {
      _adapter = options.adapter;
    } else {
      _adapter = _DefaultAdapter(this);
    }

    _useNonce = options.useNonce;

    if (options.onLoad == KeycloakOnLoad.loginRequired) {
      loginRequired = true;
    }

    if (options.responseMode != null) {
      responseMode = options.responseMode!;
    }

    if (options.flow != null) {
      switch (options.flow!) {
        case KeycloakFlow.standard:
          responseType = KeycloakResponseType.code;
          break;
        case KeycloakFlow.implicit:
          responseType = KeycloakResponseType.idTokenToken;
          break;
        case KeycloakFlow.hybrid:
          responseType = KeycloakResponseType.codeIdTokenToken;
          break;
      }
      flow = options.flow!;
    }

    if (options.timeSkew != null) {
      timeSkew = options.timeSkew;
    }

    if (options.redirectUri != null) {
      redirectUri = options.redirectUri;
    }

    if (options.silentCheckSsoRedirectUri != null) {
      silentCheckSsoRedirectUri = options.silentCheckSsoRedirectUri;
    }

    silentCheckSsoFallback = options.silentCheckSsoFallback;

    if (options.enablePkce) {
      pkceMethod = options.pkceMethod;
    } else {
      pkceMethod = null;
    }

    enableLogging = options.enableLogging;

    if (options.logoutMethod == 'POST') {
      logoutMethod = 'POST';
    }

    if (options.scope != null) {
      scope = options.scope;
    }

    if (options.messageReceiveTimeout > 0) {
      messageReceiveTimeout = options.messageReceiveTimeout;
    }

    await _loadConfig();

    // Process initial tokens if provided
    if (options.token != null || options.refreshToken != null) {
      setToken(
        options.token,
        options.refreshToken,
        options.idToken,
        options.timeSkew != null
            ? DateTime.now().millisecondsSinceEpoch
            : null,
      );
    }

    _scheduleTokenExpiry();

    onReady?.call(authenticated);

    return authenticated;
  }

  /// Redirect to login form.
  Future<void> login([KeycloakLoginOptions? options]) async {
    if (_adapter == null) {
      throw StateError('Adapter not initialized. Call init() first.');
    }
    return _adapter!.login(options);
  }

  /// Create a login URL.
  Future<String> createLoginUrl([KeycloakLoginOptions? options]) async {
    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    final state = _createUUID();
    final nonce = _createUUID();
    final effectiveRedirectUri =
        options?.redirectUri ?? _adapter?.redirectUri() ?? redirectUri ?? '';

    final url = options?.action == 'register'
        ? endpoints!.register()
        : endpoints!.authorize();

    String? effectiveScope = options?.scope ?? scope;
    final scopeValues =
        effectiveScope != null ? effectiveScope.split(' ') : <String>[];

    if (!scopeValues.contains('openid')) {
      scopeValues.insert(0, 'openid');
    }

    effectiveScope = scopeValues.join(' ');

    final params = <String, String>{
      'client_id': clientId!,
      'redirect_uri': effectiveRedirectUri,
      'state': state,
      'response_mode': responseMode.value,
      'response_type': responseType.value,
      'scope': effectiveScope,
    };

    if (_useNonce) {
      params['nonce'] = nonce;
    }

    if (options?.prompt != null) {
      params['prompt'] = options!.prompt!;
    }

    if (options?.maxAge != null) {
      params['max_age'] = options!.maxAge.toString();
    }

    if (options?.loginHint != null) {
      params['login_hint'] = options!.loginHint!;
    }

    if (options?.idpHint != null) {
      params['kc_idp_hint'] = options!.idpHint!;
    }

    if (options?.action != null && options!.action != 'register') {
      params['kc_action'] = options.action!;
    }

    if (options?.locale != null) {
      params['ui_locales'] = options!.locale!;
    }

    if (options?.acr != null) {
      params['claims'] = _buildClaimsParameter(options!.acr!);
    }

    if (options?.acrValues != null) {
      params['acr_values'] = options!.acrValues!;
    }

    String? pkceCodeVerifier;
    if (pkceMethod != null) {
      final codeVerifier = _generateCodeVerifier(96);
      final pkceChallenge =
          await _generatePkceChallenge(pkceMethod!, codeVerifier);

      pkceCodeVerifier = codeVerifier;
      params['code_challenge'] = pkceChallenge;
      params['code_challenge_method'] = pkceMethod!.value;
    }

    final updatedCallbackState = CallbackState(
      state: state,
      nonce: nonce,
      redirectUri: effectiveRedirectUri,
      loginOptions: options,
      prompt: options?.prompt,
      pkceCodeVerifier: pkceCodeVerifier,
    );

    _callbackStorage.add(updatedCallbackState);

    final uri = Uri.parse(url).replace(queryParameters: params);
    return uri.toString();
  }

  /// Redirect to logout.
  Future<void> logout([KeycloakLogoutOptions? options]) async {
    if (_adapter == null) {
      throw StateError('Adapter not initialized. Call init() first.');
    }
    return _adapter!.logout(options);
  }

  /// Create a logout URL.
  String createLogoutUrl([KeycloakLogoutOptions? options]) {
    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    final effectiveLogoutMethod = options?.logoutMethod ?? logoutMethod;
    final url = endpoints!.logout();

    if (effectiveLogoutMethod == 'POST') {
      return url;
    }

    final effectiveRedirectUri =
        options?.redirectUri ?? _adapter?.redirectUri() ?? redirectUri ?? '';

    final params = <String, String>{
      'client_id': clientId!,
      'post_logout_redirect_uri': effectiveRedirectUri,
    };

    if (idToken != null) {
      params['id_token_hint'] = idToken!;
    }

    final uri = Uri.parse(url).replace(queryParameters: params);
    return uri.toString();
  }

  /// Redirect to registration form.
  Future<void> register([KeycloakRegisterOptions? options]) async {
    if (_adapter == null) {
      throw StateError('Adapter not initialized. Call init() first.');
    }
    return _adapter!.register(options);
  }

  /// Create a registration URL.
  Future<String> createRegisterUrl([KeycloakRegisterOptions? options]) {
    final loginOptions = options?.toLoginOptions() ??
        const KeycloakLoginOptions(action: 'register');
    return createLoginUrl(loginOptions);
  }

  /// Create an account management URL.
  String createAccountUrl([KeycloakAccountOptions? options]) {
    final realmUrl = getRealmUrl();

    if (realmUrl == null) {
      throw StateError(
        'Unable to create account URL, make sure the adapter is not '
        'configured using a generic OIDC provider.',
      );
    }

    final effectiveRedirectUri =
        options?.redirectUri ?? _adapter?.redirectUri() ?? redirectUri ?? '';

    final params = <String, String>{
      'referrer': clientId!,
      'referrer_uri': effectiveRedirectUri,
    };

    final uri = Uri.parse('$realmUrl/account').replace(queryParameters: params);
    return uri.toString();
  }

  /// Redirects to the Account Management Console.
  Future<void> accountManagement() async {
    if (_adapter == null) {
      throw StateError('Adapter not initialized. Call init() first.');
    }
    return _adapter!.accountManagement();
  }

  /// Returns true if the token has the given realm role.
  bool hasRealmRole(String role) {
    return realmAccess != null && realmAccess!.roles.contains(role);
  }

  /// Returns true if the token has the given role for the resource.
  bool hasResourceRole(String role, [String? resource]) {
    if (resourceAccess == null) return false;
    final access = resourceAccess![resource ?? clientId];
    return access != null && access.roles.contains(role);
  }

  /// Load the user's profile from the account endpoint.
  Future<KeycloakProfile> loadUserProfile() async {
    final realmUrl = getRealmUrl();

    if (realmUrl == null) {
      throw StateError(
        'Unable to load user profile, make sure the adapter is not '
        'configured using a generic OIDC provider.',
      );
    }

    if (token == null) {
      throw StateError(
        'Unable to build authorization header, token is not set, '
        'make sure the user is authenticated.',
      );
    }

    final url = '$realmUrl/account';
    final response = await _httpClient.get(
      Uri.parse(url),
      headers: {
        'Accept': 'application/json',
        'Authorization': 'bearer $token',
      },
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to load user profile.');
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    profile = KeycloakProfile.fromJson(json);
    return profile!;
  }

  /// Load user info from the userinfo endpoint.
  Future<KeycloakUserInfo> loadUserInfo() async {
    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    if (token == null) {
      throw StateError(
        'Unable to build authorization header, token is not set, '
        'make sure the user is authenticated.',
      );
    }

    final url = endpoints!.userinfo();
    final response = await _httpClient.get(
      Uri.parse(url),
      headers: {
        'Accept': 'application/json',
        'Authorization': 'bearer $token',
      },
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to load user info.');
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final info = KeycloakUserInfo.fromJson(json);
    userInfo = info;
    return info;
  }

  /// Returns true if the token has less than [minValidity] seconds
  /// left before it expires.
  bool isTokenExpired([int minValidity = 0]) {
    if (tokenParsed == null) {
      throw StateError('Not authenticated');
    }

    if (flow != KeycloakFlow.implicit && refreshToken == null) {
      throw StateError('Not authenticated');
    }

    if (timeSkew == null) {
      return true;
    }

    if (tokenParsed!.exp == null) {
      return false;
    }

    var expiresIn = tokenParsed!.exp! -
        (DateTime.now().millisecondsSinceEpoch / 1000).ceil() +
        timeSkew!;
    expiresIn -= minValidity;
    return expiresIn < 0;
  }

  /// If the token expires within [minValidity] seconds, refresh it.
  ///
  /// Uses a queue to coalesce concurrent refresh requests — only the first
  /// request actually contacts the server; subsequent callers share the result.
  Future<bool> updateToken([int minValidity = 5]) async {
    if (refreshToken == null) {
      throw StateError(
        'Unable to update token, no refresh token available.',
      );
    }

    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    bool shouldRefresh = false;

    if (minValidity == -1) {
      shouldRefresh = true;
    } else if (tokenParsed == null || isTokenExpired(minValidity)) {
      shouldRefresh = true;
    }

    if (!shouldRefresh) {
      return false;
    }

    final completer = Completer<bool>();
    _refreshQueue.add(completer);

    if (_refreshQueue.length == 1) {
      // First caller performs the actual refresh.
      _performTokenRefresh();
    }

    return completer.future;
  }

  Future<void> _performTokenRefresh() async {
    try {
      final url = endpoints!.token();
      var timeLocal = DateTime.now().millisecondsSinceEpoch;

      final response = await _httpClient.post(
        Uri.parse(url),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'grant_type': 'refresh_token',
          'refresh_token': refreshToken,
          'client_id': clientId,
        },
      );

      if (response.statusCode != 200) {
        if (response.statusCode == 400) {
          clearToken();
        }
        onAuthRefreshError?.call();
        throw NetworkError(
          'Failed to refresh token.',
          statusCode: response.statusCode,
          responseBody: response.body,
        );
      }

      timeLocal = (timeLocal + DateTime.now().millisecondsSinceEpoch) ~/ 2;

      final json = jsonDecode(response.body) as Map<String, dynamic>;

      setToken(
        json['access_token'] as String,
        json['refresh_token'] as String?,
        json['id_token'] as String?,
        timeLocal,
      );

      onAuthRefreshSuccess?.call();

      // Resolve all queued completers.
      final queue = List.of(_refreshQueue);
      _refreshQueue.clear();
      for (final c in queue) {
        c.complete(true);
      }
    } catch (error) {
      // Reject all queued completers.
      final queue = List.of(_refreshQueue);
      _refreshQueue.clear();
      for (final c in queue) {
        c.completeError(error);
      }
    }
  }

  /// Clear authentication state.
  void clearToken() {
    if (token != null) {
      setToken();
      onAuthLogout?.call();
      if (loginRequired) {
        login();
      }
    }
  }

  /// Set the token state.
  void setToken([
    String? accessToken,
    String? newRefreshToken,
    String? newIdToken,
    int? timeLocal,
  ]) {
    if (newRefreshToken != null) {
      refreshToken = newRefreshToken;
      refreshTokenParsed = decodeToken(newRefreshToken);
    } else {
      refreshToken = null;
      refreshTokenParsed = null;
    }

    if (newIdToken != null) {
      idToken = newIdToken;
      idTokenParsed = decodeToken(newIdToken);
    } else {
      idToken = null;
      idTokenParsed = null;
    }

    if (accessToken != null) {
      token = accessToken;
      tokenParsed = decodeToken(accessToken);
      sessionId = tokenParsed!.sid;
      authenticated = true;
      subject = tokenParsed!.sub;
      realmAccess = tokenParsed!.realmAccess;
      resourceAccess = tokenParsed!.resourceAccess;

      if (timeLocal != null) {
        timeSkew =
            (timeLocal / 1000).floor() - (tokenParsed!.iat ?? 0);
      }
    } else {
      token = null;
      tokenParsed = null;
      subject = null;
      realmAccess = null;
      resourceAccess = null;
      authenticated = false;
    }
  }

  /// Get the realm URL.
  String? getRealmUrl() {
    if (authServerUrl == null) return null;
    final url = _stripTrailingSlash(authServerUrl!);
    return '$url/realms/${Uri.encodeComponent(realm!)}';
  }

  /// Load configuration from the provided config object.
  Future<void> _loadConfig() async {
    if (_config is String) {
      final response = await _httpClient.get(
        Uri.parse(_config as String),
        headers: {'Accept': 'application/json'},
      );

      if (response.statusCode != 200) {
        throw Exception('Failed to load adapter configuration.');
      }

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      authServerUrl = json['auth-server-url'] as String?;
      realm = json['realm'] as String?;
      clientId = json['resource'] as String?;
      _setupEndpoints();
    } else if (_config is KeycloakServerConfig) {
      final config = _config as KeycloakServerConfig;
      clientId = config.clientId;
      authServerUrl = config.url;
      realm = config.realm;
      _setupEndpoints();
    } else if (_config is GenericOidcConfig) {
      final config = _config as GenericOidcConfig;
      clientId = config.clientId;
      await _loadOidcConfig(config.oidcProvider);
    }
  }

  void _setupEndpoints() {
    final realmUrl = getRealmUrl()!;
    endpoints = Endpoints(
      authorize: () => '$realmUrl/protocol/openid-connect/auth',
      token: () => '$realmUrl/protocol/openid-connect/token',
      logout: () => '$realmUrl/protocol/openid-connect/logout',
      checkSessionIframe: () =>
          '$realmUrl/protocol/openid-connect/login-status-iframe.html',
      register: () => '$realmUrl/protocol/openid-connect/registrations',
      userinfo: () => '$realmUrl/protocol/openid-connect/userinfo',
    );
  }

  Future<void> _loadOidcConfig(Object oidcProvider) async {
    if (oidcProvider is String) {
      final url =
          '${_stripTrailingSlash(oidcProvider)}/.well-known/openid-configuration';
      final response = await _httpClient.get(
        Uri.parse(url),
        headers: {'Accept': 'application/json'},
      );

      if (response.statusCode != 200) {
        throw Exception('Failed to load OpenID configuration.');
      }

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final metadata = OpenIdProviderMetadata.fromJson(json);
      _setupOidcEndpoints(metadata);
    } else if (oidcProvider is OpenIdProviderMetadata) {
      _setupOidcEndpoints(oidcProvider);
    }
  }

  void _setupOidcEndpoints(OpenIdProviderMetadata config) {
    endpoints = Endpoints(
      authorize: () => config.authorizationEndpoint,
      token: () => config.tokenEndpoint,
      logout: () {
        if (config.endSessionEndpoint == null) {
          throw StateError('Not supported by the OIDC server');
        }
        return config.endSessionEndpoint!;
      },
      checkSessionIframe: () {
        if (config.checkSessionIframe == null) {
          throw StateError('Not supported by the OIDC server');
        }
        return config.checkSessionIframe!;
      },
      register: () {
        throw StateError(
          'Redirection to "Register user" page not supported '
          'in standard OIDC mode',
        );
      },
      userinfo: () {
        if (config.userinfoEndpoint == null) {
          throw StateError('Not supported by the OIDC server');
        }
        return config.userinfoEndpoint!;
      },
    );
  }

  // Callback parsing

  /// Parse an OAuth callback from a URL string.
  ///
  /// Returns null if the URL does not contain valid OAuth callback parameters.
  OAuthCallbackParams? parseCallback(String url) {
    final oauth = parseCallbackUrl(url);
    if (oauth == null) return null;

    final oauthState = _callbackStorage.get(oauth.state);
    if (oauthState != null) {
      return oauth.copyWith(
        valid: true,
        redirectUri: oauthState.redirectUri,
        storedNonce: oauthState.nonce,
        prompt: oauthState.prompt,
        pkceCodeVerifier: oauthState.pkceCodeVerifier,
        loginOptions: oauthState.loginOptions,
      );
    }

    return oauth;
  }

  /// Parse the OAuth parameters from a callback URL.
  OAuthCallbackParams? parseCallbackUrl(String urlString) {
    List<String> supportedParams;

    switch (flow) {
      case KeycloakFlow.standard:
        supportedParams = [
          'code',
          'state',
          'session_state',
          'kc_action_status',
          'kc_action',
          'iss',
        ];
        break;
      case KeycloakFlow.implicit:
        supportedParams = [
          'access_token',
          'token_type',
          'id_token',
          'state',
          'session_state',
          'expires_in',
          'kc_action_status',
          'kc_action',
          'iss',
        ];
        break;
      case KeycloakFlow.hybrid:
        supportedParams = [
          'access_token',
          'token_type',
          'id_token',
          'code',
          'state',
          'session_state',
          'expires_in',
          'kc_action_status',
          'kc_action',
          'iss',
        ];
        break;
    }

    supportedParams.addAll(['error', 'error_description', 'error_uri']);

    final uri = Uri.parse(urlString);
    ParsedCallbackParams? parsed;
    String newUrl = '';

    if (responseMode == KeycloakResponseMode.query &&
        uri.query.isNotEmpty) {
      parsed = parseCallbackParams(uri.query, supportedParams);
      final newUri = uri.replace(query: parsed.paramsString);
      newUrl = newUri.toString();
    } else if (responseMode == KeycloakResponseMode.fragment &&
        uri.fragment.isNotEmpty) {
      parsed = parseCallbackParams(uri.fragment, supportedParams);
      final cleanFragment = parsed.paramsString;
      newUrl = uri.removeFragment().toString();
      if (cleanFragment.isNotEmpty) {
        newUrl = '$newUrl#$cleanFragment';
      }
    }

    if (parsed?.oauthParams != null) {
      final p = parsed!.oauthParams;

      if (flow == KeycloakFlow.standard || flow == KeycloakFlow.hybrid) {
        if ((p.containsKey('code') || p.containsKey('error')) &&
            p.containsKey('state')) {
          return _oauthParamsToCallback(p, newUrl);
        }
      } else if (flow == KeycloakFlow.implicit) {
        if ((p.containsKey('access_token') || p.containsKey('error')) &&
            p.containsKey('state')) {
          return _oauthParamsToCallback(p, newUrl);
        }
      }
    }

    return null;
  }

  /// Parse OAuth parameters from a query string or fragment.
  static ParsedCallbackParams parseCallbackParams(
    String paramsString,
    List<String> supportedParams,
  ) {
    final params = paramsString.split('&').reversed.toList();
    final oauthParams = <String, String>{};
    final remaining = <String>[];

    for (final param in params) {
      if (param.isEmpty) {
        remaining.insert(0, '');
        continue;
      }

      final eqIdx = param.indexOf('=');
      final key = eqIdx >= 0
          ? Uri.decodeComponent(param.substring(0, eqIdx))
          : param;
      final rawValue = eqIdx >= 0 ? param.substring(eqIdx + 1) : '';
      final value = Uri.decodeComponent(rawValue.replaceAll('+', '%20'));

      if (supportedParams.contains(key) && !oauthParams.containsKey(key)) {
        oauthParams[key] = value;
      } else {
        remaining.insert(0, param);
      }
    }

    return ParsedCallbackParams(
      paramsString: remaining.join('&'),
      oauthParams: oauthParams,
    );
  }

  static OAuthCallbackParams _oauthParamsToCallback(
    Map<String, String> p,
    String newUrl,
  ) {
    return OAuthCallbackParams(
      code: p['code'],
      error: p['error'],
      errorDescription: p['error_description'],
      errorUri: p['error_uri'],
      state: p['state'],
      sessionState: p['session_state'],
      accessToken: p['access_token'],
      tokenType: p['token_type'],
      idToken: p['id_token'],
      expiresIn: p['expires_in'],
      kcActionStatus: p['kc_action_status'],
      kcAction: p['kc_action'],
      iss: p['iss'],
      newUrl: newUrl,
    );
  }

  /// Process a parsed OAuth callback, exchanging codes for tokens.
  Future<void> processCallback(OAuthCallbackParams oauth) async {
    final code = oauth.code;
    final error = oauth.error;
    final prompt = oauth.prompt;
    var timeLocal = DateTime.now().millisecondsSinceEpoch;

    void authSuccess(String accessToken, String? refreshTkn, String? idTkn) {
      timeLocal = (timeLocal + DateTime.now().millisecondsSinceEpoch) ~/ 2;

      setToken(accessToken, refreshTkn, idTkn, timeLocal);

      if (_useNonce &&
          idTokenParsed != null &&
          idTokenParsed!.nonce != oauth.storedNonce) {
        _logInfo('Invalid nonce, clearing token');
        clearToken();
        throw StateError('Invalid nonce.');
      }
    }

    if (oauth.kcActionStatus != null) {
      onActionUpdate?.call(oauth.kcActionStatus!, oauth.kcAction);
    }

    if (error != null) {
      if (prompt != 'none') {
        if (oauth.errorDescription == 'authentication_expired') {
          await login(oauth.loginOptions);
        } else {
          final errorData = KeycloakError(
            error: error,
            errorDescription: oauth.errorDescription ?? '',
          );
          onAuthError?.call(errorData);
          throw errorData;
        }
      }
      return;
    } else if (flow != KeycloakFlow.standard &&
        (oauth.accessToken != null || oauth.idToken != null)) {
      authSuccess(oauth.accessToken!, null, oauth.idToken);
      onAuthSuccess?.call();
    }

    if (flow != KeycloakFlow.implicit && code != null) {
      try {
        final response = await fetchAccessToken(
          endpoints!.token(),
          code,
          clientId!,
          oauth.redirectUri ?? '',
          oauth.pkceCodeVerifier,
        );

        authSuccess(
          response['access_token'] as String,
          response['refresh_token'] as String?,
          response['id_token'] as String?,
        );

        if (flow == KeycloakFlow.standard) {
          onAuthSuccess?.call();
        }
      } catch (e) {
        onAuthError?.call(null);
        rethrow;
      }
    }
  }

  /// Exchange an authorization code for tokens at the token endpoint.
  Future<Map<String, dynamic>> fetchAccessToken(
    String tokenUrl,
    String code,
    String clientId,
    String redirectUri, [
    String? pkceCodeVerifier,
  ]) async {
    final body = <String, String>{
      'grant_type': 'authorization_code',
      'code': code,
      'client_id': clientId,
      'redirect_uri': redirectUri,
    };

    if (pkceCodeVerifier != null) {
      body['code_verifier'] = pkceCodeVerifier;
    }

    final response = await _httpClient.post(
      Uri.parse(tokenUrl),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: body,
    );

    if (response.statusCode != 200) {
      throw NetworkError(
        'Failed to exchange authorization code.',
        statusCode: response.statusCode,
        responseBody: response.body,
      );
    }

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Build an authorization header value from the current token.
  String? buildAuthorizationHeader() {
    if (token == null) return null;
    return 'Bearer $token';
  }

  void _logInfo(String message) {
    if (enableLogging) {
      // ignore: avoid_print
      print('[KEYCLOAK] $message');
    }
  }

  // Utility functions

  static String _createUUID() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));

    // Set version 4
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    final hex = bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();

    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
        '${hex.substring(12, 16)}-${hex.substring(16, 20)}-'
        '${hex.substring(20)}';
  }

  static String _buildClaimsParameter(Acr requestedAcr) {
    return jsonEncode({
      'id_token': {
        'acr': requestedAcr.toJson(),
      },
    });
  }

  static String _generateCodeVerifier(int length) {
    const alphabet =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random.secure();
    return String.fromCharCodes(
      List.generate(
        length,
        (_) => alphabet.codeUnitAt(random.nextInt(alphabet.length)),
      ),
    );
  }

  static Future<String> _generatePkceChallenge(
    KeycloakPkceMethod method,
    String codeVerifier,
  ) async {
    if (method != KeycloakPkceMethod.s256) {
      throw ArgumentError(
        "Invalid value for 'pkceMethod', expected 'S256'.",
      );
    }

    final bytes = utf8.encode(codeVerifier);
    final digest = crypto_lib.sha256.convert(bytes);
    final encoded = base64Url.encode(digest.bytes).replaceAll('=', '');

    return encoded;
  }

  static String _stripTrailingSlash(String url) {
    return url.endsWith('/') ? url.substring(0, url.length - 1) : url;
  }

  void _scheduleTokenExpiry() {
    if (tokenParsed?.exp == null || timeSkew == null) return;

    final expiresIn = tokenParsed!.exp! -
        (DateTime.now().millisecondsSinceEpoch / 1000).ceil() +
        timeSkew!;

    if (expiresIn > 0) {
      Future.delayed(Duration(seconds: expiresIn), () {
        onTokenExpired?.call();
      });
    }
  }
}

/// Default adapter that stores redirect URIs without performing
/// actual browser redirects (suitable for non-browser environments).
class _DefaultAdapter implements KeycloakAdapter {
  final Keycloak _keycloak;

  _DefaultAdapter(this._keycloak);

  @override
  Future<void> login([KeycloakLoginOptions? options]) async {
    // In a real browser environment, this would redirect.
    // For non-browser usage, the URL can be obtained via createLoginUrl.
  }

  @override
  Future<void> logout([KeycloakLogoutOptions? options]) async {
    // In a real browser environment, this would redirect.
  }

  @override
  Future<void> register([KeycloakRegisterOptions? options]) async {
    // In a real browser environment, this would redirect.
  }

  @override
  Future<void> accountManagement() async {
    // In a real browser environment, this would redirect.
  }

  @override
  String redirectUri([KeycloakRedirectUriOptions? options]) {
    return options?.redirectUri ?? _keycloak.redirectUri ?? '';
  }
}
