import 'dart:convert';

import 'package:http/http.dart' as http;

import 'keycloak.dart';

/// Authorization request for UMA protocol.
class AuthorizationRequest {
  /// An array of objects representing the resource and scopes.
  final List<ResourcePermission>? permissions;

  /// A permission ticket obtained from a resource server.
  final String? ticket;

  /// Whether the server should create permission requests.
  final bool? submitRequest;

  /// Additional information about this authorization request.
  final AuthorizationRequestMetadata? metadata;

  /// Whether this request should include the current RPT.
  final bool? incrementalAuthorization;

  const AuthorizationRequest({
    this.permissions,
    this.ticket,
    this.submitRequest,
    this.metadata,
    this.incrementalAuthorization,
  });
}

/// Metadata for an authorization request.
class AuthorizationRequestMetadata {
  /// Whether resource names should be included in the RPT's permissions.
  final bool? responseIncludeResourceName;

  /// Defines a limit for the amount of permissions an RPT can have.
  final int? responsePermissionsLimit;

  const AuthorizationRequestMetadata({
    this.responseIncludeResourceName,
    this.responsePermissionsLimit,
  });
}

/// A resource permission with id and optional scopes.
class ResourcePermission {
  /// The id or name of a resource.
  final String id;

  /// An array of scope names associated with the resource.
  final List<String>? scopes;

  const ResourcePermission({
    required this.id,
    this.scopes,
  });
}

/// Keycloak Authorization client for UMA protocol.
class KeycloakAuthorization {
  final Keycloak _keycloak;
  final http.Client _httpClient;

  String? rpt;
  String? _rptEndpoint;

  KeycloakAuthorization(
    this._keycloak, {
    http.Client? httpClient,
  }) : _httpClient = httpClient ?? http.Client();

  /// Load the UMA configuration from the server.
  Future<void> _ensureConfig() async {
    if (_rptEndpoint != null) return;

    final realmUrl = _keycloak.getRealmUrl();
    if (realmUrl == null) {
      throw Exception(
        'Unable to load authorization config, realm URL not available.',
      );
    }

    final url = '$realmUrl/.well-known/uma2-configuration';
    final response = await _httpClient.get(
      Uri.parse(url),
      headers: {'Accept': 'application/json'},
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to load UMA configuration.');
    }

    final config = jsonDecode(response.body) as Map<String, dynamic>;
    _rptEndpoint = config['token_endpoint'] as String?;
  }

  /// Request authorization with a permission ticket (UMA flow).
  Future<String> authorize(AuthorizationRequest request) async {
    await _ensureConfig();

    if (_rptEndpoint == null) {
      throw Exception('RPT endpoint not configured.');
    }

    final token = _keycloak.token;
    if (token == null) {
      throw Exception('Not authenticated.');
    }

    final params = <String, String>{
      'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
    };

    if (request.ticket != null) {
      params['ticket'] = request.ticket!;
    }

    if (request.incrementalAuthorization == true && rpt != null) {
      params['rpt'] = rpt!;
    }

    if (request.permissions != null) {
      final permStrings = request.permissions!.map((p) {
        if (p.scopes != null && p.scopes!.isNotEmpty) {
          return '${p.id}#${p.scopes!.join(',')}';
        }
        return p.id;
      });
      params['permission'] = permStrings.join(',');
    }

    if (request.metadata != null) {
      if (request.metadata!.responseIncludeResourceName != null) {
        params['response_include_resource_name'] =
            request.metadata!.responseIncludeResourceName.toString();
      }
      if (request.metadata!.responsePermissionsLimit != null) {
        params['response_permissions_limit'] =
            request.metadata!.responsePermissionsLimit.toString();
      }
    }

    final response = await _httpClient.post(
      Uri.parse(_rptEndpoint!),
      headers: {
        'Authorization': 'Bearer $token',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params,
    );

    if (response.statusCode != 200) {
      throw Exception('Authorization request denied.');
    }

    final body = jsonDecode(response.body) as Map<String, dynamic>;
    rpt = body['access_token'] as String?;

    if (rpt == null) {
      throw Exception('No RPT in authorization response.');
    }

    return rpt!;
  }

  /// Obtain entitlements from a resource server.
  Future<String> entitlement(
    String resourceServerId, [
    AuthorizationRequest? request,
  ]) async {
    await _ensureConfig();

    if (_rptEndpoint == null) {
      throw Exception('RPT endpoint not configured.');
    }

    final token = _keycloak.token;
    if (token == null) {
      throw Exception('Not authenticated.');
    }

    final params = <String, String>{
      'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
      'audience': resourceServerId,
    };

    if (request?.permissions != null) {
      final permStrings = request!.permissions!.map((p) {
        if (p.scopes != null && p.scopes!.isNotEmpty) {
          return '${p.id}#${p.scopes!.join(',')}';
        }
        return p.id;
      });
      params['permission'] = permStrings.join(',');
    }

    final response = await _httpClient.post(
      Uri.parse(_rptEndpoint!),
      headers: {
        'Authorization': 'Bearer $token',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params,
    );

    if (response.statusCode != 200) {
      throw Exception('Entitlement request denied.');
    }

    final body = jsonDecode(response.body) as Map<String, dynamic>;
    rpt = body['access_token'] as String?;

    if (rpt == null) {
      throw Exception('No RPT in entitlement response.');
    }

    return rpt!;
  }
}
