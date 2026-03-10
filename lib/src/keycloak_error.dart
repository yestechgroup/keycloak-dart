/// Represents an error response from Keycloak.
class KeycloakError {
  /// The error code.
  final String error;

  /// A human-readable description of the error.
  final String errorDescription;

  const KeycloakError({
    required this.error,
    required this.errorDescription,
  });

  factory KeycloakError.fromJson(Map<String, dynamic> json) {
    return KeycloakError(
      error: json['error'] as String,
      errorDescription: json['error_description'] as String,
    );
  }

  Map<String, String> toJson() => {
        'error': error,
        'error_description': errorDescription,
      };

  @override
  String toString() => 'KeycloakError($error: $errorDescription)';
}
