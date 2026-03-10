/// An error that occurs during network requests.
///
/// Contains the HTTP response that caused the error, if available.
class NetworkError implements Exception {
  /// A message describing the error.
  final String message;

  /// The HTTP status code, if available.
  final int? statusCode;

  /// The response body, if available.
  final String? responseBody;

  const NetworkError(
    this.message, {
    this.statusCode,
    this.responseBody,
  });

  @override
  String toString() => 'NetworkError: $message';
}
