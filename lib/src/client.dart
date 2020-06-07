import 'package:meta/meta.dart';
import 'package:http/http.dart';

import 'base_client.dart';
import 'sigv4.dart';


/// A client that stores secrets and configuration for AWS requests
/// signed with Signature Version 4. Required the following parameters:
/// - `keyId`: Your access key ID
/// - `accessKey`: Your secret access key
class Sigv4Client implements BaseSigv4Client {
  static const x_amz_date_key = 'x-amz-date';
  static const x_amz_target_key = 'x-amz-target';
  static const x_amz_security_token_key = 'x-amz-security-token';
  static const x_amz_content_sha256_key = 'x-amz-content-sha256';
  static const host_key = 'host';
  static const authorization_key = 'Authorization';
  static const content_encoding_key = 'content-encoding';
  static const content_type_key = 'content-type';
  static const content_type_default_val = 'application/json; charset=utf-8';
  static const content_encoding_default_val = 'amz-1.0';
  static const target_default_val = 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.SearchItems';
  static const chunked_val = 'aws-chunked';
  static const unsigned_payload_val = 'UNSIGNED-PAYLOAD';
  static const chunked_payload_val = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD';
  /// The region of the service(s) to be called.
  String region;

  /// Your access key ID
  String keyId;

  /// Your secret access key
  String accessKey;

  /// An optional session token
  String sessionToken;

  /// The name of the service to be called.
  /// E.g. `s3`, `execute-api` etc.
  String serviceName;

  /// The default `Content-Type` header value.
  /// Defaults to `application/json`
  String defaultContentType;

  Sigv4Client({
    @required this.keyId,
    @required this.accessKey,
    @required this.serviceName,
    @required this.region,
    this.sessionToken,
    this.defaultContentType = content_type_default_val
  })  : assert(keyId != null),
        assert(accessKey != null);

  /// Returns the path with encoded, canonical query parameters.
  /// This is __required__ by AWS.
  @override
  String canonicalUrl(String path, {Map<String, dynamic> query}) {
    return _generateUrl(path, query: query);
  }

  /// Generates SIGV4-signed headers.
  /// - `path`: The complete path of your request
  /// - `method`: The HTTP verb your request is using
  /// - `query`: Query parameters, if any. __required__ to be included if used
  /// - `headers`: Any additional headers. **DO NOT** add headers to your request after generating signed headers
  /// - `body`: An *encodable* object
  /// - `dateTime`: An AWS-compatible time string. You'll probably want to leave it blank.
  /// - `encoding`: The payload encoding. if any
  /// - `signPayload`: If the optional payload should be signed or unsigned
  @override
  Map<String, String> signedHeaders(
    String path, {
    String method = 'GET',
    Map<String, dynamic> query,
    Map<String, dynamic> headers,
    String body,
    String dateTime,
    String encoding,
    bool signPayload = true,
    bool chunked = false,
  }) {
    /// Split the URI into segments
    final parsedUri = Uri.parse(path);

    /// The endpoint used
    final baseUrl = '${parsedUri.scheme}://${parsedUri.host}';

    path = parsedUri.path;

    /// Format the `method` correctly
    method = method.toUpperCase();
    headers ??= {};

    if (encoding != null) {
      headers[content_encoding_key] = encoding;
    }
    else {
      headers[content_encoding_key] = content_encoding_default_val;
    }

    if (headers[x_amz_target_key] == null) {
      headers[x_amz_target_key] = target_default_val;
    }

    /// Set the `Content-Type header`
    if (headers[content_type_key] == null) {
      headers[content_type_key] = defaultContentType;
    }

    /// Set the `body`, if any
    if (body == null || method == 'GET') {
      body = '';
    }

    headers[x_amz_content_sha256_key] =
        signPayload ? Sigv4.hashPayload(body) : unsigned_payload_val;

    if (body == '') {
      headers.remove(content_type_key);
    }

    if (chunked) {
      headers[content_encoding_key] = chunked_val;
    }

    /// Sets or generate the `dateTime` parameter needed for the signature
    dateTime ??= Sigv4.generateDatetime();
    headers[x_amz_date_key] = dateTime;

    /// Sets the `host` header
    final baseUri = Uri.parse(baseUrl);
    headers[host_key] = baseUri.host;

    if (headers.containsKey(content_encoding_key) &&
        headers[content_encoding_key] == chunked_val) {
      headers[x_amz_content_sha256_key] = chunked_payload_val;
    }

    /// Generates the `Authorization` headers
    headers[authorization_key] = _generateAuthorization(
      method: method,
      path: path,
      query: query,
      headers: headers,
      body: body,
      dateTime: dateTime,
    );

    /// Adds the `x-amz-security-token` header if a session token is present
    if (sessionToken != null) {
      headers[x_amz_security_token_key] = sessionToken;
    }

    // Return only string values
    return headers.cast<String, String>();
  }

  /// A wrapper that generates both the canonical path and
  /// signed headers and returns a [Request] object from [package:http](https://pub.dev/packages/http)
  /// - `path`: The complete path of your request
  /// - `method`: The HTTP verb your request is using
  /// - `query`: Query parameters, if any. __required__ to be included if used
  /// - `headers`: Any additional headers. **DO NOT** add headers to your request after generating signed headers
  /// - `body`: An *encodable* object
  /// - `dateTime`: An AWS-compatible time string. You'll probably want to leave it blank.
  /// - `encoding`: The payload encoding. if any
  /// - `signPayload`: If the optional payload should be signed or unsigned
  @override
  Request request(
    String path, {
    String method = 'GET',
    Map<String, dynamic> query,
    Map<String, dynamic> headers,
    String body,
    String dateTime,
    String encoding,
    bool signPayload = true,
  }) {
    /// Converts the path to a canonical path
    path = canonicalUrl(path, query: query);
    var request = Request(method, Uri.parse(path));

    final signed = signedHeaders(
      path,
      method: method,
      query: query,
      headers: headers,
      body: body,
      dateTime: dateTime,
      signPayload: signPayload,
      encoding: encoding,
    );

    /// Adds the signed headers to the request
    request.headers.addAll(signed);

    /// Adds the body to the request
    if (body != null) {
      request.body = body;
    }

    return request;
  }

  String _generateUrl(String path, {Map<String, dynamic> query}) {
    var url = '$path';
    if (query != null) {
      final queryString = Sigv4.buildCanonicalQueryString(query);
      if (queryString != '') {
        url += '?$queryString';
      }
    }
    return url;
  }

  String _generateAuthorization({
    String method,
    String path,
    Map<String, dynamic> query,
    Map<String, dynamic> headers,
    String body,
    String dateTime,
  }) {
    final canonicalRequest =
        Sigv4.buildCanonicalRequest(method, path, query, headers, body);
    final hashedCanonicalRequest = Sigv4.hashPayload(canonicalRequest);
    final credentialScope =
        Sigv4.buildCredentialScope(dateTime, region, serviceName);
    final stringToSign = Sigv4.buildStringToSign(
        dateTime, credentialScope, hashedCanonicalRequest);
    final signingKey =
        Sigv4.calculateSigningKey(accessKey, dateTime, region, serviceName);
    final signature = Sigv4.calculateSignature(signingKey, stringToSign);
    return Sigv4.buildAuthorizationHeader(
        keyId, credentialScope, headers, signature);
  }
}
