#!/usr/bin/env python3
"""Portable C2Hunter allowlisted API client (Python >= 3.10).

Successful requests: JSON on stdout. Failures: fixed JSON on stderr, nonzero
exit. No credentials are accepted as arguments or read from credential files.
"""
import argparse
from datetime import datetime
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit


class ClientError(Exception):
    def __init__(self, code, status=None, unknown=False):
        self.code, self.status, self.unknown = code, status, unknown

    def payload(self):
        return {'error': self.code, 'http_status': self.status,
                'write_outcome_unknown': self.unknown}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ClientError('CLI_ERROR')


def arguments(argv):
    parser = Parser(prog='client.py', description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    describe = commands.add_parser('describe', allow_abbrev=False)
    describe.add_argument('operation', nargs='?')
    request = commands.add_parser('request', allow_abbrev=False)
    request.add_argument('operation')
    request.add_argument('--param', action='append', default=[])
    request.add_argument('--query', action='append', default=[])
    request.add_argument('--json')
    request.add_argument('--binary')
    request.add_argument('--allow-write', action='store_true')
    request.add_argument('--allow-remote-model', action='store_true')
    request.add_argument('--timeout', type=float, default=10)
    watch = commands.add_parser('watch', allow_abbrev=False)
    watch.add_argument('operation', choices=['job-get', 'ai-get'])
    watch.add_argument('--param', action='append', default=[])
    watch.add_argument('--timeout', type=float, default=10)
    watch.add_argument('--max-polls', type=int, default=20)
    watch.add_argument('--interval', type=float, default=3)
    watch.set_defaults(query=[], json=None, binary=None, allow_write=False, allow_remote_model=False)
    args = parser.parse_args(argv)
    if args.command == 'watch' and (not 1 <= args.max_polls <= 100 or
            not math.isfinite(args.interval) or not 1 <= args.interval <= 3600):
        raise ClientError('CLI_ERROR')
    if args.command != 'describe' and (not math.isfinite(args.timeout) or not 1 <= args.timeout <= 60):
        raise ClientError('CLI_ERROR')
    return args


def load_contract():
    try:
        contract = json.loads((Path(__file__).resolve().parents[1] /
                               'references' / 'operations.json').read_text(encoding='utf-8'))
        if contract['schema_version'] != 1:
            raise ValueError
        return contract
    except (OSError, ValueError, KeyError):
        raise ClientError('CONTRACT_ERROR') from None


def configuration():
    raw = os.environ.get('C2HUNTER_BASE_URL', '')
    token = os.environ.get('C2HUNTER_API_TOKEN', '')
    if not token or len(token) > 8192 or any(not 33 <= ord(c) <= 126 for c in token):
        raise ClientError('CONFIG_ERROR')
    if not raw or len(raw) > 2048 or any(not 33 <= ord(c) <= 126 for c in raw):
        raise ClientError('CONFIG_ERROR')
    if not re.fullmatch(r'https?://(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?', raw, re.I):
        raise ClientError('CONFIG_ERROR')
    try:
        url = urlsplit(raw)
        host, port = url.hostname, url.port
        if (url.scheme not in ('http', 'https') or not host or url.path or
                url.username is not None or url.netloc.endswith(':') or
                (port is not None and not 1 <= port <= 65535)):
            raise ValueError
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            if len(host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                      for label in host.split('.')):
                raise ValueError
            loopback = host.lower() == 'localhost'
        if url.scheme == 'http' and not loopback:
            raise ValueError
        return url, token
    except ValueError:
        raise ClientError('CONFIG_ERROR') from None


def pairs(items, allowed, path=False):
    result = {}
    for item in items:
        key, sep, value = item.partition('=')
        if (not sep or key not in allowed or key in result or not value or
                len(value) > 4096 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
            raise ClientError('INVALID_PARAMETERS')
        if path and (value in ('.', '..') or not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}', value)):
            raise ClientError('INVALID_PARAMETERS')
        result[key] = value
    if path and set(result) != set(allowed):
        raise ClientError('INVALID_PARAMETERS')
    return result


def target_for(args, operation):
    params = pairs(args.param, operation['path_parameters'], path=True)
    query = pairs(args.query, operation['query_parameters'])
    if args.operation == 'baseline-scopes':
        for key, value in query.items():
            low, high = (0, 16) if key == 'offset' else (1, 20)
            if not re.fullmatch(r'0|[1-9][0-9]*', value) or not low <= int(value) <= high:
                raise ClientError('INVALID_PARAMETERS')
    target = operation['path'].format(**params)
    return target + ('?' + urlencode(query) if query else '')


JSON_LIMIT = 1024 * 1024
BINARY_LIMIT = 64 * 1024 * 1024
RESPONSE_LIMIT = 2 * 1024 * 1024


def strict_json(raw):
    def reject_constant(value):
        raise ValueError

    def object_pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    data = json.loads(raw, parse_constant=reject_constant, object_pairs_hook=object_pairs)
    # Also rejects exponent overflow (e.g. 1e999), not only NaN literals.
    json.dumps(data, allow_nan=False)
    return data


def read_body(path, limit, stdin=False):
    try:
        if stdin and path == '-':
            data = sys.stdin.buffer.read(limit + 1)
        else:
            with open(path, 'rb') as stream:
                data = stream.read(limit + 1)
    except (OSError, ValueError):
        raise ClientError('BODY_READ_ERROR') from None
    # Check actual bytes, not a prior stat, to cover files growing during reads.
    if len(data) > limit:
        raise ClientError('BODY_TOO_LARGE')
    return data


def validate_ai(data, args):
    if not isinstance(data.get('idempotency_key'), str) or not 1 <= len(data['idempotency_key']) <= 200:
        raise ClientError('INVALID_BODY')
    defaults = {'candidate_limit': 1, 'allow_remote': False, 'analysis_kind': 'C2',
                'language': 'ko', 'discovery_mode': 'legacy', 'baseline_mode': 'off'}
    for key, value in defaults.items():
        data.setdefault(key, value)
    if type(data['candidate_limit']) is not int or not 1 <= data['candidate_limit'] <= 5:
        raise ClientError('INVALID_BODY')
    if type(data['allow_remote']) is not bool:
        raise ClientError('INVALID_BODY')
    if data['allow_remote'] and not args.allow_remote_model:
        raise ClientError('REMOTE_MODEL_REQUIRES_CONSENT')


def validate_capture(data):
    capture = data.get('capture')
    if not isinstance(capture, dict):
        raise ClientError('INVALID_BODY')
    for key in ('duration_seconds', 'max_packets', 'max_bytes'):
        if type(capture.get(key)) is not int or capture[key] <= 0:
            raise ClientError('INVALID_BODY')
    if capture['duration_seconds'] > 86400:
        raise ClientError('INVALID_BODY')
    try:
        # Python 3.10 lacks fromisoformat's Z support.
        start = datetime.fromisoformat(data['start_time'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(data['end_time'].replace('Z', '+00:00'))
        if start.tzinfo is None or end.tzinfo is None or start >= end:
            raise ValueError
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ClientError('INVALID_BODY') from None


def body_for(args, operation):
    kind = operation['body']
    if kind == 'none':
        if args.json is not None or args.binary is not None:
            raise ClientError('INVALID_BODY')
        return None, None
    if kind == 'binary':
        if args.binary is None or args.json is not None:
            raise ClientError('INVALID_BODY')
        return read_body(args.binary, BINARY_LIMIT), 'application/octet-stream'
    if args.json is None or args.binary is not None:
        raise ClientError('INVALID_BODY')
    try:
        data = strict_json(read_body(args.json, JSON_LIMIT, stdin=True))
        if not isinstance(data, dict):
            raise ValueError
    except (ValueError, RecursionError):
        raise ClientError('INVALID_BODY') from None
    if args.operation == 'ai-create':
        validate_ai(data, args)
    elif args.operation == 'job-create':
        validate_capture(data)
    payload = json.dumps(data, ensure_ascii=True, allow_nan=False).encode('utf-8')
    if len(payload) > JSON_LIMIT:
        raise ClientError('BODY_TOO_LARGE')
    return payload, 'application/json'


def redact(value, token):
    if isinstance(value, str):
        return value.replace(token, '[REDACTED]')
    if isinstance(value, dict):
        return {redact(key, token): redact(item, token) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, token) for item in value]
    if token in json.dumps(value, allow_nan=False):
        return '[REDACTED]'
    return value


def response_body(response, sock, deadline):
    lengths = response.headers.get_all('Content-Length', [])
    length = None
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r'[0-9]+', lengths[0]):
            raise ClientError('INVALID_RESPONSE')
        length = int(lengths[0])
        if length > RESPONSE_LIMIT:
            raise ClientError('RESPONSE_TOO_LARGE')
    encoding = response.getheader('Content-Encoding')
    if encoding not in (None, 'identity'):
        raise ClientError('INVALID_RESPONSE')
    parts = bytearray()
    while not response.isclosed():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ClientError('NETWORK_ERROR')
        sock.settimeout(remaining)
        part = response.read1(min(65536, RESPONSE_LIMIT + 1 - len(parts)))
        if not part:
            break
        parts.extend(part)
        if len(parts) > RESPONSE_LIMIT:
            raise ClientError('RESPONSE_TOO_LARGE')
    if length is not None and len(parts) != length:
        raise ClientError('INVALID_RESPONSE')
    try:
        return strict_json(parts)
    except (ValueError, RecursionError):
        raise ClientError('INVALID_RESPONSE') from None


def request(url, token, operation, target, timeout, body=None, content_type=None):
    # Direct stdlib connections: no proxies, redirects, cookies or retries.
    if url.scheme == 'https':
        # Explicit verified context avoids SSLKEYLOGFILE's ambient file writes.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        connection = http.client.HTTPSConnection(url.hostname, url.port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=timeout)
    status = None
    response = None
    timer = None
    dispatched = False
    failure = None
    cleanup_failed = False

    def cleanup(action):
        nonlocal cleanup_failed
        try:
            action()
        except Exception:
            # Secondary failures must not replace the primary outcome or stop
            # cleanup of the other owned resources. Never retain exception text.
            cleanup_failed = True

    # getresponse() itself calls close() for Connection: close responses before
    # returning their status. Protect that cleanup boundary as well as finally.
    original_close = connection.close
    connection.close = lambda: cleanup(original_close)
    deadline = time.monotonic() + timeout
    try:
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
                   'Connection': 'close'}
        if content_type:
            headers['Content-Type'] = content_type
        # Stdlib DNS resolution is not cancellable; this is not a hard DNS deadline.
        connection.connect()
        sock = connection.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ClientError('NETWORK_ERROR')
        sock.settimeout(remaining)

        def expire():
            # Also interrupt trickling header/chunk-metadata readline loops.
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        # Once request() starts sending, a transport failure cannot prove that
        # the mutation was rejected. Connect/setup failures are still preflight.
        dispatched = True
        connection.request(operation['method'], target, body=body, headers=headers)
        response = connection.getresponse()
        if time.monotonic() >= deadline:
            raise ClientError('NETWORK_ERROR')
        status = response.status
        if 300 <= status < 400:
            raise ClientError('REDIRECT_REFUSED')
        if not 200 <= status < 300:
            raise ClientError('HTTP_ERROR')
        data = redact(response_body(response, sock, deadline), token)
        if time.monotonic() >= deadline:
            raise ClientError('NETWORK_ERROR')
    except ClientError as error:
        failure = error.code
    except Exception:
        failure = 'NETWORK_ERROR'
    finally:
        if timer is not None:
            cleanup(timer.cancel)
            cleanup(timer.join)
        if response is not None:
            cleanup(response.close)
        connection.close()
    if failure is not None or cleanup_failed:
        unknown = (dispatched and operation['write'] and
                   not (status is not None and 400 <= status < 500))
        raise ClientError('WRITE_OUTCOME_UNKNOWN' if unknown else (failure or 'NETWORK_ERROR'),
                          status, unknown) from None
    return {'status': status, 'data': data}


def watch(args, contract, url, token, operation, target):
    terminal = contract['terminal_states'][args.operation]
    safe_states = {'QUEUED', 'PENDING', 'RUNNING', 'VALIDATING', 'DISPATCHING',
                   'CAPTURING', 'PROCESSING', 'ANALYZING', 'CANCELLING',
                   'CREATED', 'WAITING_FOR_SENSOR', 'UPLOADING', 'INGESTING', 'PREPARING',
                   'COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED'}
    exits = {'PARTIALLY_COMPLETED': 3, 'FAILED': 4, 'CANCELLED': 5, 'INCOMPLETE': 6}
    for poll in range(1, args.max_polls + 1):
        result = request(url, token, operation, target, args.timeout)
        data = result['data']
        if not isinstance(data, dict) or not isinstance(data.get('status'), str):
            raise ClientError('INVALID_RESPONSE', result['status'])
        state = data['status']
        if state == 'COMPLETED' and state in terminal:
            return dict(result, state=state, polls=poll), 0
        if state in terminal or poll == args.max_polls:
            code = state if state in terminal and state in exits else 'INCOMPLETE'
            failure = ClientError(code, result['status']).payload()
            failure['polls'] = poll
            if state in safe_states:
                failure['state'] = state
            return failure, exits[code]
        time.sleep(args.interval)
    raise ClientError('CLIENT_ERROR')


def main(argv=None):
    publication_failure = ClientError('CLIENT_ERROR')
    try:
        exit_code = 0
        args = arguments(argv)
        contract = load_contract()
        if args.command == 'describe' and args.operation is None:
            result = contract
        else:
            if args.operation not in contract['operations']:
                raise ClientError('INVALID_OPERATION')
            operation = contract['operations'][args.operation]
            if args.command == 'describe':
                result = operation
            else:
                if operation['write'] and not args.allow_write:
                    raise ClientError('WRITE_REQUIRES_ALLOW_WRITE')
                target = target_for(args, operation)
                body, content_type = body_for(args, operation)
                url, token = configuration()
                if args.command == 'watch':
                    result, exit_code = watch(args, contract, url, token, operation, target)
                    publication_failure = ClientError('CLIENT_ERROR', result.get('status', result.get('http_status')))
                else:
                    result = request(url, token, operation, target, args.timeout, body, content_type)
                    # Only a returned receipt establishes this publication context;
                    # preflight/transport errors retain their own classification.
                    publication_failure = ClientError(
                        'WRITE_OUTCOME_UNKNOWN' if operation['write'] else 'CLIENT_ERROR',
                        result['status'], operation['write'])
        # Flush here, not at interpreter shutdown: even a small buffered receipt
        # must report output failure while its dispatch/status context is alive.
        print(json.dumps(result, ensure_ascii=True, allow_nan=False),
              file=sys.stdout if exit_code == 0 else sys.stderr, flush=True)
        return exit_code
    except ClientError as error:
        print(json.dumps(error.payload()), file=sys.stderr, flush=True)
        return 2
    except Exception:
        # Never publish exception text, input arguments, URLs, or response bodies.
        print(json.dumps(publication_failure.payload()), file=sys.stderr, flush=True)
        return 2


if __name__ == '__main__':
    exit_code = main()
    try:
        sys.stdout.flush()
    except OSError:
        # Only the CLI owns stdout. Prevent shutdown from retrying a failed
        # buffered write and appending a traceback to the sanitized diagnostic.
        # In-process main() callers retain their stream and descriptor unchanged.
        with open(os.devnull, 'w') as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
    raise SystemExit(exit_code)
