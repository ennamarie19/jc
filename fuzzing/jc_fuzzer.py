import contextlib

import atheris
import sys
import io

from fuzz_helpers import EnhancedFuzzedDataProvider

with atheris.instrument_imports():
    import jc

    from jc.lib import parsers
    from jc.exceptions import ParseError, LibraryNotInstalled
    from jc.parsers.tomli import TOMLDecodeError

exception_matches = frozenset({
    'ignore_exceptions', 'Unexpected', 'delimited', 'plist', 'Unterminated', 'Malformed', 'terminating', 'Missing',
    'Invalid'
})
type_exception_matches = frozenset({
    'Input', 'packed_ip', 'ip_string', 'unicode string', 'byte string', '1 arguments',
    'implicit', 'explicit', 'copy', 'convert', 'Asn1Value', 'while constructing',
    'while parsing', '_map', 'positive', 'value must', 'membership', 'asn1crypto', 'datetimes', 'IP', 'CIDR',
    'X.509', 'Unknown', 'Fatal', 'binary'
})
value_exception_matches = frozenset({
    'invalid version', 'address_family', 'ip_string', 'algorithm', 'EncryptionAlgorithm',
    'implicit', 'explicit', 'universal', 'constructed', 'while constructing', 'while parsing',
    'passing a', 'alternative', 'trailing', 'Asn1Value', 'unused', '_map', 'value must', 'positive',
    'arc', 'valid value', 'constructor', 'not set', 'delete', 'definition', 'structure', '_fields',
    'Missing', 'Error', 'timezone', 'UTCTime', 'large', 'Unknown', 'Invalid', 'Compressed', 'Unable',
    'asn1crypto', 'EC', 'DSA', 'must be', 'recursion', 'Insufficient', 'tag', 'pem_bytes',
    'Offset', 'year', 'Comparison', 'supported', 'initialized', 'base', 'single', 'edid',
    'Checksum', 'parse_float', 'enough', 'IPv4'
})
key_exception_matches = frozenset({
    'dictionary is empty', 'definition', 'defined', 'numbered', 'key', 'network_cards', 'wake'
})
overflow_exception_matches = frozenset({'too big'})

# Xrandr has an infinite loop, so we can't fuzz-test it
parsers.remove('xrandr')


@contextlib.contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr


def TestOneInput(data):
    fdp = EnhancedFuzzedDataProvider(data)

    try:
        with nostdout():
            jc.parse(fdp.PickValueInList(parsers), fdp.ConsumeRemainingString(), quiet=True)
    except IndexError:
        return -1
    except AttributeError as e:
        if 'nativeType' in str(e):
            return -1
        raise e
    except KeyError as e:
        if any(ss in str(e) for ss in key_exception_matches):
            return -1
        raise e
    except OverflowError as e:
        if any(ss in str(e) for ss in overflow_exception_matches):
            return -1
        raise e
    except RuntimeError as e:
        if 'xrandr' in str(e):
            return -1
        raise e
    except (ParseError, LibraryNotInstalled, SystemError, TOMLDecodeError, AssertionError):
        return -1
    except TypeError as e:
        if any(ss in str(e) for ss in type_exception_matches):
            return -1
        raise e
    except ValueError as e:
        if any(ss in str(e) for ss in value_exception_matches):
            return -1
        raise e
    except Exception as e:
        if any(ss in str(e) for ss in exception_matches):
            return -1
        raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
