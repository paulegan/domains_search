import time
import pickle
import socket
import argparse
import itertools
import dns.resolver
import whois
from progress.bar import IncrementalBar


name_parts = [
    'ka', 'ki', 'ku', 'ke', 'ko',
    'sa', 'shi', 'su', 'se', 'so', 'sha', 'shu', 'sho',
    'ta', 'chi', 'te', 'to',  'cha', 'chu', 'cho',
    'na', 'ni', 'nu', 'ne', 'no',
    'ha', 'hi', 'fu', 'he', 'ho',
    'ma', 'mi', 'mu', 'me', 'mo',
    'ya', 'yu', 'yo',
    'ra', 'ri', 'ru', 're', 'ro',
]

checked = {
    'exists': {},
    'available': {},
}


class ProgressBar(IncrementalBar):
    message = 'Checking'
    suffix = '%(index)d/%(max)d available=%(available)d remaining=%(remaining_minutes)dmin'
    available = 0

    @property
    def remaining_minutes(self):
        return self.eta // 60


def domain_exists(name):
    try:
        socket.gethostbyname(name + '.')
    except OSError:
        # Really doesn't exist? Check for an SOA record:
        try:
            dns.resolver.query(name + '.', 'SOA')
        except dns.exception.DNSException:
            # Really, really doesn't exist? Check whois:
            try:
                assert(whois.query(name))
            except (whois.exceptions.FailedParsingWhoisOutput, whois.exceptions.UnknownDateFormat):
                # record exists, but perhaps not recorded correctly
                pass
            except AssertionError:
                return False
    return True


def get_name_cominations(r):
    for combo in itertools.combinations(name_parts, r):
        yield ''.join(combo)


def check_domain_names(prefix='', suffix='', r=2, tld='.com'):
    all_combos = list(get_name_cominations(r))
    with ProgressBar() as progressbar:
        for root in progressbar.iter(all_combos):
            name = ''.join((prefix, root, suffix, tld))
            if name in checked['exists']:
                continue
            time.sleep(0)
            if domain_exists(name):
                checked['exists'][name] = True
            else:
                checked['available'][name] = True
                progressbar.available += 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--combo-length', dest='r', type=int, default=3)
    parser.add_argument('--suffix', default='')
    parser.add_argument('--prefix', default='')
    parser.add_argument('--tld', default='.com')
    parser.add_argument('--cachefile', default='kana_domains.cache')
    args = parser.parse_args()

    try:
        with open(args.cachefile, 'rb') as f:
            checked.update(pickle.load(f))
    except FileNotFoundError:
        pass

    try:
        check_domain_names(prefix=args.prefix, suffix=args.suffix, r=args.r, tld=args.tld)
    except KeyboardInterrupt:
        pass
    except BaseException:
        raise
    finally:
        with open(args.cachefile, 'wb') as f:
            pickle.dump(checked, f)

    print('\n'.join(sorted(checked['available'])))
