from __future__ import absolute_import

import logging
import json
from pymisp import PyMISP
import re

from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)

_MISP_TO_MINEMELD = {
    'url': 'URL',
    'ip-dst': 'IPv4',
    'ip-src': 'IPv4',
    'ip-dst|port': 'IPv4',
    'ip-src|port': 'IPv4',
    'domain': 'domain',
    'hostname': 'domain',
    'md5': 'md5',
    'sha256': 'sha256',
    'sha1': 'sha1',
    'sha512': 'sha512',
    'ssdeep': 'ssdeep',
    'mutex': 'mutex',
    'filename': 'file.name',
    'email-dst': 'email-addr',
    'email-src': 'email-addr'
}

_ALL_MISP_TYPES = ['url', 'ip-dst', 'ip-src', 'ip-dst|port', 'ip-src|port', 'domain', 'hostname', 'md5', 'sha256', 'sha1', 'sha512', 'ssdeep', 'mutex', 'filename', 'email-src', 'email-dst']

class MISPMiner(BasePollerFT):
    # this method sets all variables required by miner
    # including ones defined in config file
    # returns error if required value wasn't defined in config
    def configure(self):
        super(MISPMiner, self).configure()

        # get MISP credentials from config
        self.verify_cert = self.config.get('verify_cert', False)
        self.misp_url = self.config.get('misp_url', None)
        if self.misp_url is None:
            raise ValueError('%s - MISP URL is required' % self.name)
        self.misp_key = self.config.get('misp_key', None)
        if self.misp_key is None:
            raise ValueError('%s - MISP key is required' % self.name)

        # create MISP object
        self.misp = PyMISP(self.misp_url, self.misp_key, False)

        # get search values
        self.published = self.config.get('published', True)
        self.attr_tag = self.config.get('attr_tag', None)
        if self.attr_tag is None:
            raise ValueError('%s - Attribute teg is required' % self.name)
        self.attr_types = self.config.get('attr_types', _ALL_MISP_TYPES)
        
        # regex for ignored attributes
        self.ignore_regex = self.config.get('ignore_regex', None)
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)
        
        # regex for idicators to be transformed 
        self.indicator_regex = self.config.get('indicator_regex', None)
        if self.indicator_regex is not None:
            self.indicator_regex = re.compile(self.indicator_regex)
            self.indicator_transform = self.config.get('indicator_transform', None)
            if self.indicator_transform is None:
                raise ValueError('%s - indicator_transform is required if indicator_regex given' % self.name)
                
    def _process_item(self, item):
        # called on each item returned by _build_iterator
        # it should return a list of (indicator, value) pairs
        comment = 'timestamp: ' + item['timestamp']
        if 'port' in item['type']:
            values = item['value'].split('|')
            indicator = values[0]
            comment += '\non port: ' + values[1]
        else:
            indicator = item['value']
        try:
            attr_type = _MISP_TO_MINEMELD[item['type']]
        except KeyError:  # should not happen
            return None
        value = {
            'type': attr_type,
            'confidence': 100,
            'comment': comment
        }
        if self.ignore_regex is not None:
            _indicator = self.ignore_regex.search(indicator)
            if _indicator is not None:
                return [[None, None]]
                
        if self.indicator_regex is not None:
            _indicator = self.indicator_regex.search(indicator)
            if _indicator is not None:
                indicator = _indicator.expand(self.indicator_transform)
                
        LOG.error('%s - is being processed', str(indicator))
        return [[indicator, value]]

    def _build_iterator(self, now):
        # called at every polling interval
        # search for attributes by tag and their type and return them as lists
        search_result = self.misp.search(controller='attributes', tags=[self.attr_tag], type_attribute=self.attr_types, published=self.published)
        try:
            result = search_result['response']['Attribute']
        except:
            result = []
        return result
