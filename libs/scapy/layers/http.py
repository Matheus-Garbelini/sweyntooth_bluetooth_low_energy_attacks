#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : Steeve Barbeau, Luca Invernizzi
# This program is published under a GPLv2 license

import re
from scapy.packet import Packet, bind_layers
from scapy.fields import StrField
from scapy.layers.inet import TCP


def _canonicalize_header(name):
    ''' Takes a header key (i.e., "Host" in "Host: www.google.com",
        and returns a canonical representation of it '''
    return name.strip().lower()

def _parse_headers(s):
    headers = s.split("\r\n")
    headers_found = {}
    for header_line in headers:
        try:
            key, value = header_line.split(':', 1)
        except:
            continue
        headers_found[_canonicalize_header(key)] = header_line.strip()
    return headers_found

def _parse_headers_and_body(s):
    ''' Takes a HTTP packet, and returns a tuple containing:
      - the first line (e.g., "GET ...")
      - the headers in a dictionary
      - the body '''
    try:
        crlfcrlf = b"\x0d\x0a\x0d\x0a"
        crlfcrlfIndex = s.find(crlfcrlf)
        headers = s[:crlfcrlfIndex + len(crlfcrlf)].decode("utf-8")
        body = s[crlfcrlfIndex + len(crlfcrlf):]
    except:
        headers = s
        body = ''
    first_line, headers = headers.split("\r\n", 1)
    return first_line.strip(), _parse_headers(headers), body


def _dissect_headers(obj, s):
    ''' Takes a HTTP packet as the string s, and populates the scapy layer obj
        (either HTTPResponse or HTTPRequest). Returns the first line of the
        HTTP packet, and the body
    '''
    first_line, headers, body = _parse_headers_and_body(s)
    obj.setfieldval('Headers', '\r\n'.join(list(headers.values())))
    for f in obj.fields_desc:
        canonical_name = _canonicalize_header(f.name)
        try:
            header_line = headers[canonical_name]
        except:
            continue
        key, value = header_line.split(':', 1)
        obj.setfieldval(f.name,  value.strip())
        del headers[canonical_name]
    if headers:
        # Kept for compatibility
        obj.setfieldval(
            'Additional-Headers', '\r\n'.join(list(headers.values())) + '\r\n')
    return first_line, body


def _get_field_value(obj, name):
    ''' Returns the value of a packet field.'''
    val = obj.getfieldval(name)
    if name != 'Headers':
        return val
    # Headers requires special handling, as we give a parsed representation of it.
    headers = _parse_headers(val)
    val = []
    for header_name in headers:
        try:
            header_value = obj.getfieldval(header_name.capitalize())
            # If we provide a parsed representation for this header
            headers[header_name] = header_value
            val.append('%s: %s' % (header_name.capitalize(), header_value))
        except AttributeError as e:
            # If we don't provide a parsed representation
            val.append(headers[header_name])
    return '\r\n'.join(val)


def _self_build(obj, field_pos_list=None):
    ''' Takes an HTTPRequest or HTTPResponse object, and creates its internal
    scapy representation as a string. That is, generates the HTTP
    packet as a string '''
    p = b""
    newline = b'\x0d\x0a'  # '\r\n'
    # Walk all the fields, in order
    for f in obj.fields_desc:
        if f.name not in ['Method', 'Path', 'Status-Line', 'Http-Version',
            'Headers']:
          # Additional fields added for user-friendliness should be ignored
          continue
        # Get the field value
        val = _get_field_value(obj, f.name)
        # Fields used in the first line have a space as a separator, whereas
        # headers are terminated by a new line
        if f.name in ['Method', 'Path', 'Status-Line']:
          separator = b' '
        else:
          separator = newline
        # Add the field into the packet
        p = f.addfield(obj, p, val + separator)
    # The packet might be empty, and in that case it should stay empty.
    if p:
      # Add an additional line after the last header
      p = f.addfield(obj, p, '\r\n')
    return p


class HTTPRequest(Packet):

    name = "HTTP Request"
    http_methods = "^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"
    fields_desc = [StrField("Method", None, fmt="H"),
                StrField("Path", None, fmt="H"),
                StrField("Http-Version", None, fmt="H"),
                StrField("Host", None, fmt="H"),
                StrField("User-Agent", None, fmt="H"),
                StrField("Accept", None, fmt="H"),
                StrField("Accept-Language", None, fmt="H"),
                StrField("Accept-Encoding", None, fmt="H"),
                StrField("Accept-Charset", None, fmt="H"),
                StrField("Referer", None, fmt="H"),
                StrField("Authorization", None, fmt="H"),
                StrField("Expect", None, fmt="H"),
                StrField("From", None, fmt="H"),
                StrField("If-Match", None, fmt="H"),
                StrField("If-Modified-Since", None, fmt="H"),
                StrField("If-None-Match", None, fmt="H"),
                StrField("If-Range", None, fmt="H"),
                StrField("If-Unmodified-Since", None, fmt="H"),
                StrField("Max-Forwards", None, fmt="H"),
                StrField("Proxy-Authorization", None, fmt="H"),
                StrField("Range", None, fmt="H"),
                StrField("TE", None, fmt="H"),
                StrField("Cache-Control", None, fmt="H"),
                StrField("Connection", None, fmt="H"),
                StrField("Date", None, fmt="H"),
                StrField("Pragma", None, fmt="H"),
                StrField("Trailer", None, fmt="H"),
                StrField("Transfer-Encoding", None, fmt="H"),
                StrField("Upgrade", None, fmt="H"),
                StrField("Via", None, fmt="H"),
                StrField("Warning", None, fmt="H"),
                StrField("Keep-Alive", None, fmt="H"),
                StrField("Allow", None, fmt="H"),
                StrField("Content-Encoding", None, fmt="H"),
                StrField("Content-Language", None, fmt="H"),
                StrField("Content-Length", None, fmt="H"),
                StrField("Content-Location", None, fmt="H"),
                StrField("Content-MD5", None, fmt="H"),
                StrField("Content-Range", None, fmt="H"),
                StrField("Content-Type", None, fmt="H"),
                StrField("Expires", None, fmt="H"),
                StrField("Last-Modified", None, fmt="H"),
                StrField("Cookie", None, fmt="H"),
                StrField("Headers", None, fmt="H"),
                # Deprecated
                StrField("Additional-Headers", None, fmt="H")]

    def do_dissect(self, s):
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        Method, Path, HTTPVersion = re.split("\s+", first_line)
        self.setfieldval('Method', Method)
        self.setfieldval('Path', Path)
        self.setfieldval('Http-Version', HTTPVersion)
        return body

    def self_build(self, field_pos_list=None):
        ''' Generate the HTTP packet string (the oppposite of do_dissect) '''
        return _self_build(self, field_pos_list)


class HTTPResponse(Packet):

    name = "HTTP Response"
    fields_desc = [StrField("Status-Line", None, fmt="H"),
                StrField("Accept-Ranges", None, fmt="H"),
                StrField("Age", None, fmt="H"),
                StrField("E-Tag", None, fmt="H"),
                StrField("Location", None, fmt="H"),
                StrField("Proxy-Authenticate", None, fmt="H"),
                StrField("Retry-After", None, fmt="H"),
                StrField("Server", None, fmt="H"),
                StrField("Vary", None, fmt="H"),
                StrField("WWW-Authenticate", None, fmt="H"),
                StrField("Cache-Control", None, fmt="H"),
                StrField("Connection", None, fmt="H"),
                StrField("Date", None, fmt="H"),
                StrField("Pragma", None, fmt="H"),
                StrField("Trailer", None, fmt="H"),
                StrField("Transfer-Encoding", None, fmt="H"),
                StrField("Upgrade", None, fmt="H"),
                StrField("Via", None, fmt="H"),
                StrField("Warning", None, fmt="H"),
                StrField("Keep-Alive", None, fmt="H"),
                StrField("Allow", None, fmt="H"),
                StrField("Content-Encoding", None, fmt="H"),
                StrField("Content-Language", None, fmt="H"),
                StrField("Content-Length", None, fmt="H"),
                StrField("Content-Location", None, fmt="H"),
                StrField("Content-MD5", None, fmt="H"),
                StrField("Content-Range", None, fmt="H"),
                StrField("Content-Type", None, fmt="H"),
                StrField("Expires", None, fmt="H"),
                StrField("Last-Modified", None, fmt="H"),
                StrField("Headers", None, fmt="H"),
                # Deprecated
                StrField("Additional-Headers", None, fmt="H")]

    def do_dissect(self, s):
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        self.setfieldval('Status-Line', first_line)
        return body

    def self_build(self, field_pos_list=None):
        ''' From the HTTP packet string, populate the scapy object '''
        return _self_build(self, field_pos_list)


class HTTP(Packet):

    name = "HTTP"

    def do_dissect(self, s):
        return s

    def guess_payload_class(self, payload):
        ''' Decides if the payload is an HTTP Request or Response, or
            something else '''
        try:
            prog = re.compile(
                r"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) "
                r"(?:.+?) "
                r"HTTP/\d\.\d$"
            )
            crlfIndex = payload.index("\r\n".encode())
            req = payload[:crlfIndex].decode("utf-8")
            result = prog.match(req)
            if result:
                return HTTPRequest
            else:
                prog = re.compile(r"^HTTP/\d\.\d \d\d\d .*$")
                result = prog.match(req)
                if result:
                    return HTTPResponse
        except:
            pass
        return Packet.guess_payload_class(self, payload)

bind_layers(TCP, HTTP, dport=80)
bind_layers(TCP, HTTP, sport=80)

#For Proxy
bind_layers(TCP, HTTP, sport=8080)
bind_layers(TCP, HTTP, dport=8080)
