"""Exercise the fixed-parameter RSA-PSS transforms from XMLDSig-more."""

from pathlib import Path

import pytest
from lxml import etree

import xmlsec

pytestmark = pytest.mark.skipif(xmlsec.get_libxmlsec_version() < (1, 3, 0), reason='RSA-PSS requires xmlsec1 >= 1.3.0')

DATA_DIR = Path(__file__).parent / 'data'


@pytest.fixture(params=[224, 256, 384, 512], ids=lambda bits: f'sha{bits}')
def hash_bits(request):
    return request.param


@pytest.fixture
def rsa_pss(hash_bits):
    return getattr(xmlsec.constants, f'TransformRsaPssSha{hash_bits}')


def _context(key_file):
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(DATA_DIR / key_file, xmlsec.constants.KeyDataFormatPem)
    return ctx


def test_rsa_pss_constants(rsa_pss, hash_bits):
    assert rsa_pss.name == f'rsa-pss-sha{hash_bits}'
    assert rsa_pss is getattr(xmlsec.Transform, f'RSA_PSS_SHA{hash_bits}')
    assert rsa_pss.href == f'http://www.w3.org/2007/05/xmldsig-more#sha{hash_bits}-rsa-MGF1'
    assert rsa_pss.usage == xmlsec.constants.TransformUsageSignatureMethod


def test_rsa_pss_sign_verify_binary(rsa_pss):
    data = b'RSA-PSS signature test'
    signature = _context('rsakey.pem').sign_binary(data, rsa_pss)
    _context('rsapub.pem').verify_binary(data, rsa_pss, signature)

    with pytest.raises(xmlsec.VerificationError):
        _context('rsapub.pem').verify_binary(data + b'!', rsa_pss, signature)


def test_rsa_pss_sign_verify_xml(rsa_pss):
    root = etree.fromstring(b'<document><message>RSA-PSS signature test</message></document>')
    signature = xmlsec.template.create(root, xmlsec.constants.TransformExclC14N, rsa_pss)
    root.append(signature)
    reference = xmlsec.template.add_reference(signature, xmlsec.constants.TransformSha256, uri='')
    xmlsec.template.add_transform(reference, xmlsec.constants.TransformEnveloped)
    _context('rsakey.pem').sign(signature)

    # Verify a newly parsed document, not the signing context's in-memory tree.
    parsed = etree.fromstring(etree.tostring(root))
    signature = xmlsec.tree.find_node(parsed, xmlsec.constants.NodeSignature)
    method = xmlsec.tree.find_node(signature, xmlsec.constants.NodeSignatureMethod)
    assert method.get('Algorithm') == rsa_pss.href
    _context('rsapub.pem').verify(signature)

    parsed.find('message').text = 'tampered'
    with pytest.raises(xmlsec.VerificationError):
        _context('rsapub.pem').verify(signature)
