import pytest
from ckanext.iso19115.utils import codelist_options

def test_codelist_options_injection():
    """
    Test that malicious XPath input does not manipulate the query structure.
    """
    # A malicious name that would have worked with f-string interpolation:
    # f"//cat:codelistItem/cat:CT_Codelist[@id='{name}']/..."
    # Injection: "' or 1=1 or '" would result in:
    # //cat:codelistItem/cat:CT_Codelist[@id='' or 1=1 or '']/...
    # which would return values from ALL codelists.
    
    malicious_name = "' or 1=1 or '"
    
    # With safe parameter binding, this should be treated as a literal string
    # and return no results (unless a codelist literally has that ID).
    results = codelist_options(malicious_name)
    assert results == []

def test_codelist_options_valid():
    """
    Test that a valid codelist name still returns expected results.
    """
    valid_name = "CI_RoleCode"
    results = codelist_options(valid_name)
    
    # We expect some results for a valid codelist
    assert len(results) > 0
    # Check that it contains expected structure
    assert hasattr(results[0], 'name')
    assert hasattr(results[0], 'definition')

def test_codelist_names():
    """
    Test that codelist_names returns a list of valid codelist IDs.
    """
    from ckanext.iso19115.utils import codelist_names
    names = codelist_names()
    assert len(names) > 0
    assert "CI_RoleCode" in names
