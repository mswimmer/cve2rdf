import unittest
import rdflib

PREFIXES="""
PREFIX nvdcve: <https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2019.xml#>
PREFIX cvss: <https://mswimmer.github.io/utim/score#>
PREFIX vuln: <https://mswimmer.github.io/utim/vulnerability#>
"""

class TestCVE20180001XSLT(unittest.TestCase):
    def setUp(self):
        self.g = rdflib.Graph()
        self.g.load("gov.nist.nvd-CVE-2018-0001.rdf")

    def test_container(self):
        q = PREFIXES + """
        SELECT * 
        WHERE { 
          ?s a vuln:NVDEntry .
        }"""
        self.assertEqual(1, len(list(self.g.query(q))))
        self.assertEqual("https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2019.xml#CVE-2018-0001", str(list(self.g.query(q))[0].s))

    def test_cvss(self):
        q = PREFIXES + """
        SELECT * 
        WHERE { 
          ?s a cvss:CVSSv2BaseMetricGroup .
        }"""
        self.assertEqual(1, len(list(self.g.query(q))))

    def test_cvss_data_objects(self):
        q = PREFIXES + """
        ASK {
          ?s a cvss:CVSSv2BaseMetricGroup;
             cvss:hasAttackComplexity cvss:CVSSv2LowAccessComplexity ;
	     cvss:hasAttackVector cvss:CVSSv2NetworkAccessVector ;
	     cvss:hasAuthentication cvss:CVSSv2NoAuthentication ;
             cvss:hasAvailabilityImpact cvss:CVSSv2PartialAvailabilityImpact ;
             cvss:hasConfidentialityImpact cvss:CVSSv2PartialConfidentialityImpact ;
             cvss:hasIntegrityImpact cvss:CVSSv2PartialIntegrityImpact .
        }"""
        self.assertTrue(self.g.query(q))

    def test_cvss_data_literals(self):
        q = PREFIXES + """
        ASK {
          ?s a cvss:CVSSv2BaseMetricGroup;
             cvss:cvss_v2_baseScore "7.5"^^<xs:decimal> ;
             cvss:generationTime "2018-01-30T17:21:59.327-05:00"^^<xs:dateTime> .
        }"""
        self.assertTrue(self.g.query(q))
        
    def test_id(self):
        q = PREFIXES + """
        ASK {
          ?s a vuln:NVDEntry;
             vuln:id "CVE-2018-0001" .
        }"""
        self.assertTrue(self.g.query(q))

    def test_reference_unknown(self):
        q = PREFIXES + """
        ASK {
          ?s a vuln:UNKNOWNReference;
             vuln:referenceSource "BID" ;
             vuln:referenceTitle "103092"@en ;
             vuln:referenceURL "http://www.securityfocus.com/bid/103092"^^<xsd:anyURI> .
        }"""
        self.assertTrue(self.g.query(q))

    def test_reference_sectrack(self):
        q = PREFIXES + """
        ASK {
          ?s a vuln:VENDOR_ADVISORYReference ;
           vuln:referenceSource "SECTRACK" ;
           vuln:referenceTitle "1040180"@en ;
           vuln:referenceURL "http://www.securitytracker.com/id/1040180"^^<xsd:anyURI>
        }"""
        self.assertTrue(self.g.query(q))
        
    def test_reference_confirm(self):
        q = PREFIXES + """
        ASK {
          ?s a vuln:VENDOR_ADVISORYReference ;
             vuln:referenceSource "CONFIRM" ;
             vuln:referenceTitle "https://kb.juniper.net/JSA10828"@en ;
             vuln:referenceURL "https://kb.juniper.net/JSA10828"^^<xsd:anyURI>
        }"""
        self.assertTrue(self.g.query(q))

        
if __name__ == '__main__':
    unittest.main()
    

        
