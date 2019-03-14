saxon -s:nvdcve-2019.xml -xsl:../xslt/nvd2rdf.xsl -o:nvdcve-2019.rdf BASEURI=https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2019.xml#
rapper -i rdfxml -o turtle nvdcve-2019.rdf >nvdcve-2019.ttl

saxon -s:nvdcve-2.0-2019.xml -xsl:../xslt/nvd2rdf.xsl -o:nvdcve-2.0-2019.rdf BASEURI=https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2019.xml#
rapper -i rdfxml -o turtle nvdcve-2.0-2019.rdf >nvdcve-2.0-2019.ttl

saxon -s:allitems.xml -xsl:../xslt/nvd2rdf.xsl -o:allitems.rdf BASEURI="http://cve.mitre.org/data/allitems.xml#"
rapper -i rdfxml -o turtle allitems.rdf >allitems.ttl
