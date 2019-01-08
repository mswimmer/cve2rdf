#xsltproc cve2rdf.xsl test/CVE-2018-0001.xml
INFILE=test/CVE-2018-0001.xml
XSL=cve2rdf.xsl
echo Running SAXON
saxon -s:$INFILE -xsl:$XSL -o:$INFILE.rdf
echo Running Rapper to convert to turtle
rapper -i rdfxml -o turtle $INFILE.rdf > $INFILE.ttl
