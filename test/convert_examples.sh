#!/bin/bash
# continuously build example RDF files from the sources

XSLT_DIR=../xslt

for (( ; ; ))
do
    for i in "org.mitre.cve-CVE-2004-0296 http://cve.mitre.org/data/downloads/allitems.xml#" "gov.nist.nvd-CVE-2018-0001 https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2019.xml#"; do
	set -- $i
	#echo $1 and $2
	     
	if [[ $XSLT_DIR/nvd2rdf.xsl -nt $1.rdf || $XSLT_DIR/cvss2rdf.xsl -nt $1.rdf || $XSLT_DIR/cpe-lang2rdf.xsl -nt $1.rdf  ]]; then
            echo *************************************************************************
            saxon -T:net.sf.saxon.trace.XSLTTraceListener -s:$1.xml -xsl:$XSLT_DIR/nvd2rdf.xsl -o:$1.rdf BASEURI=$2
            echo done ***
	fi
    
	if [[ $1.rdf -nt $1.ttl ]]; then
            echo -------------------------------------------------------------------------
            rapper -i rdfxml -o turtle $1.rdf > $1.ttl
            echo done ---
	fi
    done
    sleep 1
done
