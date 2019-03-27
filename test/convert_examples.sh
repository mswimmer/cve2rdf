#!/bin/bash
# continuously build example RDF files from the sources

XSLT_DIR=../xslt
#SAXON_ARGS=-T:net.sf.saxon.trace.XSLTTraceListener
SAXON_ARGS=

for (( ; ; ))
do
    for i in "org.mitre.cve-CVE-2004-0296 http://cve.mitre.org/data/downloads/allitems.xml#" "gov.nist.nvd-CVE-2018-0001 https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2019.xml#" "gov.nist.nvd-1.2-CVE-2019-0001 http://nvd.nist.gov/feeds/cve/1.2"; do
	# Split the string into two parts separated by a space
	set -- $i
	     
	if [[ $XSLT_DIR/nvd2rdf.xsl -nt $1.rdf || $XSLT_DIR/cvss2rdf.xsl -nt $1.rdf || $XSLT_DIR/cpe-lang2rdf.xsl -nt $1.rdf ]]; then
            echo "*************************************************************************"
	    echo "[saxon $SAXON_ARGS -s:$1.xml -xsl:$XSLT_DIR/nvd2rdf.xsl -o:$1.rdf BASEURI=\"$2\"]"
            saxon $SAXON_ARGS -s:$1.xml -xsl:$XSLT_DIR/nvd2rdf.xsl -o:$1.rdf BASEURI=$2
            echo "done ***"
	fi
    
	if [[ $1.rdf -nt $1.ttl ]]; then
            echo "-------------------------------------------------------------------------"
	    echo "[rapper -i rdfxml -o turtle $1.rdf \> $1.ttl"]
            rapper -i rdfxml -o turtle $1.rdf > $1.ttl
            echo "done ---"
	fi
    done
    sleep 1
done
