SAXON_ARGS=
XSLT_DIR=../../utim/xslt
COL_DIR=.

convert () {
    echo "convert $1 $2 $3 $4 $5"
    if [[ $1 -nt $4.rdf || $2 -nt $4.rdf || $3 -nt $4.rdf ]]; then

        CMD="saxon $SAXON_ARGS -s:$4.xml -xsl:$1 -o:$4.rdf BASEURI=$5"
	echo "[$CMD]"
	$CMD
    fi

    if [[ $4.rdf -nt $4.ttl ]]; then
        CMD="rapper -i rdfxml -o turtle $4.rdf"
	echo "[$CMD]"
	$CMD > $4.ttl
    fi
}

convert $XSLT_DIR/nvd2rdf.xsl $XSLT_DIR/cpe-lang2rdf.xsl $XSLT_DIR/cvss2rdf.xsl $COL_DIR/nvdcve-2019 "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2019.xml"

convert $XSLT_DIR/nvd2rdf.xsl $XSLT_DIR/cpe-lang2rdf.xsl $XSLT_DIR/cvss2rdf.xsl $COL_DIR/nvdcve-2.0-2019 "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2019.xml"

convert $XSLT_DIR/nvd2rdf.xsl $XSLT_DIR/cpe-lang2rdf.xsl $XSLT_DIR/cvss2rdf.xsl $COL_DIR/allitems "http://cve.mitre.org/data/allitems.xml"

convert $XSLT_DIR/cpe-dict2rdf.xsl $XSLT_DIR/cpe-dict2rdf.xsl $XSLT_DIR/cpe-dict2rdf.xsl $COL_DIR/official-cpe-dictionary_v2.3 "https://nvd.nist.gov/products/cpe#"

