<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xsl:stylesheet [
<!ENTITY rdf 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
<!ENTITY rdfs 'http://www.w3.org/2000/01/rdf-schema#'>
]>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:sc="http://cpe.mitre.org/dictionary/2.0"
    xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
    xmlns:patch="http://scap.nist.gov/schema/patch/0.1"
    xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0"
    xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
    xmlns:nvdcpe="http://ontologies.ti-semantics.com/platform#"
    xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    xmlns:cpe="http://cpe.mitre.org/cpe"
    xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
    xmlns:dc="http://purl.org/dc/terms/"
    xmlns:fn="http://www.w3.org/2005/xpath-functions">
  
  <xsl:output method="xml" />
  <xsl:strip-space elements="*" />
  <xsl:output indent="yes" />

  <xsl:template match="sc:cpe-list">
    <rdf:RDF>
      <xsl:apply-templates />
    </rdf:RDF>
  </xsl:template>

  <xsl:template match="sc:generator">
  </xsl:template>
  
  <xsl:template match="sc:cpe-item">
    <rdf:Description
	rdf:type="http://ontologies.ti-semantics.com/core#Platform">
      <nvdcpe:wfn>
	<xsl:value-of select="@name" />
      </nvdcpe:wfn>
      <xsl:apply-templates select="sc:title" />
      <xsl:apply-templates select="sc:references" />
    </rdf:Description>
  </xsl:template>

  <xsl:template match="sc:title">
    <nvdcpe:title xml:lang="{@xml:lang}">
      <xsl:value-of select="text()" />
    </nvdcpe:title>
  </xsl:template>

  <xsl:template match="sc:references">
      <xsl:apply-templates select="sc:reference" />
  </xsl:template>

  <xsl:template match="sc:reference">
    <nvdcpe:reference>
      <rdf:Description
	  rdf:type="http://ontologies.ti-semantics.com/platform#Reference">
	<nvdcpe:url>
	  <xsl:value-of select="@href" />
	</nvdcpe:url>
	<nvdcpe:title>
	  <xsl:value-of select="text()" />
	</nvdcpe:title>
      </rdf:Description>
    </nvdcpe:reference>
  </xsl:template>
  
</xsl:stylesheet>
