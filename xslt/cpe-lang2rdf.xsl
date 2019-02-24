<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
  xmlns:patch="http://scap.nist.gov/schema/patch/0.1"
  xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0"
  xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
  xmlns:nvdcpe="https://mswimmer.github.io/utim/platform#"
  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns:cpe="http://cpe.mitre.org/cpe"
  xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
  xmlns:dc="http://purl.org/dc/terms/"
  xmlns:fn="http://www.w3.org/2005/xpath-functions">
  
  <xsl:output method="xml" />
  <xsl:strip-space elements="*" />
  <xsl:output indent="yes" />

  
  <xsl:template match="cpe-lang:logical-test">
    <rdf:Description>
      <rdf:type rdf:resource="https://mswimmer.github.io/utim/platform#LogicalTest" />
      <nvdcpe:operator>
	<xsl:choose>
          <xsl:when test="@operator='AND'">
	    <rdf:Description rdf:about="https://mswimmer.github.io/utim/platform#AND" />
          </xsl:when>
          <xsl:when test="@operator='OR'">
	    <rdf:Description rdf:about="https://mswimmer.github.io/utim/platform#OR" />
          </xsl:when>
	</xsl:choose>
	
      </nvdcpe:operator>
      <nvdcpe:negate rdf:datatype="xsd:boolean">
	<xsl:value-of select="@negate" />
      </nvdcpe:negate>
      <xsl:for-each select="cpe-lang:fact-ref">
        <!--nvdcpe:namePattern>
          <xsl:value-of select="@name" />
        </nvdcpe:namePattern-->
	<nvdcpe:product>
	  <!-- Make the CPE string into a URN with the experimental namespace of X-cpe as per https://tools.ietf.org/html/rfc3406#section-4.1 -->
	  <rdf:Description rdf:about="urn:X-{@name}" />
	</nvdcpe:product>
      </xsl:for-each>
    </rdf:Description>
  </xsl:template>
  
</xsl:stylesheet>
