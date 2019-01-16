<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
  xmlns:cvss3="http://first.org/cvss/v3#"
  xmlns:cvss2="http://first.org/cvss/v2#"
  xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
  xmlns:patch="http://scap.nist.gov/schema/patch/0.1"
  xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0"
  xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns:cpe="http://cpe.mitre.org/cpe"
  xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
  xmlns:dc="http://purl.org/dc/terms/"
  xmlns:fn="http://www.w3.org/2005/xpath-functions">
  
  <xsl:output method="xml" />
  <xsl:strip-space elements="*" />
  <xsl:output indent="yes" />

  <xsl:template match="/">
    <rdf:RDF>
      <xsl:apply-templates />
    </rdf:RDF>
  </xsl:template>

  
  <xsl:template match="//cvss:base_metrics">
      <rdf:Description>
	<rdf:type rdf:resource="cvss2:CVSS" />
	<cvss2:score>
	  <xsl:value-of select="cvss:score/text()" />
	</cvss2:score>
        
	<cvss2:hasAttackVector>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:access-vector, 'ADJACENT_NETWORK')">
              <rdf:Description rdf:about="cvss2:network_access_vector"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-vector, 'LOCAL')">
              <rdf:Description rdf:about="cvss2:local_access_vector"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-vector, 'NETWORK')">
              <rdf:Description rdf:about="cvss2:network_access_vector"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-vector, 'PHYSICAL')">
              <rdf:Description rdf:about="cvss2:physical_access_vector"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAttackVector>
        
	<cvss2:hasAttackComplexity>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:access-complexity, 'LOW')">
              <rdf:Description rdf:about="cvss2:low_access_complexity"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-complexity, 'MEDIUM')">
              <rdf:Description rdf:about="cvss2:medium_access_complexity"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-complexity, 'HIGH')">
              <rdf:Description rdf:about="cvss2:high_access_complexity"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAttackComplexity>
        
	<cvss2:hasConfidentialityImpact>
          <xsl:choose>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'NONE')">
              <rdf:Description rdf:about="cvss2:no_confidentiality_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'LOW')">
              <rdf:Description rdf:about="cvss2:low_confidentiality_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'MEDIUM')">
              <rdf:Description rdf:about="cvss2:medium_confidentiality_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'HIGH')">
              <rdf:Description rdf:about="cvss2:high_confidentiality_impact"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasConfidentialityImpact>
        
	<cvss2:hasIntegrityImpact>
          <xsl:choose>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:integrity-impact, 'NONE')">
              <rdf:Description rdf:about="cvss2:no_integrity_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:integrity-impact, 'LOW')">
              <rdf:Description rdf:about="cvss2:low_integrity_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:integrity-impact, 'MEDIUM')">
              <rdf:Description rdf:about="cvss2:medium_integrity_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:integrity-impact, 'HIGH')">
              <rdf:Description rdf:about="cvss2:high_integrity_impact"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasIntegrityImpact>
        
	<cvss2:hasAuthentication>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:authentication, 'NONE')">
              <rdf:Description rdf:about="cvss2:no_authentication"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:authentication, 'SINGLE')">
              <rdf:Description rdf:about="cvss2:single_authentication"></rdf:Description>
            </xsl:when>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:authentication, 'MULTIPLE')">
              <rdf:Description rdf:about="cvss2:multiple_authentications"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAuthentication>

        <cvss2:hasAvailabilityImpact>

          <xsl:choose>
            <xsl:when test="starts-with(cvss:availability-impact, 'NONE')">
              <rdf:Description rdf:about="cvss2:no_availability_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:availability-impact, 'LOW')">
              <rdf:Description rdf:about="cvss2:low_availability_impact"></rdf:Description>
            </xsl:when>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:availability-impact, 'HIGH')">
              <rdf:Description rdf:about="cvss2:high_availability_impact"></rdf:Description>
            </xsl:when>
            <!-- legacy CVSS2 -->
            <xsl:when test="starts-with(cvss:availability-impact, 'PARTIAL')">
              <rdf:Description rdf:about="cvss2:low_availability_impact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:availability-impact, 'COMPLETE')">
              <rdf:Description rdf:about="cvss2:high_availability_impact"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAvailabilityImpact>

        
	<dc:source rdf:resource="{cvss:source/text()}" />
        
	<cvss2:generationTime rdf:datatype="xs:dateTime">
	  <xsl:value-of select="cvss:generated-on-datetime/text()" />
	</cvss2:generationTime>
        
      </rdf:Description>
  </xsl:template>
  
</xsl:stylesheet>
