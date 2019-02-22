<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
  xmlns:cvss2="https://mswimmer.github.io/utim/score#"
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

  
  <xsl:template match="//cvss:base_metrics">
      <rdf:Description>
	<rdf:type rdf:resource="https://mswimmer.github.io/utim/score#CVSSv2MetricGroup" />
	<cvss2:cvss_v2_baseScore rdf:datatype="xs:decimal">
	  <xsl:value-of select="cvss:score/text()" />
	</cvss2:cvss_v2_baseScore>
        
	<cvss2:hasAttackVector>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:access-vector, 'ADJACENT_NETWORK')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2NetworkAccessVector"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-vector, 'LOCAL')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2LocalAccessVector"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-vector, 'NETWORK')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2NetworkAccessVector"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-vector, 'PHYSICAL')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2PhysicalAccessVector"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAttackVector>
        
	<cvss2:hasAttackComplexity>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:access-complexity, 'LOW')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2LowAccessComplexity"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-complexity, 'MEDIUM')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2MediumAccessComplexity"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:access-complexity, 'HIGH')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2HighAccessComplexity"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAttackComplexity>
        
	<cvss2:hasConfidentialityImpact>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'PARTIAL')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2PartialConfidentialityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'COMPLETE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2CompleteConfidentialityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'NONE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2NoConfidentialityImpact"></rdf:Description>
            </xsl:when>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'LOW')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv3LowConfidentialityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:confidentiality-impact, 'HIGH')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv3HighConfidentialityImpact"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasConfidentialityImpact>
        
	<cvss2:hasIntegrityImpact>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:integrity-impact, 'PARTIAL')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2PartialIntegrityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:integrity-impact, 'COMPLETE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2CompleteIntegrityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:integrity-impact, 'NONE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2NoIntegrityImpact"></rdf:Description>
            </xsl:when>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:integrity-impact, 'LOW')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2LowIntegrityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:integrity-impact, 'HIGH')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2HighIntegrityImpact"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasIntegrityImpact>
        
        <cvss2:hasAvailabilityImpact>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:availability-impact, 'PARTIAL')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2PartialAvailabilityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:availability-impact, 'COMPLETE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2CompleteAvailabilityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:availability-impact, 'NONE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2NoAvailabilityImpact"></rdf:Description>
            </xsl:when>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:availability-impact, 'LOW')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv3LowAvailabilityImpact"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:availability-impact, 'HIGH')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv3HighAvailabilityImpact"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAvailabilityImpact>

	<cvss2:hasAuthentication>
          <xsl:choose>
            <xsl:when test="starts-with(cvss:authentication, 'NONE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2NoAuthentication"></rdf:Description>
            </xsl:when>
            <xsl:when test="starts-with(cvss:authentication, 'SINGLE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2SingleAuthentication"></rdf:Description>
            </xsl:when>
            <!-- new for CVSS3 -->
            <xsl:when test="starts-with(cvss:authentication, 'MULTIPLE')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/score#CVSSv2MultipleAuthentications"></rdf:Description>
            </xsl:when>
          </xsl:choose>
	</cvss2:hasAuthentication>

        
	<dc:source rdf:resource="{cvss:source/text()}" />
        
	<cvss2:generationTime rdf:datatype="xs:dateTime">
	  <xsl:value-of select="cvss:generated-on-datetime/text()" />
	</cvss2:generationTime>
        
      </rdf:Description>
  </xsl:template>
  
</xsl:stylesheet>
