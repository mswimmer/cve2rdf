<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
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

  <xsl:template match="nvd:nvd/nvd:entry">
    <xsl:message>
      <xsl:value-of select="@id" />
    </xsl:message>
    <rdf:Description rdf:about="{@id}">
      <rdf:type rdf:resource="http://scap.nist.gov/schema/feed/vulnerability/2.0/Entry" />
      <dc:identifier>
	<xsl:value-of select="vuln:cve-id/text()" />
      </dc:identifier>
      <dc:created rdf:datatype="xs:dateTime">
	<xsl:value-of select="vuln:published-datetime/text()" />
      </dc:created>
      <dc:modified rdf:datatype="xs:dateTime">
	<xsl:value-of select="vuln:last-modified-datetime/text()" />
      </dc:modified>
      <dc:abstract>
	<xsl:value-of select="vuln:summary/text()" />
      </dc:abstract>
      <vuln:cwe>
	<xsl:value-of select="vuln:cwe/@id" />
      </vuln:cwe>
      <xsl:apply-templates select="vuln:vulnerable-software-list" />
      <xsl:apply-templates select="vuln:cvss" />
      <xsl:apply-templates select="vuln:references" />
      <xsl:apply-templates select="vuln:vulnerable-configuration" />
    </rdf:Description>
  </xsl:template>
  
  <xsl:template match="vuln:vulnerable-software-list">
    <xsl:apply-templates select="vuln:product" />
  </xsl:template>

  <xsl:template match="vuln:product">
    <vuln:vulnerable-software-list>
      <vuln:product>
	<xsl:variable name="cpe_in"><xsl:value-of select="." /></xsl:variable>
	<xsl:variable name="cpe_out"><xsl:value-of select="translate($cpe_in, ':/',':')" /></xsl:variable>
	
	<xsl:value-of select="$cpe_out" />
      </vuln:product>
    </vuln:vulnerable-software-list>
  </xsl:template>

  <xsl:template match="vuln:cvss">
    <vuln:cvss>
      <rdf:Description>
	<rdf:type rdf:resource="http://scap.nist.gov/schema/cvss-v2/0.2/base_metrics" />
	<cvss:score>
	  <xsl:value-of select="cvss:base_metrics/cvss:score/text()" />
	</cvss:score>
	<cvss:access-vector>
	  <xsl:value-of select="cvss:base_metrics/cvss:access-vector/text()" />
	</cvss:access-vector>
	<cvss:access-complexity>
	  <xsl:value-of select="cvss:base_metrics/cvss:access-complexity/text()" />
	</cvss:access-complexity>
	<cvss:authentication>
	  <xsl:value-of select="cvss:base_metrics/cvss:authentication/text()" />
	</cvss:authentication>
	<cvss:confidentiality-impact>
	  <xsl:value-of
	    select="cvss:base_metrics/cvss:confidentiality-impact/text()" />
	</cvss:confidentiality-impact>
	<cvss:integrity-impact>
	  <xsl:value-of select="cvss:base_metrics/cvss:integrity-impact/text()" />
	</cvss:integrity-impact>
	<cvss:availability-impact>
	  <xsl:value-of select="cvss:base_metrics/cvss:availability-impact/text()" />
	</cvss:availability-impact>
	<dc:source rdf:resource="{cvss:base_metrics/cvss:source/text()}" />
	<cvss:generated-on-datetime rdf:datatype="xs:dateTime">
	  <xsl:value-of select="cvss:base_metrics/cvss:generated-on-datetime/text()" />
	</cvss:generated-on-datetime>
      </rdf:Description>
    </vuln:cvss>
  </xsl:template>
  
  <xsl:template match="vuln:references">
    <vuln:reference>
      <rdf:Description>
	<rdf:type
	  rdf:resource="http://scap.nist.gov/schema/vulnerability/0.4/{@reference_type}" />
	<dc:language>
	  <xsl:value-of select="@xml:lang" />
	</dc:language>
	<vuln:source>
	  <xsl:value-of select="vuln:source" />
	</vuln:source>
	<dc:references rdf:resource="{vuln:reference/@href}" />
	<dc:identifier>
	  <xsl:value-of select="vuln:reference/text()" />
	</dc:identifier>
	<!-- is this always the same as the parent lang? <xsl:value-of select="vuln:reference/@xml:lang" 
	     /> -->
      </rdf:Description>
    </vuln:reference>
  </xsl:template>
  
  <xsl:template match="vuln:vulnerable-configuration">
    <vuln:vulnerable-configuration>
      <rdf:Description>
	<rdf:type
	  rdf:resource="http://scap.nist.gov/schema/vulnerability/0.4/VulnerableConfiguration" />
	<xsl:apply-templates select="cpe-lang:logical-test" />
      </rdf:Description>
    </vuln:vulnerable-configuration>
  </xsl:template>

  <xsl:template match="cpe-lang:logical-test">
    <cpe-lang:logical-test>
      <rdf:Description>
	<rdf:type rdf:resource="http://cpe.mitre.org/language/2.0/LogicalTest" />        
	<xsl:variable name="operator" select="@operator" />
	<xsl:variable name="negated" select="@negate" />
	<xsl:message>
	  <xsl:value-of select="$operator" />
	</xsl:message>
	<xsl:choose>
	  <xsl:when test="$operator='AND' and $negated='false'">
	    <xsl:message>
	      processing and-ed facts
	    </xsl:message>
	    <xsl:apply-templates select="cpe-lang:fact-ref" />
	    <xsl:apply-templates select="cpe-lang:logical-test" />
	  </xsl:when>
	  <xsl:when test="$operator='OR' and $negated='false'">
	    <xsl:message>
	      processing or-ed facts
	    </xsl:message>
	    <rdf:Alt>
	      <xsl:for-each select="cpe-lang:fact-ref">
		<rdf:li>
		  <cpe-lang:fact-ref>
		    <xsl:value-of select="@name" />
		  </cpe-lang:fact-ref>
		</rdf:li>
	      </xsl:for-each>
              <xsl:for-each select="cpe-lang:logical-test">
                <rdf:li>
                  <xsl:apply-templates select="cpe-lang:logical-test" />
                </rdf:li>
              </xsl:for-each>
	    </rdf:Alt>
	  </xsl:when>
	</xsl:choose>
      </rdf:Description>
    </cpe-lang:logical-test>
  </xsl:template>
  
  <xsl:template match="cpe-lang:fact-ref">
    <xsl:message>
      <xsl:value-of select="@name" />
    </xsl:message>
    <cpe-lang:fact-ref>
      <xsl:value-of select="@name" />
    </cpe-lang:fact-ref>
  </xsl:template>
</xsl:stylesheet>
