<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xsl:stylesheet [
  <!ENTITY rdf 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
  <!ENTITY rdfs 'http://www.w3.org/2000/01/rdf-schema#'>
]>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema#"
    xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
    xmlns:dc="http://purl.org/dc/terms/"

    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 

    xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" 
    xmlns:scapvuln="http://scap.nist.gov/schema/vulnerability/0.4" 
    xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
    
    xmlns:cvefeed="http://cve.mitre.org/cve/downloads/1.0"
    xmlns:nvdfeed="http://scap.nist.gov/schema/feed/vulnerability/2.0"
    
    xmlns:vuln="http://ontologies.ti-semantics.com/vulnerability#"
>
  <xsl:include href="cvss2rdf.xsl"/>
  <xsl:include href="cpe-lang2rdf.xsl"/>
  
  <!--xsl:variable name="URI">http://nvd.nist.gov/nvd-feed</xsl:variable-->
  <xsl:param name="BASEURI"/>
  <xsl:variable
      name="VULN">http://ontologies.ti-semantics.com/vulnerability#</xsl:variable>
  
  <xsl:output method="xml" encoding="UTF-8"/>
  <xsl:strip-space elements="*" />
  <xsl:output indent="yes" />

  <!-- NVD root -->
  <xsl:template match="/nvdfeed:nvd">
    <rdf:RDF>
      <xsl:apply-templates />
    </rdf:RDF>
  </xsl:template>

  <!-- CVE root -->
  <xsl:template match="/cvefeed:cve">
    <rdf:RDF>
      <xsl:apply-templates />
    </rdf:RDF>
  </xsl:template>
  
  <xsl:template match="*">
    <xsl:message terminate="no">
      WARNING: Unmatched element: <xsl:value-of select="name()"/>
    </xsl:message>
    <xsl:apply-templates/>
  </xsl:template>

  <!-- NVD entry -->
  <xsl:template match="//nvdfeed:entry">
    <xsl:variable name="entryId" select="@id" />
    <xsl:variable name="entryURL"><xsl:value-of select="$BASEURI"/><xsl:value-of select="$entryId"/></xsl:variable>
    
    <rdf:Description rdf:about="{$entryURL}">
      <rdf:type rdf:resource="{$VULN}NVDEntry" />

      <vuln:id>
        <xsl:value-of select="$entryId"/>
      </vuln:id>
      
      <vuln:summary>
        <xsl:value-of select="scapvuln:summary"/>
      </vuln:summary>
      
      <vuln:cwe>
        <rdf:Description>
          <xsl:attribute name="rdf:about">http://cve.mitre.org/data/<xsl:value-of select="scapvuln:cwe/@id"/></xsl:attribute>
        </rdf:Description>
      </vuln:cwe>
      
      <vuln:cve>
        <rdf:Description>
          <xsl:attribute name="rdf:about"><xsl:value-of select="$BASEURI"/><xsl:value-of select="scapvuln:cve-id"/></xsl:attribute>
        </rdf:Description>
      </vuln:cve>
      
      <vuln:published rdf:datatype="xsd:dateTime">
        <xsl:value-of select="scapvuln:published-datetime"/>
      </vuln:published>
      
      <vuln:modified rdf:datatype="xsd:dateTime">
        <xsl:value-of select="scapvuln:last-modified-datetime"/>
      </vuln:modified>

      <xsl:apply-templates select="scapvuln:vulnerable-software-list" />
      <xsl:apply-templates select="scapvuln:references" />
      <xsl:apply-templates select="scapvuln:cvss" />
      <xsl:apply-templates select="scapvuln:vulnerable-configuration" />

      <!-- TODO: not tested -->
      <xsl:apply-templates select="scapvuln:assessment_check" />
      <xsl:apply-templates select="scapvuln:scanner" />
      
    </rdf:Description>
  </xsl:template>

  <!-- CVE Item (entry) -->
  <xsl:template match="//cvefeed:item">
    <xsl:variable name="entryId" select="@name" />
    <xsl:variable name="entryURL"><xsl:value-of select="$BASEURI"/><xsl:value-of select="$entryId"/></xsl:variable>
    <rdf:Description  rdf:about="{$entryURL}">
      <rdf:type>
	<xsl:choose>
          <xsl:when test="@type='CAN'">
            <rdf:Description rdf:about="vuln:CandidateEntry" />
          </xsl:when>
          <xsl:when test="@type='CVE'">
            <rdf:Description rdf:about="vuln:CVEEntry" />
          </xsl:when>
	</xsl:choose>
      </rdf:type>
      <xsl:apply-templates select="cvefeed:refs" />
      <!-- we will skip votes and comments because these were
	   eventually phased out -->
    </rdf:Description>
  </xsl:template>
  
  <xsl:template match="scapvuln:vulnerable-software-list">
      <xsl:apply-templates select="scapvuln:product" />
  </xsl:template>
  
  <xsl:template match="scapvuln:product">
    <vuln:vulnerableProduct>
     <rdf:Description rdf:about="urn:X-{text()}" />
    </vuln:vulnerableProduct>
  </xsl:template>
  
  <xsl:template match="scapvuln:vulnerable-configuration">
    <vuln:vulnerableConfiguration>
      <xsl:apply-templates select="cpe-lang:logical-test" />
    </vuln:vulnerableConfiguration>
  </xsl:template>
  
  <!-- TODO: utilize the xml:lang attribute to set the language -->
  <xsl:template match="scapvuln:references">
    <vuln:reference>
      <rdf:Description>
        <rdf:type>
          <xsl:choose>
            <xsl:when test="starts-with(@reference_type, 'PATCH')">
              <rdf:Description rdf:about="{$VULN}PATCHReference"/>
            </xsl:when>
            <xsl:when test="starts-with(@reference_type, 'UNKNOWN')">
              <rdf:Description rdf:about="{$VULN}UNKNOWNReference" />
            </xsl:when>
            <xsl:when test="starts-with(@reference_type, 'VENDOR_ADVISORY')">
              <rdf:Description rdf:about="{$VULN}VENDOR_ADVISORYReference" />
            </xsl:when>
            <xsl:otherwise>
              <rdf:Description rdf:about="{$VULN}Reference" />
            </xsl:otherwise>
          </xsl:choose>
        </rdf:type>
        <xsl:if test="@deprecated">
          <vuln:referenceDeprecated rdf:datatype="xsd:boolean">
            <xsl:value-of select="@deprecated" />
          </vuln:referenceDeprecated>
        </xsl:if>
        <xsl:apply-templates select="scapvuln:source" />
        <xsl:apply-templates select="scapvuln:reference" />
      </rdf:Description>
    </vuln:reference>
  </xsl:template>

  <xsl:template match="cvefeed:refs">
    <xsl:apply-templates select="cvefeed:ref" />
  </xsl:template>
    
  <xsl:template match="cvefeed:ref">
    <vuln:reference>
      <rdf:Description>
        <rdf:type>
          <rdf:Description rdf:about="{$VULN}Reference" />
        </rdf:type>
	
        <vuln:referenceSource>
	  <xsl:value-of select="@source"/>
	</vuln:referenceSource>
	
        <xsl:apply-templates select="scapvuln:reference" />
	<vuln:referenceURL rdf:datatype="xsd:anyURI">
	  <xsl:value-of select="@url" />
	</vuln:referenceURL>
	<vuln:referenceTitle xml:lang="en">
	  <xsl:value-of select="text()" />
	</vuln:referenceTitle>
	
      </rdf:Description>
    </vuln:reference>
  </xsl:template>
  
  <xsl:template match="scapvuln:reference">
    <vuln:referenceURL rdf:datatype="xsd:anyURI">
      <xsl:value-of select="@href"/>
    </vuln:referenceURL>
    <vuln:referenceTitle xml:lang="{@xml:lang}">
      <xsl:value-of select="text()"/>
    </vuln:referenceTitle>
  </xsl:template>

  <xsl:template match="scapvuln:source">
    <vuln:referenceSource>
      <xsl:value-of select="text()"/>
    </vuln:referenceSource>
  </xsl:template>

  <xsl:template match="scapvuln:cvss">
    <vuln:cvss>
      <xsl:apply-templates select="cvss:base_metrics" />
    </vuln:cvss>
  </xsl:template>
  
  <!-- vuln:assessment_check -->
  <xsl:template match="scapvuln:assessment_check">
    <vuln:assessmentCheck>
      <rdf:Description>
        <vuln:assessmentCheckName>
          <xsl:value-of select="@name"/>
        </vuln:assessmentCheckName>
        <vuln:assessmentCheckURL>
          <xsl:value-of select="@href"/>
        </vuln:assessmentCheckURL>
      </rdf:Description>
    </vuln:assessmentCheck>
  </xsl:template>

  <!-- vuln:scanner -->
  <xsl:template match="scapvuln:scanner">
    <vuln:scanner>
      <rdf:Description>
        <xsl:apply-templates select="scapvuln:definition" />
      </rdf:Description>
    </vuln:scanner>
  </xsl:template>
  
  <!-- vuln:definition -->
  <xsl:template match="scapvuln:definition">
    <rdf:Description>
      <vuln:definitionName>
        <xsl:value-of select="@name"/>
      </vuln:definitionName>
      <vuln:definitionURL>
        <xsl:value-of select="@href"/>
      </vuln:definitionURL>
      <vuln:definitionSystem>
        <xsl:value-of select="@system"/>
      </vuln:definitionSystem>
    </rdf:Description>
  </xsl:template>

</xsl:stylesheet>
