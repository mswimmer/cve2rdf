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

    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
    xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1" 
    xmlns:patch="http://scap.nist.gov/schema/patch/0.1" 
    xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" 
    
    xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4" 
    xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2" 
    xmlns:dc="http://purl.org/dc/terms/"
    xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0"
    
    xmlns:nvdvuln="https://mswimmer.github.io/utim/vulnerability#"
>
  <xsl:include href="cvss2rdf.xsl"/>
  <xsl:include href="cpe-lang2rdf.xsl"/>
  
  <xsl:variable name="URI">http://nvd.nist.gov/nvd-feed</xsl:variable>

  <xsl:output method="xml" encoding="UTF-8"/>
  <xsl:strip-space elements="*" />
  <xsl:output indent="yes" />

  <!--root(rdf:RDF)-->
  <xsl:template match="/nvd:nvd">
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

  <!--entry-->
  <xsl:template match="//nvd:entry">
    <xsl:variable name="nvd-id" select="@id" />
    <xsl:variable name="entryURL"><xsl:value-of select="$URI"/>/<xsl:value-of select="$nvd-id"/></xsl:variable>
    
    <rdf:Description rdf:about="{$entryURL}">
      <rdf:type rdf:resource="https://mswimmer.github.io/utim/vulnerability#NVDEntry" />

      <nvdvuln:id>
        <xsl:value-of select="$nvd-id"/>
      </nvdvuln:id>
      
      <nvdvuln:summary>
        <xsl:value-of select="vuln:summary"/>
      </nvdvuln:summary>
      
      <nvdvuln:cwe>
        <rdf:Description>
          <xsl:attribute name="rdf:about">http://cve.mitre.org/data/<xsl:value-of select="vuln:cwe/@id"/></xsl:attribute>
        </rdf:Description>
      </nvdvuln:cwe>
      
      <nvdvuln:cve>
        <rdf:Description>
          <xsl:attribute name="rdf:about"><xsl:value-of select="$URI"/>/<xsl:value-of select="vuln:cve-id"/></xsl:attribute>
        </rdf:Description>
      </nvdvuln:cve>
      
      <nvdvuln:published rdf:datatype="xsd:dateTime">
        <xsl:value-of select="vuln:published-datetime"/>
      </nvdvuln:published>
      
      <nvdvuln:lastModified rdf:datatype="xsd:dateTime">
        <xsl:value-of select="vuln:last-modified-datetime"/>
      </nvdvuln:lastModified>

      <xsl:apply-templates select="vuln:vulnerable-software-list" />
      <xsl:apply-templates select="vuln:references" />
      <xsl:apply-templates select="vuln:cvss" />
      <xsl:apply-templates select="vuln:vulnerable-configuration" />

      <!-- TODO: not tested -->
      <xsl:apply-templates select="vuln:assessment_check" />
      <xsl:apply-templates select="vuln:scanner" />
      
    </rdf:Description>
  </xsl:template>

  <xsl:template match="vuln:vulnerable-software-list">
      <xsl:apply-templates select="vuln:product" />
  </xsl:template>
  
  <xsl:template match="vuln:product">
    <nvdvuln:vulnerableProduct>
    <!--rdf:Description>
      <rdf:type rdf:resource="cpe-lang:Product" />
      <cpe-lang:title>
        <xsl:value-of select="text()" />
      </cpe-lang:title>
    </rdf:Description-->
     <rdf:Description rdf:about="urn:X-{text()}" />
    </nvdvuln:vulnerableProduct>
  </xsl:template>
  
  <xsl:template match="vuln:vulnerable-configuration">
    <nvdvuln:vulnerableConfiguration>
      <xsl:apply-templates select="cpe-lang:logical-test" />
    </nvdvuln:vulnerableConfiguration>
  </xsl:template>
  
  <!-- TODO: utilize the xml:lang attribute to set the language -->
  <xsl:template match="vuln:references">
    <nvdvuln:reference>
      <rdf:Description>
        <rdf:type>
          <xsl:choose>
            <xsl:when test="starts-with(@reference_type, 'PATCH')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/vulnerability#PATCHReference"/>
            </xsl:when>
            <xsl:when test="starts-with(@reference_type, 'UNKNOWN')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/vulnerability#UNKNOWNReference" />
            </xsl:when>
            <xsl:when test="starts-with(@reference_type, 'VENDOR_ADVISORY')">
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/vulnerability#VENDOR_ADVISORYReference" />
            </xsl:when>
            <xsl:otherwise>
              <rdf:Description rdf:about="https://mswimmer.github.io/utim/vulnerability#Reference" />
            </xsl:otherwise>
          </xsl:choose>
        </rdf:type>
        <xsl:if test="@deprecated">
          <nvdvuln:referenceDeprecated rdf:datatype="xsd:boolean">
            <xsl:value-of select="@deprecated" />
          </nvdvuln:referenceDeprecated>
        </xsl:if>
        <xsl:apply-templates select="vuln:source" />
        <xsl:apply-templates select="vuln:reference" />
      </rdf:Description>
    </nvdvuln:reference>
  </xsl:template>
  
  <xsl:template match="vuln:reference">
    <nvdvuln:referenceURL rdf:datatype="xsd:anyURI">
      <xsl:value-of select="@href"/>
    </nvdvuln:referenceURL>
    <nvdvuln:referenceTitle xml:lang="{@xml:lang}">
      <xsl:value-of select="text()"/>
    </nvdvuln:referenceTitle>
  </xsl:template>

  <xsl:template match="vuln:source">
    <nvdvuln:referenceSource>
      <xsl:value-of select="text()"/>
    </nvdvuln:referenceSource>
  </xsl:template>

  <xsl:template match="vuln:cvss">
    <nvdvuln:cvss>
      <xsl:apply-templates select="cvss:base_metrics" />
    </nvdvuln:cvss>
  </xsl:template>
  
  <!-- vuln:assessment_check -->
  <xsl:template match="vuln:assessment_check">
    <nvdvuln:assessmentCheck>
      <rdf:Description>
        <nvdvuln:assessmentCheckName>
          <xsl:value-of select="@name"/>
        </nvdvuln:assessmentCheckName>
        <nvdvuln:assessmentCheckURL>
          <xsl:value-of select="@href"/>
        </nvdvuln:assessmentCheckURL>
      </rdf:Description>
    </nvdvuln:assessmentCheck>
  </xsl:template>

  <!-- vuln:scanner -->
  <xsl:template match="vuln:scanner">
    <nvdvuln:scanner>
      <rdf:Description>
        <xsl:apply-templates select="vuln:definition" />
      </rdf:Description>
    </nvdvuln:scanner>
  </xsl:template>
  
  <!-- vuln:definition -->
  <xsl:template match="vuln:definition">
    <rdf:Description>
      <nvdvuln:definitionName>
        <xsl:value-of select="@name"/>
      </nvdvuln:definitionName>
      <nvdvuln:definitionURL>
        <xsl:value-of select="@href"/>
      </nvdvuln:definitionURL>
      <nvdvuln:definitionSystem>
        <xsl:value-of select="@system"/>
      </nvdvuln:definitionSystem>
    </rdf:Description>
  </xsl:template>

</xsl:stylesheet>
