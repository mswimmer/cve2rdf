<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xsl:stylesheet [
  <!ENTITY rdf 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
  <!ENTITY rdfs 'http://www.w3.org/2000/01/rdf-schema#'>
  <!ENTITY ontology 'http://discovery.nict.go.jp/ontology#'>
  <!ENTITY terms 'http://discovery.nict.go.jp/terms#'>
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
    xmlns:ontology="http://discovery.nict.go.jp/ontology#"
    xmlns:terms="http://discovery.nict.go.jp/terms#"
    xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0"
    
    xmlns:nvdcve="http://nvd.nist.gov/ontology/nvdcve#"
    xmlns:nvdvuln="http://scap.nist.gov/ontology/vulnerability"
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
    <xsl:variable name="entryURL"><xsl:value-of
    select="$URI"/>/NVD/<xsl:value-of
    select="$nvd-id"/></xsl:variable>
    
    <rdf:Description rdf:about="{$entryURL}">
      <rdf:type rdf:resource="nvdcve:Entry" />

      <nvdcve:id>
        <xsl:value-of select="$nvd-id"/>
      </nvdcve:id>
      
      <dc:description>
        <xsl:value-of select="vuln:summary"/>
      </dc:description>
      
      <nvdvuln:cwe-id>
        <xsl:value-of select="vuln:cwe/@id"/>
      </nvdvuln:cwe-id>
      
      <nvdvuln:externalIdentifier>
        <xsl:value-of select="vuln:cve-id"/>
      </nvdvuln:externalIdentifier>
      
      <nvdvuln:published rdf:datatype="xsd:dateTime">
        <xsl:value-of select="vuln:published-datetime"/>
      </nvdvuln:published>
      
      <nvdvuln:lastModified rdf:datatype="xsd:dateTime">
        <xsl:value-of select="vuln:last-modified-datetime"/>
      </nvdvuln:lastModified>

      <!-- vuln:references -->
      <xsl:for-each select="vuln:references">
        <nvdvuln:hasReference>
          <rdf:Description>
            <terms:reference_type>
              <xsl:value-of select="@reference_type"/>
            </terms:reference_type>
            <nvdvuln:referenceSource>
              <xsl:value-of select="vuln:source"/>
            </nvdvuln:referenceSource>
            <nvdvuln:referenceURL rdf:datatype="xsd:anyURI">
              <xsl:value-of select="vuln:reference/@href"/>
            </nvdvuln:referenceURL>
            <nvdvuln:referenceTitle xml:lang="{@xml:lang}">
              <xsl:value-of select="vuln:reference/text()"/>
            </nvdvuln:referenceTitle>
          </rdf:Description>
        </nvdvuln:hasReference>
      </xsl:for-each>

      <xsl:for-each select="vuln:vulnerable-software-list/vuln:product">
        <nvdvuln:vulnerableSoftware>
          <rdf:Description>
            <rdf:type rdf:resource="cpe-lang:Product" />
            <cpe-lang:title>
              <xsl:value-of select="text()" />
            </cpe-lang:title>
          </rdf:Description>
        </nvdvuln:vulnerableSoftware>
      </xsl:for-each>
      
      <xsl:for-each select="vuln:cvss">
        <nvdvuln:cvss>
          <xsl:apply-templates select="cvss:base_metrics" />
        </nvdvuln:cvss>
      </xsl:for-each>
      
      <xsl:for-each select="vuln:vulnerable-configuration">
        <nvdvuln:vulnerableConfiguration>
          <xsl:apply-templates select="cpe-lang:logical-test" />
        </nvdvuln:vulnerableConfiguration>
      </xsl:for-each>

    </rdf:Description>

    <!--xsl:apply-templates select="vuln:vulnerable-configuration"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates-->
    <!--xsl:apply-templates select="vuln:vulnerable-software-list/*"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates-->
    <!--xsl:apply-templates select="vuln:assessment_check"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates-->
    <xsl:apply-templates select="vuln:references"><xsl:with-param name="entryURL" select="$entryURL"/></xsl:apply-templates>
    <!--xsl:apply-templates select="vuln:scanner"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates-->
    <!--xsl:apply-templates select="vuln:cvss"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates-->

  </xsl:template>


  <!-- vuln:vuln:vulnerable-configuration -->
  <!--xsl:template match="vuln:vulnerable-configuration">
    <xsl:param name="nvd-id"/>
    <xsl:apply-templates select="cpe-lang:logical-test"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates>
  </xsl:template-->

  <!-- cpe-lang:logical-test -->
  <!--xsl:template match="cpe-lang:logical-test">
    <xsl:param name="nvd-id"/>
    <xsl:apply-templates select="cpe-lang:logical-test"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates>
    <xsl:apply-templates select="cpe-lang:fact-ref"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates>
  </xsl:template-->

  <!-- fact-ref -->
  <!--xsl:template match="cpe-lang:fact-ref">
    <xsl:param name="nvd-id"/>
    <rdf:Description>
      <xsl:attribute name="rdf:about"><xsl:value-of select="$URI"/>/NVD/<xsl:value-of select="$nvd-id"/></xsl:attribute>
      <terms:fact-ref><xsl:value-of select="@name"/></terms:fact-ref>
    </rdf:Description>
  </xsl:template-->

  <!-- product -->
  <!--xsl:template match="vuln:product">
    <xsl:param name="nvd-id"/>
        <xsl:attribute name="rdf:about">
        <xsl:value-of select="$URI"/>/NVD/<xsl:value-of select="$nvd-id"/></xsl:attribute>
        <cpe-lang:namePattern><xsl:value-of select="."/></cpe-lang:namePattern>
  </xsl:template-->
  
  <!-- vuln:assessment_check -->
  <!--xsl:template match="vuln:assessment_check ">
    <xsl:param name="nvd-id"/>
    <rdf:Description>
<xsl:attribute name="rdf:about"><xsl:value-of select="$URI"/>/NVD/<xsl:value-of select="$nvd-id"/></xsl:attribute>
      <terms:assessment_check-name><xsl:value-of select="@name"/></terms:assessment_check-name>
      <terms:assessment_check-href><xsl:value-of select="@href"/></terms:assessment_check-href>
    </rdf:Description>
  </xsl:template-->

  
  <!-- vuln:scanner -->
  <!--xsl:template match="vuln:scanner">
    <xsl:param name="nvd-id"/>
    <xsl:apply-templates select="vuln:definition"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates>
  </xsl:template-->
  
  <!-- vuln:definition -->
  <!--xsl:template match="vuln:definition">
    <xsl:param name="nvd-id"/>
    <rdf:Description>
<xsl:attribute name="rdf:about"><xsl:value-of select="$URI"/>/NVD/<xsl:value-of select="$nvd-id"/></xsl:attribute>
      <terms:definition-name><xsl:value-of select="@name"/></terms:definition-name>
      <terms:definition-href><xsl:value-of select="@href"/></terms:definition-href>
      <terms:definition-system><xsl:value-of select="@system"/></terms:definition-system>
    </rdf:Description>
  </xsl:template-->

  <!-- vuln:cvss -->
  <!--xsl:template match="vuln:cvss">
    <xsl:param name="nvd-id"/>
    <xsl:apply-templates select="cvss:base_metrics"><xsl:with-param name="nvd-id" select="$nvd-id"/></xsl:apply-templates>
  </xsl:template-->
  
  <!-- cvss:base_metrics -->
  <!--xsl:template match="cvss:base_metrics">
    <xsl:param name="nvd-id"/>
    <rdf:Description>
<xsl:attribute name="rdf:about"><xsl:value-of
select="$URI"/>/NVD/<xsl:value-of select="$nvd-id"/></xsl:attribute>

<terms:score><xsl:value-of select="cvss:score/."/></terms:score>
      <terms:access-vector><xsl:value-of select="cvss:access-vector/."/></terms:access-vector>
      <terms:access-complexity><xsl:value-of select="cvss:access-complexity/."/></terms:access-complexity>
      <terms:authentication><xsl:value-of select="cvss:authentication/."/></terms:authentication>
      <terms:confidentiality-impact><xsl:value-of select="cvss:confidentiality-impact/."/></terms:confidentiality-impact>
      <terms:integrity-impact><xsl:value-of select="cvss:integrity-impact/."/></terms:integrity-impact>
      <terms:availability-impact><xsl:value-of select="cvss:availability-impact/."/></terms:availability-impact>
      <terms:source><xsl:value-of select="cvss:source/."/></terms:source>
      <terms:generated-on-datetime><xsl:value-of select="cvss:generated-on-datetime/."/></terms:generated-on-datetime>
    </rdf:Description>
  </xsl:template-->

</xsl:stylesheet>