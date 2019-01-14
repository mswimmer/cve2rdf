<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:cve1="http://cve.mitre.org/cve/downloads/1.0"
  xmlns:cve1o="http://mitre.org/cve1"

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

  <xsl:template match="//cve1:item">
    <rdf:Description>
      <rdf:type>
       <xsl:choose>
         <xsl:when test="@type='CAN'">
           <rdf:Description rdf:about="cve1o:CandidateEntry" />
         </xsl:when>
         <xsl:when test="@type='CVE'">
           <rdf:Description rdf:about="cve1o:Entry" />
         </xsl:when>
       </xsl:choose>
      </rdf:type>
      <cve1o:hasName>
        <xsl:value-of select="@name" />
      </cve1o:hasName>
      <cve1o:hasSequenceNumber>
        <xsl:value-of select="@seq" />
      </cve1o:hasSequenceNumber>
      <cve1o:hasStatus>
        <xsl:choose>
          <xsl:when test="cve1:status='Candidate'">
            <rdf:Description rdf:about="cve1o:candidate"></rdf:Description>
          </xsl:when>
          <xsl:when test="cve1:status='Entry'">
            <rdf:Description rdf:about="cve1o:entry"></rdf:Description>
          </xsl:when>
        </xsl:choose>
      </cve1o:hasStatus>
      
      <cve1o:hasPhase>
        <xsl:choose>
          <xsl:when test="cve1:phase='Proposed'">
            <rdf:Description>
              <rdf:type>
                <rdf:Description rdf:about="cve1o:proposed" />
              </rdf:type>
              <cve1o:modifiedDate rdf:datatype="xs:datetime">
                <!--xsl:value-of select="cve1:phase/@date" /-->
                <xsl:value-of select="concat(substring(cve1:phase/@date, 1, 4) , '-', substring(cve1:phase/@date, 5, 2 ), '-', substring(cve1:phase/@date, 7, 2 ))" />
              </cve1o:modifiedDate>
            </rdf:Description>
          </xsl:when>
          <xsl:when test="cve1:phase='Interim'">
            <rdf:Description>
              <rdf:type>
                <rdf:Description rdf:about="cve1o:interim" />
              </rdf:type>
              <cve1o:modifiedDate rdf:datatype="xs:datetime">
                <xsl:value-of select="concat(substring(cve1:phase/@date, 1, 4) , '-', substring(cve1:phase/@date, 5, 2 ), '-', substring(cve1:phase/@date, 7, 2 ))" />
              </cve1o:modifiedDate>
            </rdf:Description>
          </xsl:when>
          <xsl:when test="cve1:phase='Modified'">
            <rdf:Description>
              <rdf:type>
                <rdf:Description rdf:about="cve1o:modified" />
              </rdf:type>
              <cve1o:modifiedDate rdf:datatype="xs:datetime">
                <!--xsl:value-of select="cve1:phase/@date" /-->
                <xsl:value-of select="concat(substring(cve1:phase/@date, 1, 4) , '-', substring(cve1:phase/@date, 5, 2 ), '-', substring(cve1:phase/@date, 7, 2 ))" />
              </cve1o:modifiedDate>
            </rdf:Description>
          </xsl:when>
          <xsl:when test="cve1:phase='Assigned'">
            <rdf:Description>
              <rdf:type>
                <rdf:Description rdf:about="cve1o:assigned" />
              </rdf:type>
              <cve1o:modifiedDate rdf:datatype="xs:datetime">
                <xsl:value-of select="concat(substring(cve1:phase/@date, 1, 4) , '-', substring(cve1:phase/@date, 5, 2 ), '-', substring(cve1:phase/@date, 7, 2 ))" />
              </cve1o:modifiedDate>
            </rdf:Description>
          </xsl:when>
        </xsl:choose>
      </cve1o:hasPhase>

      <dc:description>
        <xsl:value-of select="cve1:desc/text()" />
      </dc:description>

      <xsl:for-each select="cve1:refs">
        <xsl:for-each select="cve1:ref">
          <cve1o:hasReference>
            <rdf:Description>
              <rdf:type rdf:resource="cve1o:Reference" />
              <dc:title>
                <xsl:value-of select="text()" />
              </dc:title>
              <cve1o:sourceID>
                <xsl:value-of select="@source" />
              </cve1o:sourceID>
              <cve1o:sourceURL>
                <xsl:value-of select="@url" />
              </cve1o:sourceURL>
            </rdf:Description>
          </cve1o:hasReference>
        </xsl:for-each>
      </xsl:for-each>

      <xsl:for-each select="cve1:votes/cve1:accept">
        <cve1o:hasAcceptVotes>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <cve1o:voteCount rdf:datatype="xs:integer" >
              <xsl:value-of select="@count"/>
            </cve1o:voteCount>
          </rdf:Description>
        </cve1o:hasAcceptVotes>
      </xsl:for-each>

      <xsl:for-each select="cve1:votes/cve1:modify">
        <cve1o:hasModifyVotes>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <cve1o:voteCount rdf:datatype="xs:integer">
              <xsl:value-of select="@count"/>
            </cve1o:voteCount>
          </rdf:Description>
        </cve1o:hasModifyVotes>
      </xsl:for-each>

      <xsl:for-each select="cve1:votes/cve1:noop">
        <cve1o:hasNoopVotes>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <cve1o:voteCount rdf:datatype="xs:integer">
              <xsl:value-of select="@count"/>
            </cve1o:voteCount>
          </rdf:Description>
        </cve1o:hasNoopVotes>
      </xsl:for-each>

      <xsl:for-each select="cve1:votes/cve1:recast">
        <cve1o:hasRecastVotes>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <cve1o:voteCount rdf:datatype="xs:integer">
              <xsl:value-of select="@count"/>
            </cve1o:voteCount>
          </rdf:Description>
        </cve1o:hasRecastVotes>
      </xsl:for-each>

      <xsl:for-each select="cve1:votes/cve1:reject">
        <cve1o:hasRejectVotes>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <cve1o:voteCount rdf:datatype="xs:integer">
              <xsl:value-of select="@count"/>
            </cve1o:voteCount>
          </rdf:Description>
        </cve1o:hasRejectVotes>
      </xsl:for-each>

      <xsl:for-each select="cve1:votes/cve1:reviewing">
        <cve1o:hasReviewingVotes>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <cve1o:voteCount rdf:datatype="xs:integer">
              <xsl:value-of select="@count"/>
            </cve1o:voteCount>
          </rdf:Description>
        </cve1o:hasReviewingVotes>
      </xsl:for-each>

      <xsl:for-each select="cve1:votes/cve1:revote">
        <cve1o:hasReVotes>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <cve1o:voteCount rdf:datatype="xs:integer">
              <xsl:value-of select="@count"/>
            </cve1o:voteCount>
          </rdf:Description>
        </cve1o:hasReVotes>
      </xsl:for-each>

      <xsl:for-each select="cve1:comments/cve1:comment">
        <cve1o:hasComment>
          <rdf:Description>
            <dc:description>
              <xsl:value-of select="text()" />
            </dc:description>
            <dc:author>
              <xsl:value-of select="@voter"/>
            </dc:author>
          </rdf:Description>
        </cve1o:hasComment>
      </xsl:for-each>
      
    </rdf:Description>

    
  </xsl:template>
  
</xsl:stylesheet>
