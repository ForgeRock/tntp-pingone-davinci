/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock. 
 */
package org.forgerock.am.marketplace.pingone.davinci;

/**
 * Enumerates the regions that PingOne runs in.
 */
public enum PingOneRegion {
  NA(".com"),
  CA(".ca"),
  EU(".eu"),
  AP(".ap");

  private final String domainSuffix;

  PingOneRegion(String domainSuffix) {
    this.domainSuffix = domainSuffix;
  }

  public String getDomainSuffix() {
    return domainSuffix;
  }
}
