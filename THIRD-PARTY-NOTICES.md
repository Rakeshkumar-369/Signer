# Third-party components

All bundled libraries use licences that permit commercial, closed-source distribution. Keep this file
(and the licence texts in the distributed JARs / runtime `legal` folder) with every release.

| Component | Used in | Licence |
|---|---|---|
| Apache PDFBox, FontBox, PDFBox-IO | core, agent, server | Apache License 2.0 |
| Bouncy Castle (bcprov, bcpkix, bcutil) | core, agent, server | MIT-style Bouncy Castle Licence |
| Jackson | core, agent, server | Apache License 2.0 |
| SLF4J | core, agent, server | MIT |
| Apache Commons Logging | core, agent, server | Apache License 2.0 |
| Spring Framework, Spring Boot, Spring Security Crypto | server | Apache License 2.0 |
| Apache Tomcat (embedded) | server | Apache License 2.0 |
| Flyway (community) | server | Apache License 2.0 |
| HikariCP | server | Apache License 2.0 |
| H2 Database | server | MPL 2.0 / EPL 1.0 (dual) |
| PostgreSQL JDBC driver | server | BSD 2-Clause |
| MariaDB Connector/J | server | LGPL 2.1 (used unmodified as a separate JAR) |
| OpenJDK runtime (bundled by jpackage) | agent installers | GPL v2 with Classpath Exception |

Notes

* The MySQL Connector/J driver (GPL) is intentionally **not** bundled. MariaDB Connector/J connects to
  MySQL 8 servers as well.
* iText is **not** used (its AGPL licence would require publishing your source code or buying a licence).
