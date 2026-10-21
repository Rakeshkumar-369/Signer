# Signer Server container image
#   docker build -t signer-server .
#   docker run -p 8080:8080 -v signer-data:/data signer-server
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY signer-core signer-core
COPY signer-agent signer-agent
COPY signer-server signer-server
COPY sdk sdk
RUN mvn -B -q -DskipTests -pl signer-server -am package

FROM eclipse-temurin:21-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data signer && mkdir -p /data && chown signer /data
WORKDIR /app
COPY --from=build /src/signer-server/target/signer-server.jar /app/signer-server.jar
USER signer
ENV SIGNER_DATA_DIR=/data \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -Duser.timezone=UTC"
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD curl -fsS http://127.0.0.1:8080/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "/app/signer-server.jar"]
