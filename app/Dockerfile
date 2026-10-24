# PLANTED ISSUES (PCI DSS 2.2.6 / ISO A.8.9):
#  - floating "latest" tag (unreproducible, unreviewed base image)
#  - no USER, so the JVM runs as root
#  - no HEALTHCHECK
FROM eclipse-temurin:latest
WORKDIR /app
COPY target/payments-api-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
