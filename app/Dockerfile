# FIXED (PCI DSS 2.2.6 / ISO A.8.9):
#  - pinned base image (pin by digest too in real pipelines: eclipse-temurin:21-jre-alpine@sha256:...)
#  - dedicated non-root user
#  - HEALTHCHECK
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --chown=app:app target/payments-api-1.0.0.jar app.jar
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
