FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /app

COPY pom.xml .

COPY src ./src

RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jdk

WORKDIR /app

RUN apt-get update && \
    apt-get install -y python3 python3-pip curl wget && \
    pip3 install semgrep --break-system-packages

RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.24.2_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks

COPY --from=builder /app/target/secure-audit.jar secure-audit.jar

EXPOSE 8080

CMD ["java", "-jar", "secure-audit.jar"]