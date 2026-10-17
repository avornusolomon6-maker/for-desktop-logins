# Step 1: build the JAR
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -B package -DskipTests

# Step 2: small image that only runs it
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target/intrasem-login-server.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-Xmx300m", "-jar", "app.jar"]
