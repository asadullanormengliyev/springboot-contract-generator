# Use the official OpenJDK image as a base
FROM openjdk:17-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the built JAR file to the container
COPY build/libs/project-0.0.1-SNAPSHOT.jar app.jar
COPY src/main/resources/application-docker.yml /app/application.yml

# Set environment variable for Spring profile
ENV SPRING_CONFIG_NAME=application-docker

# Expose the port your Spring Boot app listens on (default is 8080)
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]



