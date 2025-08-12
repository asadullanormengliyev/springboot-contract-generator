FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

COPY . .

RUN ./gradlew build -x test --no-daemon

COPY build/libs/project-0.0.1-SNAPSHOT.jar app.jar

CMD ["java", "-jar", "app.jar"]




