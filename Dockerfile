# Eng yengil Java 17 image
FROM eclipse-temurin:17-jdk-alpine as builder

WORKDIR /app

# Barcha fayllarni konteynerga nusxalaymiz
COPY . .

# Gradle wrapperni ishga tushirib jar build qilamiz
RUN ./gradlew build --no-daemon

# Endi runtime image tayyorlaymiz
FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# Yuqoridagi stage'dan jar faylni nusxalaymiz
COPY --from=builder /app/build/libs/*.jar app.jar

# Profilni belgilaymiz (agar kerak bo‘lsa)
ENV SPRING_PROFILES_ACTIVE=docker

# application-docker.yml ni nusxalaymiz (ixtiyoriy)
COPY src/main/resources/application-docker.yml /app/application.yml

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]

