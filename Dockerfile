# Java 17 uchun eng yengil image
FROM eclipse-temurin:17-jdk-alpine

# Ishchi papka
WORKDIR /app

# Barcha fayllarni konteynerga ko‘chiramiz
COPY . .

# Gradle wrapper orqali loyihani build qilamiz
RUN ./gradlew build --no-daemon

# JAR faylni app.jar deb ko‘chiramiz (versiyani moslashtir)
RUN cp build/libs/*.jar app.jar

# Portni ochamiz
EXPOSE 8080

# Ilovani ishga tushiramiz
ENTRYPOINT ["java", "-jar", "app.jar"]


