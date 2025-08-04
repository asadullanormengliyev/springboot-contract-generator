FROM eclipse-temurin:17-jdk-alpine

# Muallif
LABEL author="asadulla"

# Ishchi katalog
WORKDIR /app

# Gradle fayllarini nusxalaymiz
COPY . .

# Gradle build jar yasaydi
RUN ./gradlew build --no-daemon

# Jar faylni ishga tushiramiz
ENTRYPOINT ["java", "-jar", "build/libs/project-0.0.1-SNAPSHOT.jar"]



