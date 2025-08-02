# Eng yengil va barqaror Java 17 image
FROM eclipse-temurin:17-jdk-alpine

# Muallif
LABEL author="asadulla"

# Konteyner ichida ishchi papka
WORKDIR /app

# JAR faylni konteynerga ko‘chiramiz
COPY build/libs/project-0.0.1-SNAPSHOT.jar app.jar

# (optional) Docker uchun maxsus `application-docker.yml` ni asosiy config qilib olmoqchi bo‘lsang:
COPY src/main/resources/application-docker.yml /app/application.yml

# Profilni belgilaymiz (agar kerak bo‘lsa)
ENV SPRING_PROFILES_ACTIVE=docker

# Portni ochamiz
EXPOSE 8080

# Spring Boot ilovasini ishga tushiramiz
ENTRYPOINT ["java", "-jar", "app.jar"]
