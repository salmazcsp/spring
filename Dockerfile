# syntax=docker/dockerfile:1
FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
RUN apk update && apk upgrade && \
    apk add --no-cache git && \
    rm -rf /var/cache/apk/*
COPY . /app
RUN sed -i 's/\r$//' mvnw && \
    chmod +x mvnw && \
    ./mvnw package
CMD ["sh", "-c", "echo STARTING_SPRING_ON_PORT=$PORT && java -jar target/spring-0.0.1-SNAPSHOT.jar --server.port=${PORT:-10000} --logging.level.root=INFO"]
EXPOSE 10000