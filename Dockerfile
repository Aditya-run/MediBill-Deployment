FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/billingsoftware-0.0.1-SNAPSHOT.jar medibill-v1.0.jar
EXPOSE 9090
ENTRYPOINT ["java","-jar","medibill-v1.0.jar"]