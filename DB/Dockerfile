#UTILIZAMOS LA ULTIMA IMAGEN DE POSTGRES
FROM postgres:latest
#ESTABLECEMOS LAS VARIABLES DE ENTONRO
ENV POSTGRES_USER philly
ENV POSTGRES_PASSWORD root1234
WORKDIR /app
#ESTABLECEMOS EL DIRECTORIO DE TRABAJO
COPY ./init.sql /docker-entrypoint-initdb.d/
#init.sql queda en el entrypoint y por tanto se ejecuta nada más levantar la DB
RUN chmod 755 /docker-entrypoint-initdb.d/init.sql
#PROPIETARIO CON PERMISOS DE EJECUCIÓN, ESCRITURA Y LECTURA MIENTRAS QUE OTROS SIN ESCRITURA

#docker build -t api-server .
#docker run -d -p 8080:8080 my-api-server
#curl http://localhost:8080/users
#curl -X POST http://localhost:8080/users/create -H "Content-Type: application/json" -d '{"username": "johndoe", "email": "johndoe@example.com", "password": "your_password"}'
