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