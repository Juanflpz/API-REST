FROM golang:latest

WORKDIR /app

COPY . .

RUN go mod download

#DESCARGAMOS DEPENDENCIAS
RUN  go get -u github.com/gorilla/mux
RUN  go get -u gorm.io/driver/postgres
RUN  go get -u gorm.io/gorm

RUN go build -o go-server .

CMD ["./go-server"]
#EJECUTAMOS EL PROYECTO
#CMD ["go", "run", "main.go"]