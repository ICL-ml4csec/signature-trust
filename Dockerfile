FROM golang:1.23

WORKDIR /app
COPY . .

RUN go build -v -o /entrypoint

RUN git config --global credential.helper store

ENTRYPOINT ["/entrypoint"]