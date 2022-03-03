FROM ubuntu

ENV APP_FOLDER=/usr/src/app \
    RUST_LOG=warn \
    MG_MQ_HOST=mq \
    CAFILE=/run/secrets/millegrille.cert.pem \
    KEYFILE=/run/secrets/key.pem \
    CERTFILE=/run/secrets/cert.pem \
    MG_FICHIERS_URL=https://fichiers:443

WORKDIR $APP_FOLDER

COPY target/release/millegrilles_postmaster .

CMD ./millegrilles_postmaster
