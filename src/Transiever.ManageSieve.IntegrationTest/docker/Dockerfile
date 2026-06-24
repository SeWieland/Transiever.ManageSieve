FROM dovecot/dovecot:2.3.21.1

RUN openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout /etc/dovecot/private/transiever-test.key \
    -out /etc/dovecot/private/transiever-test.crt \
    && chmod 600 /etc/dovecot/private/transiever-test.key

COPY dovecot.conf /etc/dovecot/dovecot.conf

EXPOSE 4190
