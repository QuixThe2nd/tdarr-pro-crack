FROM python:3.13-alpine@sha256:2d9aefe2fef018a7eb2c13064c89c71929800fd2e5dccdbf52ea5da5bb8d929a

COPY --chmod=0555 native_verifier.py /opt/tdarr-addon/native_verifier.py
COPY --chmod=0555 entrypoint.sh /opt/tdarr-addon/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/python3", "-B", "-I", "/opt/tdarr-addon/native_verifier.py"]
CMD ["seed", "--target", "/seed"]
