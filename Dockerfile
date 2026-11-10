FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/user

RUN apt-get update \
    && apt-get install -y --no-install-recommends libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --user-group user

WORKDIR /home/user/app
COPY --chown=user:user pyproject.toml README.md ./
COPY --chown=user:user src ./src
RUN pip install .

USER user
EXPOSE 7860
CMD ["sh", "-c", "exec metascrub gui --host 0.0.0.0 --port ${PORT:-7860} --db /tmp/metascrub/metascrub.db --upload-dir /tmp/metascrub/uploads"]
