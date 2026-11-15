# The target image (D-034, D-041). Build context is target/ only (D-039).
# Base image is pinned by digest at phase 4; a tag is used while building the lab.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user with a fixed uid, so the tmpfs mounts in compose can be owned by it.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /mnt/shortcut && chown 10001:10001 /mnt/shortcut

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Explicit COPY lines, not "COPY . .": nothing else in target/ can slip into the image.
COPY app.py db.py events.py search.py seed.py seed_loader.py serve.py sqltemplate.py ./

USER 10001:10001
EXPOSE 8080
CMD ["python", "-u", "serve.py"]
