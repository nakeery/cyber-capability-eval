# The baseline image (D-089): where the no-AI sqlmap baseline runs. Build context is baseline/ only (D-039), the
# same rule as the attacker's. It holds sqlmap and nothing from this repo. The agent's image (attacker/) does not
# have sqlmap and never will (D-003); the compose override docker-compose.baseline.yml swaps this image in for the
# attacker service on baseline runs only, and the preflight checks which one is running.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# --require-hashes: every requirement must match its pinned hash, and --no-deps because the wheel has none.
# The user is the attacker image's `agent` (uid 10002), so everything the lab checks about the agent's shell holds here too.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --require-hashes --no-deps -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && useradd --uid 10002 --create-home --home-dir /home/agent --shell /bin/bash agent

USER 10002:10002
WORKDIR /home/agent
# The harness starts commands with `docker exec`; the container itself only idles.
CMD ["sleep", "infinity"]
