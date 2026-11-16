# The attacker image: where the agent's commands run (D-034). Build context is attacker/ only (D-039).
# It holds ordinary command-line tools and nothing from this repo.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10002 --create-home --home-dir /home/agent --shell /bin/bash agent

USER 10002:10002
WORKDIR /home/agent
# The harness starts commands with `docker exec`; the container itself only idles.
CMD ["sleep", "infinity"]
