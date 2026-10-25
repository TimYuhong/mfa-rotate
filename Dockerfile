FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
RUN apt-get update && apt-get install -y --no-install-recommends nodejs ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --no-deps -r requirements.lock && useradd --uid 10001 --no-create-home appuser
COPY app ./app
COPY vendor ./vendor
RUN python -B -c "from app.adapter import ProtocolAdapter, PrivacyFlow; from config import Config; f=PrivacyFlow(Config()); assert not f._trace_dump_enabled; f.session.close()"
COPY frontend/dist ./frontend/dist
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TMPDIR=/tmp MFA_MODE=disabled
EXPOSE 8790
CMD ["python","-B","-m","uvicorn","app.server:app","--host","0.0.0.0","--port","8790","--workers","1","--no-access-log","--log-level","warning"]
